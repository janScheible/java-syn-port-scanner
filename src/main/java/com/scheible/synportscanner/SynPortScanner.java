package com.scheible.synportscanner;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.DatagramSocket;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.time.Duration;
import java.util.Arrays;
import java.util.concurrent.atomic.AtomicReference;

import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PacketListener;
import org.pcap4j.core.PcapAddress;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.EthernetPacket.Builder;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.IpV4Rfc791Tos;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.namednumber.EtherType;
import org.pcap4j.packet.namednumber.IpNumber;
import org.pcap4j.packet.namednumber.IpVersion;
import org.pcap4j.packet.namednumber.TcpPort;
import org.pcap4j.util.MacAddress;

/**
 * @author sj
 */
public class SynPortScanner {

	public static void main(String[] args) throws Exception {
		scan((Inet4Address) InetAddress.getByName("scanme.nmap.org"), TcpPort.HTTP);
		System.exit(0);
	}

	public static void scan(Inet4Address dstAddress, TcpPort portToScan) throws Exception {
		PcapNetworkInterface internetIntf = null;
		PcapAddress internetAddress = null;

		for (PcapNetworkInterface intf : Pcaps.findAllDevs()) {
			for (PcapAddress address : intf.getAddresses()) {
				if (address.getAddress() != null && address.getAddress() instanceof Inet4Address
						&& !address.getAddress().isLoopbackAddress()) {
					internetIntf = intf;
					internetAddress = address;
				}
			}
		}

		NetworkInterface javaInternetAddress = NetworkInterface.getByInetAddress(internetAddress.getAddress());

		String dstMacAddress = getGatewayMacAddress(internetIntf.getName(), internetAddress.getAddress());

		long start = System.nanoTime();

		// use a UDP client socket to reserve an
		// https://en.wikipedia.org/wiki/Ephemeral_port
		try (DatagramSocket udpEphemeralPortSocket = new DatagramSocket()) {
			System.out.println(internetAddress.getAddress().getHostAddress() + ":" + udpEphemeralPortSocket.getLocalPort()
					+ " --> " + dstAddress.getHostAddress() + ":" + portToScan.valueAsInt());

			try (PcapHandle pcapListen = internetIntf.openLive(65536, PromiscuousMode.PROMISCUOUS, 10)) {
				AtomicReference<TcpPacket> receivedPacket = new AtomicReference<>(null);
				Thread listenThread = new Thread(() -> {
					try {
						while (true) {
							pcapListen.loop(1, new PacketListener() {
								@Override
								public void gotPacket(Packet packet) {
									if (packet instanceof EthernetPacket ethernetPacket) {
										if (ethernetPacket.getPayload() instanceof IpV4Packet ipv4Packet) {
											if (ipv4Packet.getPayload() instanceof TcpPacket tcpPacket) {
												if (tcpPacket.getHeader().getAck() && tcpPacket.getHeader().getSrcPort().valueAsInt() == portToScan.valueAsInt()
														&& Arrays.equals(ipv4Packet.getHeader().getSrcAddr().getAddress(), dstAddress.getAddress())) {
													if (tcpPacket.getHeader().getSyn() || tcpPacket.getHeader().getRst()) {
														receivedPacket.set(tcpPacket);
													}

												}
											}
										}
									}
								}
							});

							if (receivedPacket.get() != null) {
								break;
							}
						}
					} catch (PcapNativeException | InterruptedException | NotOpenException ex) {
						new IllegalStateException(ex);
					}
				});
				listenThread.setDaemon(true);
				listenThread.start();

				try (PcapHandle pcap = internetIntf.openLive(65536, PromiscuousMode.NONPROMISCUOUS, 10)) {
					Inet4Address srcAddress = (Inet4Address) internetAddress.getAddress();

					Builder etherBuilder = createSynPacket(dstAddress, srcAddress, udpEphemeralPortSocket, portToScan,
							javaInternetAddress, dstMacAddress);
					pcap.sendPacket(etherBuilder.build());

					TcpPacket ackPackage = null;
					for (int i = 0; i < 50; i++) {
						ackPackage = receivedPacket.get();

						if (ackPackage != null) {
							if (ackPackage.getHeader().getSyn()) {
								System.out.println("Port is open!");
							}
							break;
						} else {
							Thread.sleep(100);
						}
					}

					if (ackPackage == null || ackPackage.getHeader().getRst()) {
						System.out.println("Port is either closed or filtered.");
					}

					listenThread.interrupt();
					System.out.println("Took " + Duration.ofNanos(System.nanoTime() - start).toMillis() + " ms.");
				}
			}
		}
	}

	private static String getGatewayMacAddress(String intfName, InetAddress intfAddress) {
		try {
			// first send a ping the Google's DNS server to make sure that we can retrieve
			// the MAC address
			ProcessBuilder processBuilder = new ProcessBuilder("/bin/sh", "-c",
					"ping -I " + intfName + " -c 1 8.8.8.8 > /dev/null && "
					+ "ip neigh | grep $(ip route show | grep 'dev " + intfName
					+ "' | grep 'default via' | grep '" + intfAddress.getHostAddress()
					+ "' | cut -d ' ' -f 3) | cut -d ' ' -f 5");
			Process process = processBuilder.start();

			BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));

			// consume all lines (but should only be a single one anyway)
			String line = null;
			while (true) {
				String currentLine = reader.readLine();
				if (currentLine != null) {
					line = currentLine;
				} else {
					break;
				}
			}

			process.waitFor();

			return line.trim();
		} catch (IOException | InterruptedException ex) {
			throw new IllegalStateException("Can't determine gateway MAC address.", ex);
		}
	}

	private static Builder createSynPacket(Inet4Address dstAddress, Inet4Address srcAddress,
			final DatagramSocket udpEphemeralPortSocket, TcpPort portToScan, NetworkInterface javaInternetAddress,
			String dstMacAddress) throws SocketException {
		TcpPacket.Builder tcpSynBuilder = new TcpPacket.Builder();
		tcpSynBuilder.dstAddr(dstAddress)
				.srcAddr(srcAddress)
				.srcPort(new TcpPort((short) udpEphemeralPortSocket.getLocalPort(), "source"))
				.dstAddr(dstAddress)
				.dstPort(portToScan)
				.syn(true)
				.correctChecksumAtBuild(true)
				.correctLengthAtBuild(true);

		IpV4Packet.Builder ipBuilder = new IpV4Packet.Builder();
		ipBuilder
				.version(IpVersion.IPV4)
				.tos(IpV4Rfc791Tos.newInstance((byte) 0))
				.ttl((byte) 100)
				.protocol(IpNumber.TCP)
				.srcAddr(srcAddress)
				.dstAddr(dstAddress)
				.payloadBuilder(tcpSynBuilder)
				.correctChecksumAtBuild(true)
				.correctLengthAtBuild(true);

		EthernetPacket.Builder etherBuilder = new EthernetPacket.Builder();
		etherBuilder
				.srcAddr(MacAddress.getByAddress(javaInternetAddress.getHardwareAddress()))
				.dstAddr(MacAddress.getByName(dstMacAddress))
				.type(EtherType.IPV4)
				.payloadBuilder(ipBuilder)
				.paddingAtBuild(true);
		return etherBuilder;
	}
}
