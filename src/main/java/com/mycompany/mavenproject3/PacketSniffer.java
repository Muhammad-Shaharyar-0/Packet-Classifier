package com.mycompany.mavenproject3;

import java.io.IOException;

import com.sun.jna.Platform;
import java.io.EOFException;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;
import java.util.concurrent.TimeoutException;

import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PacketListener;
import org.pcap4j.core.PcapDumper;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.PcapStat;
import org.pcap4j.core.BpfProgram.BpfCompileMode;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
import org.pcap4j.core.PcapPacket;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.UdpPacket;
import org.pcap4j.packet.DnsPacket;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.IpV6Packet;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.TcpPacket.TcpOption;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TransportPacket;
import org.pcap4j.util.NifSelector;

class packet {

    int packetnumber;
    PcapPacket packet;
    String Type;
    int SrcPort;
    int DesPort;

    packet(int no, PcapPacket p) {
        packetnumber = no;
        packet = p;
        Type = "UnKnown";
    }
}

public class PacketSniffer {

    List<packet> packets = new ArrayList<packet>();
    List<PcapNetworkInterface> networks;

    PacketSniffer() {
    }

    List<PcapNetworkInterface> getNetworkDevice() throws PcapNativeException {
        networks = Pcaps.findAllDevs();
        return networks;
    }

    boolean isFTP(Packet p, int no, packet pac) {

        if (p.contains(TcpPacket.class)) {
            TcpPacket packet = p.get(TcpPacket.class);
            if (packet.getHeader().getSrcPort().valueAsInt() == 20 || packet.getHeader().getDstPort().valueAsInt() == 20) {
                // if (packet.getPayload() != null) {
                pac.Type = "FTP";
                pac.SrcPort = packet.getHeader().getSrcPort().valueAsInt();
                pac.DesPort = packet.getHeader().getDstPort().valueAsInt();
                return true;

                // }
            }else if (packet.getHeader().getSrcPort().valueAsInt() == 21 || packet.getHeader().getDstPort().valueAsInt() == 21) {
                pac.Type = "FTP";
                pac.SrcPort = packet.getHeader().getSrcPort().valueAsInt();
                pac.DesPort = packet.getHeader().getDstPort().valueAsInt();
                return true;

            }
        } else if (p.contains(UdpPacket.class)) {
            UdpPacket packet = p.get(UdpPacket.class);
            if (packet.getHeader().getSrcPort().valueAsInt() == 20 || packet.getHeader().getDstPort().valueAsInt() == 20) {
                // if (packet.getPayload() != null) {
                pac.Type = "FTP";
                pac.SrcPort = packet.getHeader().getSrcPort().valueAsInt();
                pac.DesPort = packet.getHeader().getDstPort().valueAsInt();
                return true;

                // }
            } else if (packet.getHeader().getSrcPort().valueAsInt() == 21 || packet.getHeader().getDstPort().valueAsInt() == 21) {
                pac.Type = "FTP";
                pac.SrcPort = packet.getHeader().getSrcPort().valueAsInt();
                pac.DesPort = packet.getHeader().getDstPort().valueAsInt();
                return true;

            }
        }
        return false;
    }

    boolean isRTP(Packet p, int no, packet pac) {

        if (p.contains(UdpPacket.class)) {
            UdpPacket packet = p.get(UdpPacket.class);
            if ((packet.getHeader().getSrcPort().valueAsInt() >= 16384 && packet.getHeader().getSrcPort().valueAsInt() <= 32767) || (packet.getHeader().getDstPort().valueAsInt() >= 16384 && packet.getHeader().getDstPort().valueAsInt() <= 32767)) {
                //if (packet.getPayload() != null) {
                if (packet.getHeader().getSrcPort().valueAsInt() % 2 == 0 || packet.getHeader().getSrcPort().valueAsInt() % 2 == 0) {
                    pac.Type = "RTP";
                    pac.SrcPort = packet.getHeader().getSrcPort().valueAsInt();
                    pac.DesPort = packet.getHeader().getDstPort().valueAsInt();
                    return true;
                }
                //}
            }
        }
        return false;
    }

    boolean isRTSP(Packet p, int no, packet pac) {

        if (p.contains(TcpPacket.class)) {
            TcpPacket packet = p.get(TcpPacket.class);
            if (packet.getHeader().getSrcPort().valueAsInt() == 554 || packet.getHeader().getDstPort().valueAsInt() == 554) {
                //if (packet.getPayload() != null) {
                pac.Type = "RTSP";
                pac.SrcPort = packet.getHeader().getSrcPort().valueAsInt();
                pac.DesPort = packet.getHeader().getDstPort().valueAsInt();
                return true;
                //}
            }
        }
        return false;
    }

    boolean isDNS(Packet p, int no, packet pac) {

        if (p.contains(DnsPacket.class)) {
            UdpPacket packet = p.get(UdpPacket.class);
            pac.Type = "DNS";
            pac.SrcPort = packet.getHeader().getSrcPort().valueAsInt();
            pac.DesPort = packet.getHeader().getDstPort().valueAsInt();
            return true;
        }
        return false;
    }

    boolean isHttp(Packet p, int no, packet pac) {

        if (p.contains(TcpPacket.class)) {
            TcpPacket packet = p.get(TcpPacket.class);
            if (packet.getHeader().getSrcPort().valueAsInt() == 80 || packet.getHeader().getDstPort().valueAsInt() == 80) {
                //if (packet.getPayload() != null) {
                pac.Type = "HTTP";
                pac.SrcPort = packet.getHeader().getSrcPort().valueAsInt();
                pac.DesPort = packet.getHeader().getDstPort().valueAsInt();
                return true;
                //}
            }
        }
        return false;

    }

    boolean isHttps(Packet p, int no, packet pac) {

        if (p.contains(TcpPacket.class)) {
            TcpPacket packet = p.get(TcpPacket.class);
            if (packet.getHeader().getSrcPort().valueAsInt() == 443 || packet.getHeader().getDstPort().valueAsInt() == 443) {
                //if (packet.getPayload() != null) {
                pac.Type = "HTTPS";
                pac.SrcPort = packet.getHeader().getSrcPort().valueAsInt();
                pac.DesPort = packet.getHeader().getDstPort().valueAsInt();
                return true;
                // }
            }
        }
        return false;

    }

    void Print() {
        for (packet pac : packets) {
            System.out.println(pac.packetnumber);
            System.out.println(pac.packet);
            System.out.println(pac.Type);
        }
    }

    void OpenFile(String filepath) throws PcapNativeException, NotOpenException, EOFException, TimeoutException {
        packets.clear();
        final PcapHandle handle;
        handle = Pcaps.openOffline(filepath);
        Run(handle);
    }

    void OpenLive(String name, int Time) throws PcapNativeException, NotOpenException, EOFException, TimeoutException {
        packets.clear();
        PcapNetworkInterface device = Pcaps.getDevByName(name);
        // Open the device and get a handle
        int snapshotLength = 65536; // in bytes   
        int readTimeout = 10; // in milliseconds                   
        final PcapHandle handle;
        handle = device.openLive(snapshotLength, PromiscuousMode.PROMISCUOUS, readTimeout);
        int i = 1;
        List<TcpPacket> packets = new ArrayList<TcpPacket>();
        int noofpacket = 0;
        int Intervel = Time * 1000;
        long startTime = System.currentTimeMillis();
        long currentTime = startTime;
        while (currentTime < startTime + Intervel) {
            PcapPacket packet;
            try {
                packet = handle.getNextPacketEx();
            } catch (Exception ex) {
                packet = null;
            }
            if (packet != null) {

                packet pac = new packet(i, packet);
                isRTP(packet, i, pac);
                isHttp(packet, i, pac);
                isHttps(packet, i, pac);
                isDNS(packet, i, pac);
                isRTSP(packet, i, pac);
                isFTP(packet, i, pac);
                if(pac.Type.equals("UnKnown")) {
                    if (pac.packet.contains(TcpPacket.class)) {
                        pac.SrcPort = packet.get(TcpPacket.class).getHeader().getSrcPort().valueAsInt();
                        pac.DesPort = packet.get(TcpPacket.class).getHeader().getDstPort().valueAsInt();
                    } else if (pac.packet.contains(UdpPacket.class)) {
                        pac.SrcPort = packet.get(UdpPacket.class).getHeader().getSrcPort().valueAsInt();
                        pac.DesPort = packet.get(UdpPacket.class).getHeader().getDstPort().valueAsInt();
                    }
                }
                this.packets.add(pac);
                i++;
            }
            currentTime = System.currentTimeMillis();

        }
        handle.close();
    }

    void Run(PcapHandle handle) throws PcapNativeException, NotOpenException, EOFException, TimeoutException {

        int i = 1;
        List<TcpPacket> packets = new ArrayList<TcpPacket>();
        PcapPacket packet = handle.getNextPacketEx();
        while (packet != null) {
            packet pac = new packet(i, packet);
            isRTP(packet, i, pac);
            isHttp(packet, i, pac);
            isHttps(packet, i, pac);
            isDNS(packet, i, pac);
            isRTSP(packet, i, pac);
            isFTP(packet, i, pac);
            if (pac.Type.equals("UnKnown")) {
                if (pac.packet.contains(TcpPacket.class)) {
                    pac.SrcPort = packet.get(TcpPacket.class).getHeader().getSrcPort().valueAsInt();
                    pac.DesPort = packet.get(TcpPacket.class).getHeader().getDstPort().valueAsInt();
                } else if (pac.packet.contains(UdpPacket.class)) {
                    pac.SrcPort = packet.get(UdpPacket.class).getHeader().getSrcPort().valueAsInt();
                    pac.DesPort = packet.get(UdpPacket.class).getHeader().getDstPort().valueAsInt();
                }

            }
            this.packets.add(pac);
            i++;
            try {
                packet = handle.getNextPacketEx();
                // System.out.println(packet.getPacket());
            } catch (Exception ex) {
                packet = null;
            }
        }
        handle.close();
    }
}
