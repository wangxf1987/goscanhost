package main

import (
	"context"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	manuf "github.com/timest/gomanuf"
	"net"
	"strings"
	"time"
)

func listenARP(ctx context.Context) {
	handle, err := pcap.OpenLive(iface, 1024, false, 10*time.Second)
	if err != nil {
		log.Fatal("Open pcap failtrue: ", err)
	}

	defer handle.Close()
	handle.SetBPFFilter("arp")
	ps := gopacket.NewPacketSource(handle, handle.LinkType())
	for {
		select {
		case <-ctx.Done():
			return
		case p := <-ps.Packets():
			arp := p.Layer(layers.LayerTypeARP).(*layers.ARP)
			if arp.Operation == 2 {
				mac := net.HardwareAddr(arp.SourceHwAddress)
				m := manuf.Search(mac.String())
				pushData(ParseIP(arp.SourceProtAddress).String(), mac, "", m)
				if strings.Contains(m, "Apple") {
					go sendMdns(ParseIP(arp.SourceProtAddress), mac)
				} else {
					go sendNbns(ParseIP(arp.SourceProtAddress), mac)
				}
			}
		}
	}
}

// Send arp packet
// ip dst ipaddress
func sendArpPackage(ip IP) {
	srcIP := net.ParseIP(ipNet.IP.String()).To4()
	dstIP := net.ParseIP(ip.String()).To4()
	if srcIP == nil || dstIP == nil {
		log.Fatal("Cannot resolve the ipaddress.")
	}

	// EthernetType 0x0806 ARP
	ether := &layers.Ethernet{
		SrcMAC:       localHaddr,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeARP,
	}

	a := &layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     uint8(6),
		ProtAddressSize:   uint8(4),
		Operation:         uint16(1),
		SourceHwAddress:   localHaddr,
		SourceProtAddress: srcIP,
		DstHwAddress:      net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		DstProtAddress:    dstIP,
	}

	buffer := gopacket.NewSerializeBuffer()
	var opt gopacket.SerializeOptions
	gopacket.SerializeLayers(buffer, opt, ether, a)
	outgoingPacket := buffer.Bytes()

	handle, err := pcap.OpenLive(iface, 2048, false, 30*time.Second)
	if err != nil {
		log.Fatal("Open pcap failtrue:", err)
	}
	defer handle.Close()

	err = handle.WritePacketData(outgoingPacket)
	if err != nil {
		log.Fatal("Send arp packet failture..")
	}

}
