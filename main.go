package main

import (
	"bytes"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"log"
	"time"
)

func main() {
	port := "6688"
	device := ""

	log.Println("开始监控数据：" + device)

	handle, err := pcap.OpenLive(device, 1024, false, 30*time.Second)
	if err != nil {
		log.Fatal(err)

		return
	}

	defer handle.Close()

	// 过滤规则，指定TCP协议，指定端口
	var filter = fmt.Sprintf("tcp and port %s and len <= 128", port)

	err = handle.SetBPFFilter(filter)
	if err != nil {

		log.Fatal(err)
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		// 过滤需要抓包的数据关键词，ASCII
		byte := []byte{109, 101, 103}
		data := packet.Data()
		if !bytes.Contains(data, byte) {

			continue
		}

		// 解析TCP数据
		ipLayer := packet.Layer(layers.LayerTypeIPv4)
		tcpLayer := packet.Layer(layers.LayerTypeTCP)
		if tcpLayer == nil {

			continue
		}

		// IP层
		ip, _ := ipLayer.(*layers.IPv4)

		// TCP层
		tcp, _ := tcpLayer.(*layers.TCP)

		// TCP负载数据
		tcpData := tcpLayer.LayerPayload()

		// 来源IP
		srcIp := ip.SrcIP.String()

		// 来源端口
		srcPort := tcp.SrcPort.String()

		// 解析来自 SOCKS5 客户端的账号密码数据
		userLen := tcpData[1]
		username := string(tcpData[2 : 2+userLen])
		passLen := userLen + 2 + 1
		password := string(tcpData[passLen:])

		log.Printf("账号：%s(%s) 上线成功，来源地址：%s:%s", username, password, srcIp, srcPort)
	}
}
