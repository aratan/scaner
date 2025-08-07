// FICHERO: pivotar.go
package main

import (
	"io"
	"log"
	"net"

	"github.com/spf13/cobra"
)

func NewPivotCmd() *cobra.Command {
	var listenPort string
	var remoteAddr string
	cmd := &cobra.Command{
		Use:   "pivot",
		Short: "Crea un túnel de reenvío de puertos (port forwarding)",
		Long: `Actúa como un pivote, escuchando en un puerto local y reenviando
todo el tráfico a una dirección remota. Esencial para el movimiento lateral.`,
		Run: func(cmd *cobra.Command, args []string) {
			if listenPort == "" || remoteAddr == "" {
				log.Fatal("Error: Debes especificar el puerto de escucha (-l) y la dirección remota (-r).")
			}
			startForwarder(listenPort, remoteAddr)
		},
	}
	cmd.Flags().StringVarP(&listenPort, "listen", "l", "", "Puerto local en el que escuchar (ej: 8080)")
	cmd.Flags().StringVarP(&remoteAddr, "remote", "r", "", "Dirección y puerto remotos a los que reenviar (ej: 192.168.50.10:80)")
	return cmd
}

func startForwarder(listenPort, remoteAddr string) {
	listener, err := net.Listen("tcp", ":"+listenPort)
	if err != nil {
		log.Fatalf("Error al empezar a escuchar en el puerto %s: %v", listenPort, err)
	}
	defer listener.Close()
	log.Printf("Pivot activado. Escuchando en el puerto %s, reenviando a %s", listenPort, remoteAddr)
	for {
		localConn, err := listener.Accept()
		if err != nil {
			log.Printf("Error al aceptar conexión: %v", err)
			continue
		}
		go handleForward(localConn, remoteAddr)
	}
}

func handleForward(localConn net.Conn, remoteAddr string) {
	defer localConn.Close()
	remoteConn, err := net.Dial("tcp", remoteAddr)
	if err != nil {
		log.Printf("Error al conectar al host remoto %s: %v", remoteAddr, err)
		return
	}
	defer remoteConn.Close()
	log.Printf("Conexión establecida: %s <-> %s", localConn.RemoteAddr(), remoteAddr)
	go io.Copy(remoteConn, localConn)
	io.Copy(localConn, remoteConn)
	log.Printf("Conexión cerrada: %s", localConn.RemoteAddr())
}