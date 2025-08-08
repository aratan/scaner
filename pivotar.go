// FICHERO: pivotar.go
package main

import (
	"io"
	"log"
	"net"

	"github.com/armon/go-socks5"
	"github.com/spf13/cobra"
)

func NewPivotCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "pivot",
		Short: "Gestiona el movimiento lateral con reenvío de puertos y proxies",
		Long:  "Contiene herramientas para pivotar en una red, como el reenvío de puertos simple (portfwd) y un proxy SOCKS5 completo.",
	}
	cmd.AddCommand(newPortFwdCmd())
	cmd.AddCommand(newSocksCmd())
	return cmd
}

func newPortFwdCmd() *cobra.Command {
	var listenPort, remoteAddr string
	cmd := &cobra.Command{
		Use:   "portfwd",
		Short: "Crea un túnel de reenvío de puertos simple",
		Run: func(cmd *cobra.Command, args []string) {
			startForwarder(listenPort, remoteAddr)
		},
	}
	cmd.Flags().StringVarP(&listenPort, "listen", "l", "", "Puerto local en el que escuchar (ej: 8080)")
	cmd.Flags().StringVarP(&remoteAddr, "remote", "r", "", "Dirección y puerto remotos a los que reenviar (ej: 192.168.50.10:80)")
	cmd.MarkFlagRequired("listen"); cmd.MarkFlagRequired("remote")
	return cmd
}

func startForwarder(listenPort, remoteAddr string) {
	listener, err := net.Listen("tcp", ":"+listenPort)
	if err != nil { log.Fatalf("Error al empezar a escuchar en el puerto %s: %v", listenPort, err) }
	defer listener.Close()
	log.Printf("Pivot (portfwd) activado. Escuchando en %s, reenviando a %s", listenPort, remoteAddr)
	for {
		localConn, err := listener.Accept()
		if err != nil { log.Printf("Error al aceptar conexión: %v", err); continue }
		go handleForward(localConn, remoteAddr)
	}
}

func handleForward(localConn net.Conn, remoteAddr string) {
	defer localConn.Close()
	remoteConn, err := net.Dial("tcp", remoteAddr)
	if err != nil { log.Printf("Error al conectar al host remoto %s: %v", remoteAddr, err); return }
	defer remoteConn.Close()
	log.Printf("Conexión establecida: %s <-> %s", localConn.RemoteAddr(), remoteAddr)
	go io.Copy(remoteConn, localConn)
	io.Copy(localConn, remoteConn)
	log.Printf("Conexión cerrada: %s", localConn.RemoteAddr())
}

func newSocksCmd() *cobra.Command {
	var listenPort string
	cmd := &cobra.Command{
		Use:   "socks",
		Short: "Inicia un proxy SOCKS5 para pivotar todo el tráfico de red",
		Run: func(cmd *cobra.Command, args []string) {
			startSocksProxy(listenPort)
		},
	}
	cmd.Flags().StringVarP(&listenPort, "port", "p", "1080", "Puerto local en el que escuchar para el proxy SOCKS")
	return cmd
}

func startSocksProxy(listenPort string) {
	conf := &socks5.Config{}
	server, err := socks5.New(conf)
	if err != nil { log.Fatalf("Error al crear el servidor SOCKS5: %v", err) }
	addr := "0.0.0.0:" + listenPort
	log.Printf("Iniciando proxy SOCKS5 en %s. Configura tus herramientas para usar este proxy.", addr)
	if err := server.ListenAndServe("tcp", addr); err != nil { log.Fatalf("Error al iniciar el servidor SOCKS5: %v", err) }
}