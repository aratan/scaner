// FICHERO: mision.go (VERSIÓN FINAL, CORREGIDA Y COMPLETA)
package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"
)

// --- TIPOS DE DATOS PARA LA MISIÓN ---

type Credential struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Username string `json:"username"`
	Password string `json:"password"`
	Source   string `json:"source"`
}
type HostInfo struct {
	IP              string       `json:"ip"`
	OpenPorts       []ScanResult `json:"open_ports"`
	Vulnerabilities []string     `json:"vulnerabilities"`
	Credentials     []Credential `json:"credentials"`
	Loot            []string     `json:"loot"`
}
type LogEntry struct {
	Timestamp time.Time `json:"timestamp"`
	Actor     string    `json:"actor"`
	Entry     string    `json:"entry"`
}
type MissionState struct {
	MissionName string              `json:"mission_name"`
	StartTime   time.Time           `json:"start_time"`
	Hosts       map[string]HostInfo `json:"hosts"`
	Log         []LogEntry          `json:"log"`
}
type AIResponse struct {
	InformeHumano string        `json:"informe_humano"`
	ProximaAccion ProximaAccion `json:"proxima_accion"`
}
type ProximaAccion struct {
	Comando    string   `json:"comando"`
	Subcomando string   `json:"subcomando"`
	Args       []string `json:"args"`
}

// --- LÓGICA DE LOS COMANDOS ---

func NewMissionCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "mission",
		Short: "Gestiona las misiones de pentesting",
		Long:  "Crea, gestiona y entra en el modo de chat interactivo o autónomo para una misión.",
	}
	cmd.AddCommand(newMissionStartCmd())
	cmd.AddCommand(newMissionStatusCmd())
	cmd.AddCommand(newMissionChatCmd())
	cmd.AddCommand(newMissionAutonomousCmd())
	return cmd
}

func newMissionStartCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "start <nombre_mision>",
		Short: "Inicia una nueva misión",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			missionName := args[0]
			if _, err := os.Stat(missionName); !os.IsNotExist(err) {
				log.Fatalf("Error: El directorio de la misión '%s' ya existe.", missionName)
			}
			os.Mkdir(missionName, 0755)
			state := MissionState{
				MissionName: missionName,
				StartTime:   time.Now(),
				Hosts:       make(map[string]HostInfo),
				Log:         []LogEntry{{Timestamp: time.Now(), Actor: "Sistema", Entry: "Misión iniciada."}},
			}
			saveMissionState(missionName, &state)
			log.Printf("Misión '%s' iniciada correctamente.", missionName)
		},
	}
}

func newMissionStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status <nombre_mision>",
		Short: "Muestra un resumen del estado de la misión",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			missionName := args[0]
			state, err := loadMissionState(missionName)
			if err != nil {
				log.Fatal(err)
			}
			fmt.Printf("--- Estado de la Misión: %s ---\n", state.MissionName)
			fmt.Printf("Iniciada el: %s\n", state.StartTime.Format(time.RFC1123))
			fmt.Printf("Hosts descubiertos: %d\n", len(state.Hosts))
			fmt.Println("--- Últimas 5 entradas del log ---")
			start := len(state.Log) - 5
			if start < 0 {
				start = 0
			}
			for _, entry := range state.Log[start:] {
				fmt.Printf("[%s] %s: %s\n", entry.Timestamp.Format("15:04:05"), entry.Actor, entry.Entry)
			}
		},
	}
}

func newMissionChatCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "chat <nombre_mision>",
		Short: "Entra en el modo de chat interactivo con la IA para una misión",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			missionName := args[0]
			log.Println("Entrando en el chat de misión. Escribe 'exit' o 'quit' para salir.")
			reader := bufio.NewReader(os.Stdin)
			for {
				fmt.Printf("(SYNAPSE:%s) > ", missionName)
				input, _ := reader.ReadString('\n')
				input = strings.TrimSpace(input)
				if input == "exit" || input == "quit" {
					break
				}
				if input == "" {
					continue
				}
				state, err := loadMissionState(missionName)
				if err != nil {
					log.Println("Error cargando estado:", err)
					continue
				}
				state.Log = append(state.Log, LogEntry{Timestamp: time.Now(), Actor: "Operador", Entry: input})
				aiResponse, err := queryOllama(state, input)
				if err != nil {
					log.Println("Error al consultar a la IA:", err)
					state.Log = append(state.Log, LogEntry{Timestamp: time.Now(), Actor: "Sistema", Entry: "Fallo al contactar con la IA."})
					saveMissionState(missionName, state)
					continue
				}
				fmt.Printf("\n[SYNAPSE]: %s\n\n", aiResponse.InformeHumano)
				state.Log = append(state.Log, LogEntry{Timestamp: time.Now(), Actor: "SYNAPSE", Entry: aiResponse.InformeHumano})
				if aiResponse.ProximaAccion.Comando != "" {
					cmdStr := fmt.Sprintf("%s %s %s", aiResponse.ProximaAccion.Comando, aiResponse.ProximaAccion.Subcomando, strings.Join(aiResponse.ProximaAccion.Args, " "))
					fmt.Printf("[PRÓXIMA ACCIÓN RECOMENDADA]: %s\n", strings.TrimSpace(cmdStr))
					fmt.Print("¿Proceder? (s/n) > ")
					confirm, _ := reader.ReadString('\n')
					if strings.ToLower(strings.TrimSpace(confirm)) == "s" {
						log.Println("Ejecutando acción recomendada...")
						output := executeAICommand(aiResponse.ProximaAccion)
						fmt.Println("\n--- RESULTADO DE LA ACCIÓN ---")
						fmt.Println(output)
						fmt.Println("------------------------------\n")
						logEntry := LogEntry{Timestamp: time.Now(), Actor: "Sistema", Entry: fmt.Sprintf("Acción ejecutada '%s'. Resultado:\n%s", strings.TrimSpace(cmdStr), output)}
						state.Log = append(state.Log, logEntry)
					} else {
						log.Println("Acción cancelada.")
						state.Log = append(state.Log, LogEntry{Timestamp: time.Now(), Actor: "Operador", Entry: "Acción recomendada cancelada."})
					}
				}
				saveMissionState(missionName, state)
			}
		},
	}
}

func newMissionAutonomousCmd() *cobra.Command {
	var tickRate time.Duration
	cmd := &cobra.Command{
		Use:   "autonomous <nombre_mision>",
		Short: "Inicia el modo autónomo dirigido por IA para una misión",
		Long:  `El agente entrará en un bucle de Observar-Decidir-Actuar...`,
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			missionName := args[0]
			runAutonomousMode(missionName, tickRate)
		},
	}
	cmd.Flags().DurationVarP(&tickRate, "tick-rate", "t", 30*time.Second, "Frecuencia con la que la IA 'piensa'")
	return cmd
}

func runAutonomousMode(missionName string, tickRate time.Duration) {
	log.Printf("Iniciando modo autónomo para la misión '%s'. Frecuencia: %s", missionName, tickRate)
	log.Println("Presiona Ctrl+C para detener.")
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	ticker := time.NewTicker(tickRate)
	defer ticker.Stop()
	for {
		select {
		case <-sigChan:
			log.Println("Señal de interrupción recibida. Deteniendo agente.")
			return
		case <-ticker.C:
			log.Println("-------------------- NUEVO CICLO DE PENSAMIENTO --------------------")
			state, err := loadMissionState(missionName)
			if err != nil {
				log.Printf("Error crítico al cargar estado: %v. Deteniendo.", err)
				return
			}
			aiResponse, err := queryOllama(state, "Analiza el estado actual y determina la siguiente acción autónoma más lógica.")
			if err != nil {
				log.Printf("Error consultando a la IA: %v. Esperando al siguiente ciclo.", err)
				continue
			}
			if aiResponse.ProximaAccion.Comando == "" {
				log.Println("[SYNAPSE]: No hay más acciones lógicas. Misión autónoma concluida.")
				state.Log = append(state.Log, LogEntry{Timestamp: time.Now(), Actor: "SYNAPSE", Entry: "Misión autónoma completada."})
				saveMissionState(missionName, state)
				return
			}
			cmdStr := fmt.Sprintf("%s %s %s", aiResponse.ProximaAccion.Comando, aiResponse.ProximaAccion.Subcomando, strings.Join(aiResponse.ProximaAccion.Args, " "))
			log.Printf("[SYNAPSE]: Decisión tomada. %s", aiResponse.InformeHumano)
			log.Printf("[ACCIÓN AUTOMÁTICA]: %s", strings.TrimSpace(cmdStr))
			output := executeAICommand(aiResponse.ProximaAccion)
			log.Println("[RESULTADO DE LA ACCIÓN]:\n", output)
			logEntry := LogEntry{Timestamp: time.Now(), Actor: "Sistema", Entry: fmt.Sprintf("Acción autónoma ejecutada '%s'. Resultado:\n%s", strings.TrimSpace(cmdStr), output)}
			state.Log = append(state.Log, logEntry)
			saveMissionState(missionName, state)
			log.Println("Estado actualizado. Esperando próximo ciclo.")
		}
	}
}

// --- FUNCIONES DE UTILIDAD PARA LA MISIÓN ---

func loadMissionState(missionName string) (*MissionState, error) {
	path := filepath.Join(missionName, "state.json")
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil, fmt.Errorf("la misión '%s' no existe", missionName)
	}
	file, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("error al leer estado: %w", err)
	}
	var state MissionState
	if err := json.Unmarshal(file, &state); err != nil {
		return nil, fmt.Errorf("error al decodificar estado: %w", err)
	}
	return &state, nil
}

func saveMissionState(missionName string, state *MissionState) {
	path := filepath.Join(missionName, "state.json")
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		log.Printf("Error al codificar estado: %v", err)
		return
	}
	os.WriteFile(path, data, 0644)
}

func queryOllama(state *MissionState, lastOperatorInput string) (*AIResponse, error) {
	log.Println("Enviando contexto de la misión a la IA para análisis táctico...")
	state.Log = append(state.Log, LogEntry{Timestamp: time.Now(), Actor: "Operador", Entry: lastOperatorInput})
	stateJSON, _ := json.MarshalIndent(state, "", "  ")

	prompt := fmt.Sprintf(`Eres "SYNAPSE", una IA co-piloto de un pentester. Tu misión es analizar el estado de la misión y responder a la última orden del "Operador". Debes ser preciso, táctico y seguir las reglas estrictamente.

**REGLA #1: Formato de Salida Obligatorio**
Tu respuesta DEBE ser un único bloque de código JSON válido con la siguiente estructura:
{
  "informe_humano": "Una respuesta conversacional y clara para el operador.",
  "proxima_accion": {
    "comando": "...",
    "subcomando": "...",
    "args": ["..."]
  }
}

**REGLA #2: Manual de Comandos Permitidos**
Solo puedes proponer acciones usando los siguientes comandos y su sintaxis EXACTA. No inventes comandos ni flags.
*   **Comando 'exploit run-script'**: Para ejecutar scripts externos.
    *   **Uso:** exploit run-script -p <categoria/nombre_script> -t <objetivo>
    *   **Ejemplo:** {"comando": "exploit", "subcomando": "run-script", "args": ["-p", "recon/nmap_vuln", "-t", "192.168.1.100"]}
	
*   **Comando 'scan'**: Para descubrir puertos.
    *   **Uso:** scan <objetivo> <puertos>
    *   **Ejemplo:** {"comando": "scan", "subcomando": "", "args": ["192.168.1.1", "1-1024", "-m", "%[1]s"]}

*   **Comando 'fuzz web-dir'**: Para buscar directorios en un servidor web.
    *   **Uso:** fuzz web-dir -u <url> -w <diccionario>
    *   **Ejemplo:** {"comando": "fuzz", "subcomando": "web-dir", "args": ["-u", "http://192.168.1.1", "-w", "./wordlists/common.txt"]}

*   **Comando 'bruteforce ssh'**: Para ataques de fuerza bruta contra SSH.
    *   **Uso:** bruteforce ssh -t <objetivo> -U <fichero_usuarios> -P <fichero_contraseñas>
    *   **Ejemplo:** {"comando": "bruteforce", "subcomando": "ssh", "args": ["-t", "192.168.1.1", "-U", "./wordlists/users.txt", "-P", "./wordlists/passwords.txt"]}

*   **Comando 'loot hunt'**: Para buscar archivos interesantes.
    *   **Uso:** loot hunt -p <ruta>
    *   **Ejemplo:** {"comando": "loot", "subcomando": "hunt", "args": ["-p", "/home/user", "-m", "%[1]s"]}

**REGLA #3: Argumentos de Misión**
Cuando un comando de ejemplo incluya "-m", "%[1]s", DEBES incluir esos dos elementos en tus 'args' para mantener el contexto de la misión.

**REGLA #4: Sé Proactivo**
Analiza el historial en el 'state.json'. Si un comando ha fallado, no lo repitas. Si un escaneo revela un puerto SSH, tu siguiente acción lógica debería ser proponer un 'bruteforce ssh'.

---
**ESTADO ACTUAL DE LA MISIÓN (JSON):**
%[2]s

**TAREA:** Responde a la última entrada del log del "Operador" y genera tu respuesta JSON siguiendo todas las reglas.
`, state.MissionName, string(stateJSON))

	ollamaAPI := "http://localhost:11434/api/generate"
	ollamaModel := ConfigData.DefaultOllamaModel
	requestBody, _ := json.Marshal(map[string]interface{}{"model": ollamaModel, "prompt": prompt, "stream": false, "format": "json"})

	resp, err := http.Post(ollamaAPI, "application/json", bytes.NewBuffer(requestBody))
	if err != nil {
		return &AIResponse{InformeHumano: fmt.Sprintf("Error crítico de conexión con Ollama: %v", err)}, nil
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Ollama respondió con error %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var ollamaResponse map[string]interface{}
	json.Unmarshal(bodyBytes, &ollamaResponse)
	responseContent, ok := ollamaResponse["response"].(string)
	if !ok || responseContent == "" {
		return nil, fmt.Errorf("la respuesta de Ollama estaba vacía o mal formada")
	}

	var aiResponse AIResponse
	if err := json.Unmarshal([]byte(responseContent), &aiResponse); err != nil {
		aiResponse.InformeHumano = "La IA devolvió una respuesta no válida (no es JSON): " + responseContent
	}
	return &aiResponse, nil
}
