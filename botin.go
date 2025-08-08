// FICHERO: botin.go
package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"time"
	"strings"

	"github.com/spf13/cobra"
)

// LootRule define una regla para encontrar un tipo de archivo valioso.
type LootRule struct {
	Description string
	Pattern     *regexp.Regexp
}

// lootRules es nuestra base de datos de patrones de archivos de alto valor.
// Es fácil añadir más reglas aquí.
var lootRules = []LootRule{
	{
		Description: "Clave privada SSH",
		Pattern:     regexp.MustCompile(`(?i)id_rsa$|id_dsa$|id_ed25519$`),
	},
	{
		Description: "Certificado o clave PEM",
		Pattern:     regexp.MustCompile(`(?i)\.pem$|\.key$`),
	},
	{
		Description: "Fichero de configuración de entorno (.env)",
		Pattern:     regexp.MustCompile(`(?i)^\.env$`),
	},
	{
		Description: "Historial de comandos de Shell",
		Pattern:     regexp.MustCompile(`(?i)\.(bash_history|zsh_history|history)$`),
	},
	{
		Description: "Base de datos de contraseñas de KeePass",
		Pattern:     regexp.MustCompile(`(?i)\.kdbx$`),
	},
	{
		Description: "Fichero con 'password' o 'secret' en el nombre",
		Pattern:     regexp.MustCompile(`(?i)password|secret|contraseña`),
	},
	{
		Description: "Configuración de cliente de AWS/GCP",
		Pattern:     regexp.MustCompile(`(?i)^\.aws/credentials$|^\.config/gcloud/credentials\.db$`),
	},
}

// NewLootCmd crea el comando padre 'loot'.
func NewLootCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "loot",
		Short: "Gestiona módulos de post-explotación y caza de botín",
		Long:  "Contiene herramientas para buscar y exfiltrar información valiosa de un sistema comprometido.",
	}
	cmd.AddCommand(newHuntCmd())
	return cmd
}

// newHuntCmd crea el subcomando 'loot hunt'.
func newHuntCmd() *cobra.Command {
	var searchPath string
	var missionName string

	cmd := &cobra.Command{
		Use:   "hunt",
		Short: "Busca archivos valiosos (botín) en el sistema de ficheros",
		Long: `Escanea recursivamente un directorio en busca de archivos que coincidan
con un conjunto de reglas predefinidas (claves SSH, ficheros .env, historiales, etc.).`,
		Run: func(cmd *cobra.Command, args []string) {
			// Si no se especifica una ruta, se usa el directorio home del usuario actual.
			if searchPath == "" {
				homeDir, err := os.UserHomeDir()
				if err != nil {
					log.Fatalf("Error: No se pudo determinar el directorio home. Por favor, especifica una ruta con -p.")
				}
				searchPath = homeDir
			}
			runLootHunt(searchPath, missionName)
		},
	}

	cmd.Flags().StringVarP(&searchPath, "path", "p", "", "Ruta del directorio desde donde empezar la búsqueda (por defecto: home del usuario)")
	cmd.Flags().StringVarP(&missionName, "mission", "m", "", "Nombre de la misión para guardar el botín encontrado en su estado")
	return cmd
}

func runLootHunt(rootPath, missionName string) {
	log.Printf("Iniciando caza de botín en: %s", rootPath)
	var foundLoot []string

	err := filepath.Walk(rootPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			// Ignorar errores de "permiso denegado" y continuar
			if os.IsPermission(err) {
				return nil
			}
			log.Printf("ADVERTENCIA: Error al acceder a '%s': %v", path, err)
			return err
		}

		// Ignorar directorios
		if info.IsDir() {
			return nil
		}

		// Comprobar cada regla contra el nombre del archivo
		for _, rule := range lootRules {
			if rule.Pattern.MatchString(info.Name()) {
				log.Printf("[+] ¡BOTÍN ENCONTRADO! [%s]: %s", rule.Description, path)
				foundLoot = append(foundLoot, path)
				break // Pasar al siguiente archivo una vez que se encuentra una coincidencia
			}
		}
		return nil
	})

	if err != nil {
		log.Fatalf("Error fatal durante la caza de botín: %v", err)
	}

	log.Printf("Caza de botín completada. Se encontraron %d archivos de interés.", len(foundLoot))

	// Integración con el módulo de misión
	if missionName != "" && len(foundLoot) > 0 {
		state, err := loadMissionState(missionName)
		if err != nil {
			log.Printf("ADVERTENCIA: No se pudo cargar la misión '%s' para guardar el botín: %v", missionName, err)
			return
		}

		// Asumimos que el botín pertenece al host local. Una versión más avanzada
		// permitiría especificar la IP del host al que pertenece el botín.
		hostname, _ := os.Hostname()
		lootLogEntry := fmt.Sprintf("Caza de botín en '%s' (%s) encontró %d archivos: %s", rootPath, hostname, len(foundLoot), strings.Join(foundLoot, ", "))
		
		state.Log = append(state.Log, LogEntry{Timestamp: time.Now(), Actor: "Sistema", Entry: lootLogEntry})
		
		// Aquí se podría añadir a una lista de 'Loot' dentro de un HostInfo específico.
		// Por simplicidad, lo dejamos en el log general por ahora.

		saveMissionState(missionName, state)
		log.Printf("El botín encontrado ha sido registrado en el estado de la misión '%s'.", missionName)
	}
}