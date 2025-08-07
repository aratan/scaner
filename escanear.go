// FICHERO: escanear.go
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/spf13/cobra"
)

// Estas variables son para los flags de este comando específico
var scanConfig Config
var ollamaModel string

func NewScanCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "scan <objetivo> <puertos>",
		Short: "Realiza un escaneo de puertos fiable (TCP Connect)",
		Long: `Escanea un objetivo o rango de red para encontrar puertos abiertos.
Este método no es sigiloso, pero es muy fiable y no requiere privilegios de administrador.`,
		Args: cobra.ExactArgs(2),
		Run: func(cmd *cobra.Command, args []string) {
			scanConfig.Target = args[0]
			scanConfig.Ports = args[1]
			scanner := NewScanner(&scanConfig) // Llama a la función de nucleo.go
			scanner.Run()                      // Llama a la función de nucleo.go
			scanner.saveResults()              // Llama a la función de nucleo.go
			if scanConfig.GenerateReport {
				generateOllamaReport(scanner.results, ollamaModel)
			}
		},
	}
	cmd.Flags().IntVarP(&scanConfig.Concurrency, "concurrencia", "c", 300, "Número de hilos concurrentes")
	cmd.Flags().DurationVarP(&scanConfig.Timeout, "timeout", "t", 1000*time.Millisecond, "Timeout por puerto")
	cmd.Flags().StringVarP(&scanConfig.Output, "output", "o", "table", "Formato de salida: table, json, csv")
	cmd.Flags().BoolVarP(&scanConfig.GenerateReport, "intel", "i", false, "Generar informe de IA estratégico con Ollama al finalizar")
	cmd.Flags().StringVar(&ollamaModel, "model", "gemma3:4b", "Modelo de Ollama a usar para el informe")
	return cmd
}

func generateOllamaReport(results []ScanResult, model string) {
	if len(results) == 0 {
		log.Println("No se encontraron puertos abiertos para generar un informe.")
		return
	}
	log.Println("Contactando a la IA con el modelo", model, "para análisis estratégico...")
	jsonData, err := json.Marshal(results)
	if err != nil {
		log.Fatalf("Error al convertir resultados a JSON para Ollama: %v", err)
	}
	prompt := fmt.Sprintf(`Eres "SYNAPSE", una IA analista de inteligencia de amenazas y experta en ciberseguridad ofensiva. Tu misión es analizar los siguientes datos de un escaneo de red (JSON) y generar un informe de pentesting de nivel profesional.

El informe debe ser visual, táctico y accionable. Sigue esta estructura rigurosamente:

**1. MAPA DE RED TÁCTICO (ASCII ART):**
Dibuja un diagrama de texto visual que represente la topología de la red descubierta. Utiliza cajas "[ ]" para los hosts, flechas "-->" o líneas "---" para las conexiones, e identifica los servicios clave. Muestra al atacante en relación con la red.
Ejemplo:
  [Atacante]
      |
      |---[ FIREWALL ??? ]---
                |
     +----------+----------+
     |                     |
[ Host: 192.168.1.10 ]   [ Host: 192.168.1.50 ]
| Servicios:           |   | Servicios:           |
|  - 22: SSH           |   |  - 80: HTTP (Apache) |
|  - 445: SMB          |   |  - 443: HTTPS        |
+----------------------+   +----------------------+

**2. ANÁLISIS ESTRATÉGICO Y SUPERFICIE DE ATAQUE:**
   - **Resumen Ejecutivo:** Una descripción de alto nivel de la postura de seguridad de la red, identificando los hallazgos más críticos.
   - **Superficie de Ataque Principal:** Identifica los 2-3 hosts/servicios que representan el mayor riesgo y son los vectores de entrada más probables para un atacante.

**3. ANÁLISIS DE VULNERABILIDADES DETALLADO (HOST POR HOST):**
Para **CADA HOST** con puertos abiertos, crea una sección detallada:

   **=========================================================**
   **Host: [IP del Host]**
   **=========================================================**
   - **Puerto [Número]: ([Servicio])**
     - **Análisis de Vulnerabilidades:** Identifica vulnerabilidades *comunes* o *probables* asociadas a este servicio. Si es posible, menciona **CVEs de ejemplo** que históricamente han afectado a este tipo de tecnología (ej. "Servidores SMBv1 son vulnerables a EternalBlue, **CVE-2017-0144**", "Servidores Apache antiguos podrían ser vulnerables a Path Traversal, **CVE-2021-41773**").
     - **Tácticas de Explotación Recomendadas (TTPs):** Describe cómo un atacante podría explotar estas debilidades.
       - **Herramientas:** Nombra herramientas específicas ("nmap -sV --script vuln", "metasploit", "hydra", "feroxbuster").
       - **Técnica:** Detalla el procedimiento (ej. "Realizar un ataque de fuerza bruta contra SSH con una lista de contraseñas comunes", "Utilizar 'searchsploit' para encontrar exploits públicos para la versión del software").
     - **Recomendaciones de Mitigación (Defensa):** Aconseja al equipo de defensa (Blue Team) cómo solucionar el problema.
       - **Acción Inmediata:** (ej. "Aplicar el parche de seguridad MS17-010", "Deshabilitar el servicio si no es esencial").
       - **Mejora a Largo Plazo:** (ej. "Implementar una política de contraseñas robusta y fail2ban", "Colocar el servidor web detrás de un Web Application Firewall (WAF)").
     - **Nivel de Riesgo:** CRÍTICO, ALTO, MEDIO, BAJO.

**4. CONCLUSIÓN Y SIGUIENTES PASOS TÁCTICOS:**
Resume el estado general de la red y proporciona una recomendación estratégica final para el pentester. ¿Cuál debería ser el próximo objetivo para maximizar las posibilidades de éxito?

**Datos del escaneo a analizar:**
%s`, string(jsonData))
	ollamaAPI := "http://localhost:11434/api/generate"
	requestBody, err := json.Marshal(map[string]interface{}{"model": model, "prompt": prompt, "stream": false})
	if err != nil {
		log.Fatalf("Error creando request para Ollama: %v", err)
	}
	resp, err := http.Post(ollamaAPI, "application/json", bytes.NewBuffer(requestBody))
	if err != nil {
		log.Fatalf("Error al conectar con la API de Ollama en %s: %v", ollamaAPI, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		log.Fatalf("Ollama respondió con un error (código %d): %s", resp.StatusCode, string(bodyBytes))
	}
	var ollamaResponse map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&ollamaResponse); err != nil {
		log.Fatalf("Error al decodificar la respuesta de Ollama: %v", err)
	}
	report, ok := ollamaResponse["response"].(string)
	if !ok {
		log.Fatalf("La respuesta de Ollama no contiene un campo 'response' de tipo texto.")
	}
	filename := "informe_IA_estrategico.md"
	if err := os.WriteFile(filename, []byte(report), 0644); err != nil {
		log.Fatalf("Error al guardar el informe de la IA: %v", err)
	}
	log.Printf("¡Informe de IA Estratégico generado y guardado en '%s'!", filename)
}
