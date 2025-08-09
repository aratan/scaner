// FICHERO: estrategia.go (VERSIÓN CON ASIGNACIÓN DE ARGS CORREGIDA)
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

// addStrategyCommands registra los subcomandos de estrategia en el comando 'mission'.
func addStrategyCommands(missionCmd *cobra.Command) {
	missionCmd.AddCommand(newThreatModelCmd())
	missionCmd.AddCommand(newGenerateReportCmd())
}

// --- SUBCOMANDO: mission threat-model ---
func newThreatModelCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "threat-model <nombre_mision>",
		Short: "La IA realiza un modelado de amenazas basado en el estado actual",
		Long:  "Analiza todos los hallazgos de la misión y propone un plan de ataque estratégico de alto nivel.",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			// --- CORRECCIÓN APLICADA AQUÍ ---
			missionName := args[0]
			state, err := loadMissionState(missionName)
			if err != nil {
				log.Fatal(err)
			}
			runThreatModel(state)
		},
	}
}

func runThreatModel(state *MissionState) {
	log.Println("Enviando estado de la misión a la IA para modelado de amenazas...")
	stateJSON, _ := json.MarshalIndent(state, "", "  ")

	prompt := fmt.Sprintf(`Eres "SYNAPSE" en modo estratega. Tu misión es realizar un modelado de amenazas (Threat Modeling) basado en el estado actual de una operación de pentesting.

**TAREA:**
Analiza el siguiente 'state.json'. Basado en los hallazgos, genera un informe conciso que incluya:
1.  **Activos Críticos Identificados:** ¿Cuáles parecen ser los objetivos de mayor valor en la red (ej. controladores de dominio, servidores de bases de datos, paneles de administración)?
2.  **Actores de Amenaza Simulados:** ¿Qué tipo de atacante se beneficiaría de explotar estos sistemas (ej. ransomware, APT, insider threat)?
3.  **Vectores de Ataque Priorizados:** Describe los 3 principales caminos de ataque, desde el acceso inicial hasta el objetivo final. Sé específico.

**ESTADO ACTUAL DE LA MISIÓN:**
%s`, string(stateJSON))

	ollamaModel := ConfigData.DefaultOllamaModel
	requestBody, _ := json.Marshal(map[string]interface{}{"model": ollamaModel, "prompt": prompt, "stream": false})
	resp, err := http.Post("http://localhost:11434/api/generate", "application/json", bytes.NewBuffer(requestBody))
	if err != nil {
		log.Fatalf("Error al conectar con Ollama: %v", err)
	}
	defer resp.Body.Close()

	var ollamaResponse map[string]interface{}
	body, _ := io.ReadAll(resp.Body)
	json.Unmarshal(body, &ollamaResponse)
	report, ok := ollamaResponse["response"].(string)
	if !ok {
		log.Println("ADVERTENCIA: La IA no devolvió un informe de modelado de amenazas válido.")
		fmt.Println("Respuesta cruda de Ollama:", string(body))
		return
	}

	fmt.Println("\n--- ANÁLISIS ESTRATÉGICO DE SYNAPSE ---")
	fmt.Println(report)
	fmt.Println("---------------------------------------")
}

// --- SUBCOMANDO: mission generate-report ---
func newGenerateReportCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "generate-report <nombre_mision>",
		Short: "La IA genera un informe de pentesting final completo",
		Long:  "Recopila todos los hallazgos, logs y botín del 'state.json' y genera un informe final en formato Markdown.",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			// --- CORRECCIÓN APLICADA AQUÍ ---
			missionName := args[0]
			state, err := loadMissionState(missionName)
			if err != nil {
				log.Fatal(err)
			}
			runGenerateReport(state)
		},
	}
}

func runGenerateReport(state *MissionState) {
	log.Println("Enviando estado final de la misión a la IA para la generación del informe...")
	stateJSON, _ := json.MarshalIndent(state, "", "  ")

	prompt := fmt.Sprintf(`Eres "SYNAPSE" en modo documentalista. Tu tarea es generar un informe de pentesting final y profesional basado en el 'state.json' completo de la misión.

**TAREA:**
Usa la siguiente plantilla Markdown y rellénala con la información del 'state.json'. Sé detallado, profesional y claro.

# Informe de Pruebas de Penetración: Misión %s

## 1. Resumen Ejecutivo
*   **Periodo de la Prueba:** %s - %s
*   **Resumen de Hallazgos Críticos:** Describe en 2-3 frases los logros más importantes de la misión (ej. "Se obtuvo acceso inicial a través de un servidor web vulnerable, se pivotó a la red interna y se extrajeron credenciales de administrador del dominio.").
*   **Postura de Seguridad General:** Evalúa el nivel de riesgo general de la organización.

## 2. Narrativa del Ataque
Describe el ataque de forma cronológica, usando la sección de "Log" del 'state.json' como guía. Explica cómo cada paso llevó al siguiente.

## 3. Hallazgos Técnicos Detallados
Para cada host en la sección "Hosts" del 'state.json', crea una subsección. Para cada hallazgo (puerto abierto, credencial, botín), crea una tabla.

### Host: [IP del Host]
| Hallazgo | Detalle | Riesgo | Recomendación |
|----------|---------|--------|---------------|
| Puerto Abierto | Puerto 80/TCP (HTTP) - Servidor Apache X.Y.Z | Medio | Actualizar a la última versión y aplicar parches de seguridad. |
| Credencial | Hash NTLMv2 para 'DOMINIO\usuario' | Crítico | Implementar políticas de contraseñas robustas y segmentación de red. |
| Botín | Fichero '/etc/passwd' | Alto | Restringir permisos de lectura en ficheros sensibles. |

## 4. Conclusión y Pasos Siguientes

**ESTADO FINAL DE LA MISIÓN:**
%s`, state.MissionName, state.StartTime.Format("2006-01-02"), time.Now().Format("2006-01-02"), string(stateJSON))

	ollamaModel := ConfigData.DefaultOllamaModel
	requestBody, _ := json.Marshal(map[string]interface{}{"model": ollamaModel, "prompt": prompt, "stream": false})
	resp, err := http.Post("http://localhost:11434/api/generate", "application/json", bytes.NewBuffer(requestBody))
	if err != nil {
		log.Fatalf("Error al conectar con Ollama: %v", err)
	}
	defer resp.Body.Close()

	var ollamaResponse map[string]interface{}
	body, _ := io.ReadAll(resp.Body)
	json.Unmarshal(body, &ollamaResponse)
	report, ok := ollamaResponse["response"].(string)
	if !ok {
		log.Println("ADVERTENCIA: La IA no devolvió un informe final válido.")
		fmt.Println("Respuesta cruda de Ollama:", string(body))
		return
	}

	filename := fmt.Sprintf("INFORME_FINAL_%s.md", state.MissionName)
	err = os.WriteFile(filename, []byte(report), 0644)
	if err != nil {
		log.Fatalf("Error al guardar el informe final: %v", err)
	}

	log.Printf("¡Informe de pentesting final generado con éxito! Guardado en: %s", filename)
}
