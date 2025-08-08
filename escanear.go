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

var scanConfig Config
var ollamaModel string
var missionName string

func NewScanCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "scan <objetivo> <puertos>",
		Short: "Realiza un escaneo de puertos fiable (TCP Connect)",
		Long:  `...`,
		Args:  cobra.ExactArgs(2),
		Run: func(cmd *cobra.Command, args []string) {
			scanConfig.Target = args[0]
			scanConfig.Ports = args[1]
			scanner := NewScanner(&scanConfig)
			scanner.Run()

			// --- CAMBIO CLAVE: IMPRIMIR RESULTADOS EN JSON PARA SER CAPTURADOS ---
			// Esta salida será capturada por la función executeAICommand en modo autónomo.
			// La salida visual para el usuario ya se imprimió durante scanner.Run().
			jsonOutput, _ := json.Marshal(scanner.results)
			fmt.Println(string(jsonOutput))
			
			// Guardar en ficheros si se solicita con -o
			scanner.saveResults()

			// Guardar en el estado de la misión si se solicita con -m
			if missionName != "" {
				state, err := loadMissionState(missionName)
				if err != nil {
					log.Printf("ADVERTENCIA: No se pudo cargar la misión '%s': %v", missionName, err)
				} else {
					for _, res := range scanner.results {
						hostInfo, ok := state.Hosts[res.Host]
						if !ok {
							hostInfo = HostInfo{IP: res.Host, OpenPorts: []ScanResult{}}
						}
						hostInfo.OpenPorts = append(hostInfo.OpenPorts, res)
						state.Hosts[res.Host] = hostInfo
					}
					state.Log = append(state.Log, LogEntry{Timestamp: time.Now(), Actor: "Sistema", Entry: fmt.Sprintf("Escaneo completado. %d puertos abiertos encontrados en %s.", len(scanner.results), scanConfig.Target)})
					saveMissionState(missionName, state)
					log.Printf("Resultados del escaneo guardados en la misión '%s'.", missionName)
				}
			}
			
			if scanConfig.GenerateReport {
				generateOllamaReport(scanner.results, ollamaModel)
			}
		},
	}

	cmd.Flags().IntVarP(&scanConfig.Concurrency, "concurrencia", "c", 1000, "Número de hilos concurrentes")
	cmd.Flags().DurationVarP(&scanConfig.Timeout, "timeout", "t", 500*time.Millisecond, "Timeout por puerto")
	cmd.Flags().StringVarP(&scanConfig.Output, "output", "o", "table", "Formato de salida: table, json, csv")
	cmd.Flags().BoolVarP(&scanConfig.GenerateReport, "intel", "i", false, "Generar informe de IA estratégico con Ollama al finalizar")
	cmd.Flags().StringVar(&ollamaModel, "model", ConfigData.DefaultOllamaModel, "Modelo de Ollama a usar para el informe")
	cmd.Flags().StringVarP(&missionName, "mission", "m", "", "Nombre de la misión para guardar los resultados y el contexto")
	
	return cmd
}


func generateOllamaReport(results []ScanResult, model string) {
	if len(results) == 0 { log.Println("No se encontraron puertos abiertos para generar un informe."); return }
	log.Println("Contactando a la IA con el modelo", model, "para análisis estratégico...")
	jsonData, err := json.Marshal(results)
	if err != nil { log.Fatalf("Error al convertir resultados a JSON para Ollama: %v", err) }
	prompt := fmt.Sprintf(`Eres "SYNAPSE"... (prompt completo aquí) ... %s`, string(jsonData))
	ollamaAPI := "http://localhost:11434/api/generate"
	requestBody, err := json.Marshal(map[string]interface{}{"model": model, "prompt": prompt, "stream": false})
	if err != nil { log.Fatalf("Error creando request para Ollama: %v", err) }
	resp, err := http.Post(ollamaAPI, "application/json", bytes.NewBuffer(requestBody))
	if err != nil { log.Fatalf("Error al conectar con la API de Ollama en %s: %v", ollamaAPI, err) }
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		log.Fatalf("Ollama respondió con un error (código %d): %s", resp.StatusCode, string(bodyBytes))
	}
	var ollamaResponse map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&ollamaResponse); err != nil { log.Fatalf("Error al decodificar la respuesta de Ollama: %v", err) }
	report, ok := ollamaResponse["response"].(string)
	if !ok { log.Fatalf("La respuesta de Ollama no contiene un campo 'response' de tipo texto.") }
	filename := "informe_IA_estrategico.md"
	if err := os.WriteFile(filename, []byte(report), 0644); err != nil { log.Fatalf("Error al guardar el informe de la IA: %v", err) }
	log.Printf("¡Informe de IA Estratégico generado y guardado en '%s'!", filename)
}