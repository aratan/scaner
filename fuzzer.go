// FICHERO: fuzzer.go (VERSIÓN 2.4 - A PRUEBA DE PÁNICO)
package main

import (
	"bufio"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/spf13/cobra"
)

func NewFuzzerCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "fuzz",
		Short: "Realiza ataques de fuzzing contra aplicaciones web",
	}
	cmd.AddCommand(newWebDirFuzzCmd())
	return cmd
}

func newWebDirFuzzCmd() *cobra.Command {
	var targetURL, wordlistPath, hideCodes string
	var concurrency int
	var showProgress bool

	cmd := &cobra.Command{
		Use:   "web-dir",
		Short: "Descubre directorios y ficheros ocultos en un servidor web",
		Run: func(cmd *cobra.Command, args []string) {
			if targetURL == "" || wordlistPath == "" {
				log.Fatal("Error: Se requiere una URL (-u) y un diccionario (-w).")
			}
			runWebDirFuzzer(targetURL, wordlistPath, concurrency, hideCodes, showProgress)
		},
	}
	cmd.Flags().StringVarP(&targetURL, "url", "u", "", "URL base del objetivo (ej: http://example.com)")
	cmd.Flags().StringVarP(&wordlistPath, "wordlist", "w", "", "Ruta al fichero de diccionario")
	cmd.Flags().IntVarP(&concurrency, "concurrency", "c", 50, "Número de hilos concurrentes")
	cmd.Flags().StringVarP(&hideCodes, "hide-codes", "H", "404", "Códigos de estado HTTP a ocultar, separados por coma (ej: 404,302)")
	cmd.Flags().BoolVarP(&showProgress, "progress", "p", true, "Muestra el progreso en tiempo real")
	return cmd
}

func runWebDirFuzzer(baseURL, wordlistPath string, concurrency int, hideCodesStr string, showProgress bool) {
	hideCodesMap := make(map[int]bool)
	for _, codeStr := range strings.Split(hideCodesStr, ",") {
		code, err := strconv.Atoi(strings.TrimSpace(codeStr))
		if err == nil {
			hideCodesMap[code] = true
		}
	}

	file, err := os.Open(wordlistPath)
	if err != nil {
		log.Fatalf("Error al abrir el diccionario: %v", err)
	}
	defer file.Close()
	lines, _ := countLines(wordlistPath)
	if !strings.HasSuffix(baseURL, "/") {
		baseURL += "/"
	}

	log.Printf("Iniciando fuzzing en %s con %d hilos.", baseURL, concurrency)
	log.Printf("Ocultando códigos de estado: %s", hideCodesStr)

	var wg sync.WaitGroup
	tasks := make(chan string)
	var requestsCount int64

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			client := &http.Client{Timeout: 10 * time.Second}
			for path := range tasks {
				atomic.AddInt64(&requestsCount, 1)
				fullURL := baseURL + path

				req, _ := http.NewRequest("GET", fullURL, nil)
				req.Header.Set("User-Agent", "SYNAPSE Fuzzer/1.0")

				// --- INICIO DE LA CORRECCIÓN FINAL Y DEFINITIVA ---
				resp, err := client.Do(req)

				// Paso 1: Comprobar el error de red. Si existe, la respuesta es inútil.
				if err != nil {
					continue
				}

				// Paso 2: Comprobación de seguridad explícita. Si por alguna razón la respuesta
				// es nula (incluso sin error), la ignoramos para evitar el pánico.
				if resp == nil {
					continue
				}

				// Si hemos llegado hasta aquí, 'resp' es un puntero válido.
				// Ahora podemos usarlo y DEBEMOS cerrar su cuerpo.

				if !hideCodesMap[resp.StatusCode] {
					// Guardamos los valores en variables locales antes de cerrar el cuerpo.
					statusCode := resp.StatusCode
					contentLength := resp.ContentLength
					// Limpiamos la línea de progreso antes de imprimir un resultado.
					fmt.Printf("\r%s\r", strings.Repeat(" ", 80))
					fmt.Printf("[+] Encontrado: %-60s (Código: %d, Tamaño: %d)\n", fullURL, statusCode, contentLength)
				}

				// Cerramos el cuerpo de la respuesta inmediatamente para liberar recursos.
				// NO USAR DEFER DENTRO DE UN BUCLE.
				resp.Body.Close()
				// --- FIN DE LA CORRECCIÓN FINAL Y DEFINITIVA ---
			}
		}()
	}

	if showProgress {
		go func() {
			startTime := time.Now()
			for {
				time.Sleep(500 * time.Millisecond) // Actualizar más rápido
				count := atomic.LoadInt64(&requestsCount)

				// Salir del bucle de progreso solo cuando todas las tareas se hayan completado.
				// Comparamos 'count' con 'lines' para saber cuándo hemos terminado.
				if lines > 0 && count >= int64(lines) {
					break
				}

				elapsed := time.Since(startTime).Seconds()
				if elapsed < 1 {
					elapsed = 1
				}
				rps := float64(count) / elapsed
				if lines > 0 {
					fmt.Printf("\rProgreso: %d / %d (%d%%) | %.2f req/s", count, lines, (count*100)/int64(lines), rps)
				} else {
					fmt.Printf("\rProgreso: %d | %.2f req/s", count, rps)
				}
			}
		}()
	}

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		tasks <- scanner.Text()
	}
	close(tasks)

	wg.Wait()
	// Esperar un poco para que la goroutine de progreso termine de imprimir.
	time.Sleep(500 * time.Millisecond)
	fmt.Printf("\r%s\n", strings.Repeat(" ", 80))
	log.Println("Fuzzing completado.")
}

func countLines(path string) (int, error) {
	file, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	count := 0
	for scanner.Scan() {
		count++
	}
	return count, scanner.Err()
}
