package main

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"text/tabwriter"
	"time"
)

// ScanResult almacena la información de un puerto abierto.
type ScanResult struct {
	Host    string `json:"host"`
	Port    int    `json:"port"`
	Status  string `json:"status"`
	Service string `json:"service"`
	Banner  string `json:"banner"`
}

// Scanner contiene la configuración y los resultados del escaneo.
type Scanner struct {
	config  *Config
	results []ScanResult
	mutex   sync.Mutex
}

// Config almacena los parámetros definidos por el usuario.
type Config struct {
	Target         string
	Ports          string
	Timeout        time.Duration
	Concurrency    int
	Output         string
	GenerateReport bool
	OllamaAPI      string
	OllamaModel    string
}

// Mapeo de puertos a servicios conocidos.
var wellKnownPorts = map[int]string{
	21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP",
	110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB", 993: "IMAPS",
	995: "POP3S", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 8080: "HTTP-Proxy",
}

// NewScanner crea una nueva instancia del escáner.
func NewScanner(config *Config) *Scanner {
	return &Scanner{config: config}
}

// AddResult añade un resultado de escaneo de forma segura.
func (s *Scanner) AddResult(result ScanResult) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.results = append(s.results, result)
	if s.config.Output == "table" {
		fmt.Printf("[+] Puerto Abierto: %s:%d (%s)\n", result.Host, result.Port, result.Service)
	}
}

// Run inicia el proceso de escaneo.
func (s *Scanner) Run() {
	ips, err := parseTarget(s.config.Target)
	if err != nil {
		log.Fatalf("Error al procesar el objetivo: %v", err)
	}
	ports, err := parsePorts(s.config.Ports)
	if err != nil {
		log.Fatalf("Error al procesar los puertos: %v", err)
	}
	log.Printf("Iniciando escaneo (TCP Connect) en %d hosts y %d puertos...", len(ips), len(ports))
	var wg sync.WaitGroup
	sem := make(chan struct{}, s.config.Concurrency)
	for _, ip := range ips {
		for _, port := range ports {
			wg.Add(1)
			sem <- struct{}{}
			go func(ip string, port int) {
				defer wg.Done()
				defer func() { <-sem }()
				result := s.connectScan(ip, port)
				if result.Status == "abierto" {
					s.AddResult(result)
				}
			}(ip, port)
		}
	}
	wg.Wait()
	log.Printf("Escaneo completado. Se encontraron %d puertos abiertos.", len(s.results))
}

// connectScan realiza un escaneo TCP Connect. Fiable y no requiere admin.
func (s *Scanner) connectScan(ip string, port int) ScanResult {
	result := ScanResult{Host: ip, Port: port, Status: "cerrado"}
	address := fmt.Sprintf("%s:%d", ip, port)
	conn, err := net.DialTimeout("tcp", address, s.config.Timeout)
	if err != nil {
		return result
	}
	defer conn.Close()

	result.Status = "abierto"
	result.Service = getServiceName(port)
	conn.SetReadDeadline(time.Now().Add(s.config.Timeout))
	buffer := make([]byte, 256)
	n, _ := conn.Read(buffer)
	if n > 0 {
		result.Banner = strings.TrimSpace(string(buffer[:n]))
	}
	return result
}

func getServiceName(port int) string {
	if service, ok := wellKnownPorts[port]; ok {
		return service
	}
	return "desconocido"
}

func parseTarget(target string) ([]string, error) {
	if !strings.Contains(target, "/") {
		ip := net.ParseIP(target)
		if ip == nil {
			return nil, fmt.Errorf("formato de IP inválido: %s", target)
		}
		return []string{target}, nil
	}
	ip, ipNet, err := net.ParseCIDR(target)
	if err != nil {
		return nil, err
	}
	var ips []string
	for ip := ip.Mask(ipNet.Mask); ipNet.Contains(ip); inc(ip) {
		ips = append(ips, ip.String())
	}
	if len(ips) > 2 {
		return ips[1 : len(ips)-1], nil
	}
	return ips, nil
}

func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func parsePorts(portRange string) ([]int, error) {
	var ports []int
	if portRange == "todos" {
		for i := 1; i <= 65535; i++ {
			ports = append(ports, i)
		}
		return ports, nil
	}
	if strings.Contains(portRange, ",") {
		parts := strings.Split(portRange, ",")
		for _, pStr := range parts {
			p, err := strconv.Atoi(pStr)
			if err != nil {
				return nil, fmt.Errorf("puerto inválido en la lista: '%s'", pStr)
			}
			ports = append(ports, p)
		}
		return ports, nil
	}
	parts := strings.Split(portRange, "-")
	if len(parts) == 1 {
		p, err := strconv.Atoi(parts[0])
		if err != nil {
			return nil, err
		}
		ports = append(ports, p)
	} else if len(parts) == 2 {
		start, err1 := strconv.Atoi(parts[0])
		end, err2 := strconv.Atoi(parts[1])
		if err1 != nil || err2 != nil || start > end {
			return nil, fmt.Errorf("rango de puertos inválido")
		}
		for i := start; i <= end; i++ {
			ports = append(ports, i)
		}
	} else {
		return nil, fmt.Errorf("formato de puertos inválido")
	}
	return ports, nil
}

func (s *Scanner) saveResults() {
	if len(s.results) == 0 {
		return
	}
	switch s.config.Output {
	case "json":
		s.saveAsJSON()
	case "csv":
		s.saveAsCSV()
	case "table":
		s.printAsTable()
	default:
		s.printAsTable()
	}
}

func (s *Scanner) saveAsJSON() {
	data, err := json.MarshalIndent(s.results, "", "  ")
	if err != nil {
		log.Fatalf("Error al generar JSON: %v", err)
	}
	filename := "scan_results.json"
	if err := os.WriteFile(filename, data, 0644); err != nil {
		log.Fatalf("Error al escribir el archivo JSON: %v", err)
	}
	log.Printf("Resultados guardados en %s", filename)
}

func (s *Scanner) saveAsCSV() {
	filename := "scan_results.csv"
	file, err := os.Create(filename)
	if err != nil {
		log.Fatalf("Error al crear el archivo CSV: %v", err)
	}
	defer file.Close()
	writer := csv.NewWriter(file)
	defer writer.Flush()
	writer.Write([]string{"Host", "Port", "Status", "Service", "Banner"})
	for _, res := range s.results {
		writer.Write([]string{res.Host, strconv.Itoa(res.Port), res.Status, res.Service, res.Banner})
	}
	log.Printf("Resultados guardados en %s", filename)
}

func (s *Scanner) printAsTable() {
	if len(s.results) == 0 {
		return
	}
	fmt.Println("\n--- Resumen de Resultados ---")
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
	fmt.Fprintln(w, "Host\tPuerto\tEstado\tServicio\tBanner")
	fmt.Fprintln(w, "----\t------\t------\t--------\t------")
	for _, res := range s.results {
		fmt.Fprintf(w, "%s\t%d\t%s\t%s\t%s\n", res.Host, res.Port, res.Status, res.Service, res.Banner)
	}
	w.Flush()
}

func (s *Scanner) generateOllamaReport() {
	if len(s.results) == 0 {
		log.Println("No se encontraron puertos abiertos para generar un informe.")
		return
	}
	log.Println("Generando informe con Ollama y el modelo", s.config.OllamaModel)
	jsonData, err := json.Marshal(s.results)
	if err != nil {
		log.Fatalf("Error al convertir resultados a JSON para Ollama: %v", err)
	}
	prompt := fmt.Sprintf(`Eres un analista de pentesting senior. Tu misión es analizar los resultados de un escaneo de puertos (en formato JSON) y crear un informe de ataque. El informe debe enfocarse en cómo un atacante podría explotar estos hallazgos. Para cada puerto/servicio abierto:
1.  **Vector de Ataque Potencial:** Describe las tácticas más comunes para atacar este servicio (ej. 'Fuerza bruta de credenciales SSH', 'Explotación de vulnerabilidades conocidas en Apache', 'Ataques de inyección SQL en la aplicación web').
2.  **Herramientas Sugeridas:** Recomienda herramientas específicas del arsenal de un pentester para cada ataque (ej. 'Hydra', 'Metasploit', 'sqlmap', 'Nikto').
3.  **Pasos Siguientes para el Pentester:** ¿Qué debería hacer el atacante a continuación si el ataque tiene éxito? (ej. 'Escalada de privilegios', 'Movimiento lateral a otros equipos en la red', 'Exfiltración de datos').
4.  **Nivel de Riesgo:** Clasifica el riesgo como CRÍTICO, ALTO, MEDIO o BAJO.
Elabora un informe claro, directo y orientado a la acción ofensiva. Datos del escaneo:
%s`, string(jsonData))
	requestBody, err := json.Marshal(map[string]interface{}{"model": s.config.OllamaModel, "prompt": prompt, "stream": false})
	if err != nil {
		log.Fatalf("Error creando el cuerpo de la solicitud para Ollama: %v", err)
	}
	resp, err := http.Post(s.config.OllamaAPI, "application/json", bytes.NewBuffer(requestBody))
	if err != nil {
		log.Fatalf("Error al conectar con la API de Ollama en %s. ¿Está Ollama en ejecución o bloqueado por un firewall? Error: %v", s.config.OllamaAPI, err)
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
	filename := "informe_pentesting_IA.md"
	if err := os.WriteFile(filename, []byte(report), 0644); err != nil {
		log.Fatalf("Error al guardar el informe de la IA: %v", err)
	}
	log.Printf("¡Informe de pentesting generado por IA y guardado en '%s'!", filename)
}

func printUsage() {
	fmt.Fprintf(os.Stderr, "\nUso: %s <objetivo> <puertos> [opciones...]\n\n", os.Args[0])
	fmt.Fprintf(os.Stderr, "Herramienta de escaneo de red. Creado por Aratan y mejorado por Gemini.\n")
	fmt.Fprintf(os.Stderr, "Este modo no requiere administrador y es 100%% portable.\n\n")
	fmt.Fprintf(os.Stderr, "Argumentos Obligatorios:\n")
	fmt.Fprintf(os.Stderr, "  <objetivo>    IP o rango CIDR (ej. '192.168.1.10' o '192.168.1.0/24').\n")
	fmt.Fprintf(os.Stderr, "  <puertos>     Puertos a escanear (ej. '80', '1-1024', '22,80,443', 'todos').\n\n")
	fmt.Fprintf(os.Stderr, "Opciones Disponibles:\n")
	fmt.Fprintf(os.Stderr, "  json          Guarda la salida en un fichero 'scan_results.json'.\n")
	fmt.Fprintf(os.Stderr, "  csv           Guarda la salida en un fichero 'scan_results.csv'.\n")
	fmt.Fprintf(os.Stderr, "  report        Al finalizar, genera un informe de pentesting con IA usando Ollama.\n")
}

func main() {
	conf := &Config{
		Output: "table", GenerateReport: false, Concurrency: 300, Timeout: 1000 * time.Millisecond,
		OllamaAPI: "http://localhost:11434/api/generate", OllamaModel: "gemma3:4b",
	}
	if len(os.Args) < 3 {
		printUsage()
		os.Exit(1)
	}
	conf.Target = os.Args[1]
	conf.Ports = os.Args[2]
	if len(os.Args) > 3 {
		for _, arg := range os.Args[3:] {
			switch strings.ToLower(arg) {
			case "json":
				conf.Output = "json"
			case "csv":
				conf.Output = "csv"
			case "report":
				conf.GenerateReport = true
			default:
				fmt.Fprintf(os.Stderr, "Advertencia: Argumento desconocido '%s' será ignorado.\n", arg)
			}
		}
	}
	scanner := NewScanner(conf)
	scanner.Run()
	scanner.saveResults()
	if conf.GenerateReport {
		scanner.generateOllamaReport()
	}
}
