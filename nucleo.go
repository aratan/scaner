// FICHERO: nucleo.go
package main

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"text/tabwriter"
	"time"
)

// --- TIPOS DE DATOS COMPARTIDOS ---
type ScanResult struct {
	Host    string `json:"host"`
	Port    int    `json:"port"`
	Status  string `json:"status"`
	Service string `json:"service"`
	Banner  string `json:"banner"`
}
type Config struct {
	Target         string
	Ports          string
	Timeout        time.Duration
	Concurrency    int
	Output         string
	GenerateReport bool
}
type Scanner struct {
	config  *Config
	results []ScanResult
	mutex   sync.Mutex
}

// --- VARIABLES GLOBALES COMPARTIDAS ---
var wellKnownPorts = map[int]string{
	21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP",
	110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB", 993: "IMAPS",
	995: "POP3S", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 8080: "HTTP-Proxy",
}

// --- FUNCIONES DEL NÚCLEO DEL ESCÁNER ---
func NewScanner(config *Config) *Scanner { return &Scanner{config: config} }

func (s *Scanner) AddResult(result ScanResult) {
	s.mutex.Lock(); defer s.mutex.Unlock()
	s.results = append(s.results, result)
	if s.config.Output == "table" {
		fmt.Printf("[+] Puerto Abierto: %s:%d (%s)\n", result.Host, result.Port, result.Service)
	}
}

func (s *Scanner) Run() {
	ips, err := parseTarget(s.config.Target); if err != nil { log.Fatalf("Error al procesar el objetivo: %v", err) }
	ports, err := parsePorts(s.config.Ports); if err != nil { log.Fatalf("Error al procesar los puertos: %v", err) }
	log.Printf("Iniciando escaneo (TCP Connect) en %d hosts y %d puertos...", len(ips), len(ports))
	var wg sync.WaitGroup; sem := make(chan struct{}, s.config.Concurrency)
	for _, ip := range ips {
		for _, port := range ports {
			wg.Add(1); sem <- struct{}{}
			go func(ip string, port int) {
				defer wg.Done(); defer func() { <-sem }()
				result := s.connectScan(ip, port)
				if result.Status == "abierto" { s.AddResult(result) }
			}(ip, port)
		}
	}
	wg.Wait(); log.Printf("Escaneo completado. Se encontraron %d puertos abiertos.", len(s.results))
}

func (s *Scanner) connectScan(ip string, port int) ScanResult {
	result := ScanResult{Host: ip, Port: port, Status: "cerrado"}; address := fmt.Sprintf("%s:%d", ip, port)
	conn, err := net.DialTimeout("tcp", address, s.config.Timeout); if err != nil { return result }; defer conn.Close()
	result.Status = "abierto"; result.Service = getServiceName(port)
	conn.SetReadDeadline(time.Now().Add(s.config.Timeout)); buffer := make([]byte, 256)
	if n, _ := conn.Read(buffer); n > 0 { result.Banner = strings.TrimSpace(string(buffer[:n])) }
	return result
}

// --- FUNCIONES DE UTILIDAD COMPARTIDAS ---
func getServiceName(port int) string {
	if service, ok := wellKnownPorts[port]; ok { return service }; return "desconocido"
}
func parseTarget(target string) ([]string, error) {
	if !strings.Contains(target, "/") { ip := net.ParseIP(target); if ip == nil { return nil, fmt.Errorf("formato de IP inválido: %s", target) }; return []string{target}, nil }
	ip, ipNet, err := net.ParseCIDR(target); if err != nil { return nil, err }
	var ips []string
	for ip := ip.Mask(ipNet.Mask); ipNet.Contains(ip); inc(ip) { ips = append(ips, ip.String()) }
	if len(ips) > 2 { return ips[1 : len(ips)-1], nil }
	return ips, nil
}
func inc(ip net.IP) { for j := len(ip) - 1; j >= 0; j-- { ip[j]++; if ip[j] > 0 { break } } }
func parsePorts(portRange string) ([]int, error) {
	var ports []int
	if portRange == "todos" { for i := 1; i <= 65535; i++ { ports = append(ports, i) }; return ports, nil }
	if strings.Contains(portRange, ",") {
		parts := strings.Split(portRange, ","); for _, pStr := range parts { p, err := strconv.Atoi(pStr); if err != nil { return nil, fmt.Errorf("puerto inválido en la lista: '%s'", pStr) }; ports = append(ports, p) }
		return ports, nil
	}
	parts := strings.Split(portRange, "-")
	if len(parts) == 1 { p, err := strconv.Atoi(parts[0]); if err != nil { return nil, err }; ports = append(ports, p)
	} else if len(parts) == 2 {
		start, err1 := strconv.Atoi(parts[0]); end, err2 := strconv.Atoi(parts[1])
		if err1 != nil || err2 != nil || start > end { return nil, fmt.Errorf("rango de puertos inválido") }
		for i := start; i <= end; i++ { ports = append(ports, i) }
	} else { return nil, fmt.Errorf("formato de puertos inválido") }
	return ports, nil
}
func (s *Scanner) saveResults() {
	if len(s.results) == 0 { return }
	switch s.config.Output {
	case "json": s.saveAsJSON()
	case "csv": s.saveAsCSV()
	case "table": s.printAsTable()
	default: s.printAsTable()
	}
}
func (s *Scanner) saveAsJSON() {
	data, err := json.MarshalIndent(s.results, "", "  "); if err != nil { log.Fatalf("Error al generar JSON: %v", err) }
	filename := "scan_results.json"; if err := os.WriteFile(filename, data, 0644); err != nil { log.Fatalf("Error al escribir el archivo JSON: %v", err) }
	log.Printf("Resultados guardados en %s", filename)
}
func (s *Scanner) saveAsCSV() {
	filename := "scan_results.csv"; file, err := os.Create(filename); if err != nil { log.Fatalf("Error al crear el archivo CSV: %v", err) }; defer file.Close()
	writer := csv.NewWriter(file); defer writer.Flush()
	writer.Write([]string{"Host", "Port", "Status", "Service", "Banner"})
	for _, res := range s.results { writer.Write([]string{res.Host, strconv.Itoa(res.Port), res.Status, res.Service, res.Banner}) }
	log.Printf("Resultados guardados en %s", filename)
}
func (s *Scanner) printAsTable() {
	if len(s.results) == 0 { return }; fmt.Println("\n--- Resumen de Resultados ---"); w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
	fmt.Fprintln(w, "Host\tPuerto\tEstado\tServicio\tBanner"); fmt.Fprintln(w, "----\t------\t------\t--------\t------")
	for _, res := range s.results { fmt.Fprintf(w, "%s\t%d\t%s\t%s\t%s\n", res.Host, res.Port, res.Status, res.Service, res.Banner) }
	w.Flush()
}