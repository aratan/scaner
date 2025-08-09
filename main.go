// FICHERO: main.go
package main

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

// rootCmd es una variable global para que el ejecutor de IA pueda acceder a ella.
var rootCmd *cobra.Command

func main() {
	rootCmd = &cobra.Command{
		Use:   "scaner-pro",
		Short: "Framework SYNAPSE: Un Agente de Pentesting Aumentado por IA",
		Long: `SYNAPSE es una completa suite de herramientas para pentesting, diseñada para
operaciones de Red Team. Combina escaneo, explotación, pivoting y post-explotación
con un núcleo de IA colaborativa para agilizar y potenciar las misiones de seguridad.

Creado por Aratan y evolucionado por Gemini.`,
	}

	// --- REGISTRO DE TODOS LOS MÓDULOS DEL FRAMEWORK ---

	// Módulos de Reconocimiento y Escaneo
	rootCmd.AddCommand(NewScanCmd())
	rootCmd.AddCommand(NewFuzzerCmd())

	// Módulos de Explotación y Fuerza Bruta
	rootCmd.AddCommand(NewExploitCmd())
	rootCmd.AddCommand(NewBruteforceCmd())

	// Módulos de Movimiento Lateral y Post-Explotación
	rootCmd.AddCommand(NewPivotCmd())
	rootCmd.AddCommand(NewLootCmd())

	// Módulos de Mando y Control (C2) y Persistencia
	rootCmd.AddCommand(NewAgentCmd())
	rootCmd.AddCommand(NewPersistCmd())

	// Módulos de Entornos Específicos
	rootCmd.AddCommand(NewCloudCmd())
	rootCmd.AddCommand(NewK8sCmd())

	// Módulos de Utilidad y Gestión del Framework
	rootCmd.AddCommand(NewUpdateCmd())
	rootCmd.AddCommand(NewMissionCmd())

	// Módulo de Generación de Armas
	rootCmd.AddCommand(NewPayloadCmd()) // <-- ¡AQUÍ ESTÁ LA LÍNEA CRÍTICA!

	rootCmd.AddCommand(NewSpoofCmd())
	rootCmd.AddCommand(NewWebAttackCmd())
	rootCmd.AddCommand(NewPostExCmd())

	rootCmd.AddCommand(NewC2Cmd())
	// Cobra se encarga de ejecutar el comando correcto
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: '%s'\n", err)
		os.Exit(1)
	}
}

// executeAICommand es el motor para que la IA pueda actuar.
func executeAICommand(action ProximaAccion) string {
	// Capturar la salida estándar para que podamos devolverla como un string.
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	// Construir la lista de argumentos para Cobra.
	args := []string{action.Comando}
	if action.Subcomando != "" {
		args = append(args, action.Subcomando)
	}
	args = append(args, action.Args...)

	log.Printf("IA ejecutando: scaner-pro %s", strings.Join(args, " "))

	// Usar la API de Cobra para establecer y ejecutar los argumentos.
	rootCmd.SetArgs(args)
	cmdErr := rootCmd.Execute()

	// Restaurar la salida estándar y leer lo que se ha capturado.
	w.Close()
	os.Stdout = oldStdout

	var buf bytes.Buffer
	io.Copy(&buf, r)

	if cmdErr != nil {
		buf.WriteString(fmt.Sprintf("\nERROR DURANTE LA EJECUCIÓN: %v", cmdErr))
	}

	return buf.String()
}
