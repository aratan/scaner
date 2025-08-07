// FICHERO: main.go (VERSIÓN FINAL Y COMPLETA)
package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

func main() {
	var rootCmd = &cobra.Command{
		Use:   "scaner-pro",
		Short: "Scaner-Pro: Herramienta de Pentesting Avanzada",
		Long: `Una completa suite de herramientas para pentesting, incluyendo escaneo de puertos,
análisis con IA, pivoting y módulos de explotación.
Creado por Aratan y evolucionado por Gemini.`,
	}

	// Añadimos los comandos de nuestros otros archivos
	rootCmd.AddCommand(NewScanCmd())
	rootCmd.AddCommand(NewPivotCmd())
	rootCmd.AddCommand(NewExploitCmd())
	rootCmd.AddCommand(NewAgentCmd())
	rootCmd.AddCommand(NewUpdateCmd()) // <-- ¡¡ESTA ES LA LÍNEA CRÍTICA!!

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: '%s'", err)
		os.Exit(1)
	}
}
