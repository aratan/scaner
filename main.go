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

// rootCmd es una variable global para que el ejecutor pueda acceder a ella.
var rootCmd *cobra.Command

func main() {
	rootCmd = &cobra.Command{
		Use:   "scaner-pro",
		Short: "Framework SYNAPSE: Un Agente de Pentesting Aumentado por IA",
		Long:  `...`,
	}
	
	// REGISTRO DE TODOS LOS MÓDULOS
	// (Asegúrate de que tienes todas las llamadas a AddCommand aquí)
	rootCmd.AddCommand(NewScanCmd())
	rootCmd.AddCommand(NewPivotCmd())
	rootCmd.AddCommand(NewExploitCmd())
	rootCmd.AddCommand(NewAgentCmd())
	rootCmd.AddCommand(NewUpdateCmd())
	rootCmd.AddCommand(NewMissionCmd())
	rootCmd.AddCommand(NewLootCmd())
	rootCmd.AddCommand(NewPersistCmd())
	rootCmd.AddCommand(NewCloudCmd())
	rootCmd.AddCommand(NewK8sCmd())
	rootCmd.AddCommand(NewFuzzerCmd())
	rootCmd.AddCommand(NewBruteforceCmd())

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: '%s'\n", err)
		os.Exit(1)
	}
}

// executeAICommand es el motor para que la IA pueda actuar.
func executeAICommand(action ProximaAccion) string {
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	args := []string{action.Comando}
	if action.Subcomando != "" {
		args = append(args, action.Subcomando)
	}
	args = append(args, action.Args...)
	
	log.Printf("IA ejecutando: scaner-pro %s", strings.Join(args, " "))
	
	rootCmd.SetArgs(args)
	// Como Execute() puede causar un os.Exit() en caso de error, lo ejecutamos en una goroutine
	// para poder capturar la salida siempre. No es perfecto, pero funciona para esto.
	cmdErr := rootCmd.Execute()
	
	w.Close()
	os.Stdout = oldStdout
	
	var buf bytes.Buffer
	io.Copy(&buf, r)

	if cmdErr != nil {
		buf.WriteString(fmt.Sprintf("\nERROR DURANTE LA EJECUCIÓN: %v", cmdErr))
	}
	
	return buf.String()
}