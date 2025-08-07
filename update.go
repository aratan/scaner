// FICHERO: update.go (VERSIÓN CORREGIDA Y FINAL)
package main

import (
	"log"
	"strings"

	"github.com/blang/semver"
	"github.com/rhysd/go-github-selfupdate/selfupdate"
	"github.com/spf13/cobra"
)

// Esta variable será inyectada en tiempo de compilación.
var currentVersion string

// CAMBIAR ESTO: Debes poner tu nombre de usuario y el nombre de tu repositorio en GitHub.
const githubRepo = "aratan/SYNAPSE" // Formato: "usuario/repositorio"

func NewUpdateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "update",
		Short: "Actualiza la herramienta a la última versión desde GitHub",
		Long: `Comprueba si hay una nueva versión disponible en los "Releases" del repositorio
de GitHub configurado. Si existe, la descarga y reemplaza el ejecutable actual.`,
		Run: func(cmd *cobra.Command, args []string) {
			doSelfUpdate()
		},
	}
	return cmd
}

func doSelfUpdate() {
	// --- Verificaciones de Seguridad ---
	if currentVersion == "" {
		log.Fatal("Error: Versión actual desconocida. La herramienta debe ser compilada con el flag '-ldflags=\"-X main.currentVersion=vX.Y.Z\"' para poder actualizarse.")
	}
	if githubRepo == "aratan/scaner-pro" {
		log.Println("ADVERTENCIA: El repositorio de GitHub no ha sido configurado. Por favor, edita la constante 'githubRepo' en el archivo update.go.")
		return
	}

	log.Printf("Versión actual: %s", currentVersion)
	log.Printf("Buscando actualizaciones en el repositorio de GitHub: %s", githubRepo)

	// --- Lógica de Actualización Corregida ---

	// 1. Quitar la 'v' del principio para que semver.Make() funcione
	version_sin_v := strings.TrimPrefix(currentVersion, "v")

	// 2. Parsear la versión actual a un objeto semver
	parsedVersion, err := semver.Make(version_sin_v)
	if err != nil {
		log.Fatalf("Error: La versión compilada ('%s') no es una versión semántica válida: %v", currentVersion, err)
	}

	// 3. Realizar la actualización usando la versión parseada
	latest, err := selfupdate.UpdateSelf(parsedVersion, githubRepo)
	if err != nil {
		log.Fatalf("Error durante el proceso de actualización: %v", err)
	}

	// 4. Comparar correctamente la versión nueva con la parseada y eliminar duplicados
	if latest.Version.Equals(parsedVersion) {
		log.Printf("¡Estás al día! La versión %s ya es la última disponible.", currentVersion)
	} else {
		log.Printf("¡Actualización completada con éxito a la versión v%s!", latest.Version)
		log.Println("Notas de la versión:", latest.ReleaseNotes)
	}
}
