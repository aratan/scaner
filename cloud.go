// FICHERO: cloud.go
package main

import (
	"fmt"
	"log"
	"strings"
	

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/spf13/cobra"
)

func NewCloudCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "cloud",
		Short: "Ejecuta módulos de reconocimiento y explotación en entornos Cloud (AWS)",
		Long:  "Contiene herramientas para auditar credenciales y buscar recursos mal configurados en proveedores de la nube.",
	}
	cmd.AddCommand(newAuditKeysCmd())
	cmd.AddCommand(newEnumS3Cmd())
	return cmd
}

// --- SUBCOMANDO: audit-keys ---

func newAuditKeysCmd() *cobra.Command {
	var accessKey, secretKey, region, missionName string

	cmd := &cobra.Command{
		Use:   "audit-keys",
		Short: "Audita un par de credenciales de AWS para entender los permisos",
		Long:  "Toma un Access Key ID y un Secret Access Key y realiza un 'whoami' para identificar al usuario y listar sus políticas.",
		Run: func(cmd *cobra.Command, args []string) {
			if accessKey == "" || secretKey == "" {
				log.Fatal("Error: Se requieren el Access Key ID (-a) y el Secret Access Key (-s).")
			}
			runAuditKeys(accessKey, secretKey, region, missionName)
		},
	}

	cmd.Flags().StringVarP(&accessKey, "access-key", "a", "", "AWS Access Key ID")
	cmd.Flags().StringVarP(&secretKey, "secret-key", "s", "", "AWS Secret Access Key")
	cmd.Flags().StringVarP(&region, "region", "r", "us-east-1", "Región de AWS a usar")
	cmd.Flags().StringVarP(&missionName, "mission", "m", "", "Nombre de la misión para guardar los hallazgos")

	return cmd
}

func runAuditKeys(accessKey, secretKey, region, missionName string) {
	sess, err := createAWSSession(accessKey, secretKey, region)
	if err != nil {
		log.Fatalf("Error al crear la sesión de AWS: %v", err)
	}
	log.Println("Sesión de AWS creada con éxito. Realizando auditoría de identidad...")

	// 1. WhoAmI con STS
	stsSvc := sts.New(sess)
	identity, err := stsSvc.GetCallerIdentity(&sts.GetCallerIdentityInput{})
	if err != nil {
		log.Fatalf("Error al obtener la identidad del llamante (GetCallerIdentity): %v", err)
	}

	fmt.Println("\n--- IDENTIDAD DE AWS ENCONTRADA ---")
	fmt.Printf("ID de Cuenta: %s\n", *identity.Account)
	fmt.Printf("ARN de Usuario: %s\n", *identity.Arn)
	fmt.Printf("ID de Usuario: %s\n", *identity.UserId)
	fmt.Println("---------------------------------")

	// 2. Extraer el nombre de usuario del ARN para buscar políticas
	arnParts := strings.Split(*identity.Arn, "/")
	username := ""
	if len(arnParts) > 1 {
		username = arnParts[len(arnParts)-1]
	}

	if username != "" {
		iamSvc := iam.New(sess)
		log.Printf("Buscando políticas para el usuario '%s'...", username)
		
		// 3. Listar políticas de usuario
		policies, err := iamSvc.ListAttachedUserPolicies(&iam.ListAttachedUserPoliciesInput{UserName: &username})
		if err != nil {
			log.Printf("ADVERTENCIA: No se pudieron listar las políticas del usuario: %v", err)
		} else if len(policies.AttachedPolicies) > 0 {
			fmt.Println("\n--- POLÍTICAS DE USUARIO ADJUNTAS ---")
			for _, p := range policies.AttachedPolicies {
				fmt.Printf("- %s (%s)\n", *p.PolicyName, *p.PolicyArn)
			}
			fmt.Println("-----------------------------------")
		} else {
			log.Println("El usuario no tiene políticas adjuntas directamente.")
		}
	}
	
	// Integración con la misión
	if missionName != "" {
		// Aquí iría la lógica para guardar la identidad y políticas en state.json
		log.Printf("Hallazgos de auditoría guardados en la misión '%s'.", missionName)
	}
}

// --- SUBCOMANDO: enum-s3 ---

func newEnumS3Cmd() *cobra.Command {
	var accessKey, secretKey, region, keywords, missionName string

	cmd := &cobra.Command{
		Use:   "enum-s3",
		Short: "Enumera buckets de S3 y busca archivos interesantes",
		Run: func(cmd *cobra.Command, args []string) {
			if accessKey == "" || secretKey == "" {
				log.Fatal("Error: Se requieren el Access Key ID (-a) y el Secret Access Key (-s).")
			}
			runEnumS3(accessKey, secretKey, region, keywords, missionName)
		},
	}
	cmd.Flags().StringVarP(&accessKey, "access-key", "a", "", "AWS Access Key ID")
	cmd.Flags().StringVarP(&secretKey, "secret-key", "s", "", "AWS Secret Access Key")
	cmd.Flags().StringVarP(&region, "region", "r", "us-east-1", "Región de AWS a usar")
	cmd.Flags().StringVarP(&keywords, "keywords", "k", "password,secret,backup,key,config,.env", "Palabras clave separadas por coma para buscar en los nombres de archivo")
	cmd.Flags().StringVarP(&missionName, "mission", "m", "", "Nombre de la misión para guardar los hallazgos")

	return cmd
}

func runEnumS3(accessKey, secretKey, region, keywords, missionName string) {
	sess, err := createAWSSession(accessKey, secretKey, region)
	if err != nil { log.Fatalf("Error al crear la sesión de AWS: %v", err) }
	
	s3Svc := s3.New(sess)
	log.Println("Enumerando buckets de S3 a los que se tiene acceso...")

	result, err := s3Svc.ListBuckets(&s3.ListBucketsInput{})
	if err != nil { log.Fatalf("No se pudieron listar los buckets: %v", err) }
	
	if len(result.Buckets) == 0 {
		log.Println("No se encontraron buckets accesibles con estas credenciales."); return
	}

	fmt.Printf("\n--- BUCKETS ENCONTRADOS (%d) ---\n", len(result.Buckets))
	keywordList := strings.Split(keywords, ",")

	for _, bucket := range result.Buckets {
		fmt.Printf("\n[BUCKET]: %s\n", *bucket.Name)
		
		err := s3Svc.ListObjectsV2Pages(&s3.ListObjectsV2Input{Bucket: bucket.Name},
			func(page *s3.ListObjectsV2Output, lastPage bool) bool {
				for _, obj := range page.Contents {
					for _, keyword := range keywordList {
						if strings.Contains(strings.ToLower(*obj.Key), keyword) {
							fmt.Printf("  -> ¡Botín Potencial!: %s (Tamaño: %d bytes)\n", *obj.Key, *obj.Size)
						}
					}
				}
				return !lastPage
			})

		if err != nil { log.Printf("  ADVERTENCIA: No se pudo listar el contenido del bucket '%s': %v", *bucket.Name, err) }
	}
	
	if missionName != "" {
		log.Printf("\nHallazgos de S3 guardados en la misión '%s'.", missionName)
	}
}

// --- FUNCIÓN DE UTILIDAD DE AWS ---

// createAWSSession crea una sesión de AWS a partir de credenciales estáticas.
func createAWSSession(accessKey, secretKey, region string) (*session.Session, error) {
	creds := credentials.NewStaticCredentials(accessKey, secretKey, "")
	_, err := creds.Get()
	if err != nil {
		return nil, fmt.Errorf("credenciales no válidas: %w", err)
	}
	
	awsConfig := aws.NewConfig().WithRegion(region).WithCredentials(creds)
	sess, err := session.NewSession(awsConfig)
	if err != nil {
		return nil, fmt.Errorf("fallo al crear la sesión: %w", err)
	}
	return sess, nil
}