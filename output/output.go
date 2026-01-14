package output

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"secrethunter/scan"

	"github.com/fatih/color"
)

// OutputFormat définit le format de sortie
type OutputFormat string

const (
	FormatTerminal OutputFormat = "terminal"
	FormatJSON     OutputFormat = "json"
	FormatSARIF    OutputFormat = "sarif"
	FormatPDF      OutputFormat = "pdf"
)

// PrintResults affiche les résultats selon le format demandé
func PrintResults(result *scan.ScanResult, format OutputFormat, verifyLight bool) error {
	switch format {
	case FormatJSON:
		return printJSON(result)
	case FormatSARIF:
		return printSARIF(result)
	case FormatPDF:
		return printPDF(result)
	default:
		return printTerminal(result, verifyLight)
	}
}

// printTerminal affiche les résultats dans le terminal avec couleurs
func printTerminal(result *scan.ScanResult, _ bool) error {
	if len(result.Secrets) == 0 {
		color.Green("✅ Aucun secret détecté !")
		return nil
	}

	// Trier par risque et fichier
	sort.Slice(result.Secrets, func(i, j int) bool {
		if result.Secrets[i].Risk != result.Secrets[j].Risk {
			return result.Secrets[i].Risk == "high"
		}
		return result.Secrets[i].File < result.Secrets[j].File
	})

	// Grouper par fichier
	secretsByFile := make(map[string][]scan.Secret)
	for _, secret := range result.Secrets {
		secretsByFile[secret.File] = append(secretsByFile[secret.File], secret)
	}

	color.Red("\n⚠️  SECRETS DÉTECTÉS ⚠️\n")
	color.Yellow(strings.Repeat("━", 80))

	// Afficher les secrets par fichier
	for file, secrets := range secretsByFile {
		color.Cyan("\n📄 Fichier: %s", file)
		for _, secret := range secrets {
			var riskColor *color.Color
			switch secret.Risk {
			case "high":
				riskColor = color.New(color.FgRed, color.Bold)
			case "medium":
				riskColor = color.New(color.FgYellow)
			default:
				riskColor = color.New(color.FgYellow)
			}

			fmt.Printf("  └─ Ligne %d: ", secret.Line)
			riskColor.Printf("[%s] ", secret.Risk)
			color.White("%s - %s\n", secret.Service, secret.Match)
			if len(secret.Context) > 0 {
				color.HiBlack("     Contexte: %s\n", truncate(secret.Context, 100))
			}
		}
	}

	// Résumé et conseils
	color.Yellow("\n" + strings.Repeat("━", 80))
	color.Red("📊 Résumé: %d secret(s) trouvé(s) dans %d fichier(s)", len(result.Secrets), len(secretsByFile))
	color.Yellow("\n💡 Conseils de remédiation:")
	color.White("   • Rotatez immédiatement toutes les clés actives détectées")
	color.White("   • Utilisez des variables d'environnement ou un gestionnaire de secrets")
	color.White("   • Vérifiez l'historique Git pour les secrets exposés")
	color.White("   • Activez la rotation automatique des clés si disponible")
	color.White("   • Surveillez les logs d'accès pour détecter des utilisations suspectes")

	if len(result.Errors) > 0 {
		color.Yellow("\n⚠️  Erreurs rencontrées:")
		for _, err := range result.Errors {
			color.HiBlack("   • %s\n", err)
		}
	}

	return nil
}

// truncate tronque une chaîne à une longueur maximale
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

// JSONResult structure pour l'export JSON
type JSONResult struct {
	Summary struct {
		TotalSecrets int `json:"total_secrets"`
		TotalFiles   int `json:"total_files"`
		ScannedFiles int `json:"scanned_files"`
	} `json:"summary"`
	Secrets []JSONSecret `json:"secrets"`
	Errors  []string     `json:"errors,omitempty"`
}

// JSONSecret structure pour un secret en JSON
type JSONSecret struct {
	File    string `json:"file"`
	Line    int    `json:"line"`
	Service string `json:"service"`
	Match   string `json:"match"`
	Risk    string `json:"risk"`
	Context string `json:"context"`
}

// printJSON affiche les résultats en format JSON
func printJSON(result *scan.ScanResult) error {
	jsonResult := JSONResult{
		Secrets: make([]JSONSecret, 0, len(result.Secrets)),
		Errors:  result.Errors,
	}

	jsonResult.Summary.TotalSecrets = len(result.Secrets)
	jsonResult.Summary.ScannedFiles = result.Files

	// Compter les fichiers uniques
	filesMap := make(map[string]bool)
	for _, secret := range result.Secrets {
		filesMap[secret.File] = true
		jsonResult.Secrets = append(jsonResult.Secrets, JSONSecret{
			File:    secret.File,
			Line:    secret.Line,
			Service: secret.Service,
			Match:   secret.Match,
			Risk:    secret.Risk,
			Context: secret.Context,
		})
	}
	jsonResult.Summary.TotalFiles = len(filesMap)

	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(jsonResult)
}

// SARIFResult structure pour l'export SARIF (format standard pour CI/CD)
type SARIFResult struct {
	Version string `json:"version"`
	Schema  string `json:"$schema"`
	Runs    []struct {
		Tool struct {
			Driver struct {
				Name    string `json:"name"`
				Version string `json:"version"`
			} `json:"driver"`
		} `json:"tool"`
		Results []SARIFResultItem `json:"results"`
	} `json:"runs"`
}

// SARIFResultItem représente un résultat SARIF
type SARIFResultItem struct {
	RuleID  string `json:"ruleId"`
	Level   string `json:"level"`
	Message struct {
		Text string `json:"text"`
	} `json:"message"`
	Locations []struct {
		PhysicalLocation struct {
			ArtifactLocation struct {
				URI string `json:"uri"`
			} `json:"artifactLocation"`
			Region struct {
				StartLine int `json:"startLine"`
			} `json:"region"`
		} `json:"physicalLocation"`
	} `json:"locations"`
}

// printSARIF affiche les résultats en format SARIF
func printSARIF(result *scan.ScanResult) error {
	sarif := SARIFResult{
		Version: "2.1.0",
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Runs: []struct {
			Tool struct {
				Driver struct {
					Name    string `json:"name"`
					Version string `json:"version"`
				} `json:"driver"`
			} `json:"tool"`
			Results []SARIFResultItem `json:"results"`
		}{
			{
				Tool: struct {
					Driver struct {
						Name    string `json:"name"`
						Version string `json:"version"`
					} `json:"driver"`
				}{
					Driver: struct {
						Name    string `json:"name"`
						Version string `json:"version"`
					}{
						Name:    "SecretHunter",
						Version: "1.0.0",
					},
				},
				Results: make([]SARIFResultItem, 0, len(result.Secrets)),
			},
		},
	}

	for _, secret := range result.Secrets {
		level := "warning"
		if secret.Risk == "high" {
			level = "error"
		}

		item := SARIFResultItem{
			RuleID: fmt.Sprintf("%s-secret", strings.ToLower(secret.Service)),
			Level:  level,
			Locations: []struct {
				PhysicalLocation struct {
					ArtifactLocation struct {
						URI string `json:"uri"`
					} `json:"artifactLocation"`
					Region struct {
						StartLine int `json:"startLine"`
					} `json:"region"`
				} `json:"physicalLocation"`
			}{
				{
					PhysicalLocation: struct {
						ArtifactLocation struct {
							URI string `json:"uri"`
						} `json:"artifactLocation"`
						Region struct {
							StartLine int `json:"startLine"`
						} `json:"region"`
					}{
						ArtifactLocation: struct {
							URI string `json:"uri"`
						}{
							URI: secret.File,
						},
						Region: struct {
							StartLine int `json:"startLine"`
						}{
							StartLine: secret.Line,
						},
					},
				},
			},
		}
		item.Message.Text = fmt.Sprintf("Secret %s détecté: %s", secret.Service, secret.Match)
		sarif.Runs[0].Results = append(sarif.Runs[0].Results, item)
	}

	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(sarif)
}

// printPDF génère un PDF basique (pour l'instant, affiche un message)
func printPDF(result *scan.ScanResult) error {
	// TODO: Implémenter génération PDF avec bibliothèque comme github.com/jung-kurt/gofpdf
	// Pour l'instant, on génère un rapport texte formaté
	color.Yellow("\n📄 Génération du rapport PDF...")
	color.White("(Fonctionnalité PDF en développement - utilisez JSON ou SARIF pour l'instant)\n")

	// Afficher un résumé formaté pour l'audit
	fmt.Println("=" + strings.Repeat("=", 78) + "=")
	fmt.Println(" RAPPORT D'AUDIT SECRETS - SecretHunter")
	fmt.Println("=" + strings.Repeat("=", 78) + "=")
	fmt.Printf("\nDate: %s\n", "2026")
	fmt.Printf("Fichiers scannés: %d\n", result.Files)
	fmt.Printf("Secrets détectés: %d\n\n", len(result.Secrets))

	if len(result.Secrets) > 0 {
		fmt.Println("DÉTAILS DES SECRETS DÉTECTÉS:")
		fmt.Println(strings.Repeat("-", 80))
		for _, secret := range result.Secrets {
			fmt.Printf("\nFichier: %s\n", secret.File)
			fmt.Printf("Ligne: %d\n", secret.Line)
			fmt.Printf("Service: %s\n", secret.Service)
			fmt.Printf("Risque: %s\n", secret.Risk)
			fmt.Printf("Match: %s\n", secret.Match)
			if secret.Context != "" {
				fmt.Printf("Contexte: %s\n", secret.Context)
			}
			fmt.Println(strings.Repeat("-", 80))
		}

		fmt.Println("\nCONSEILS DE REMÉDIATION:")
		fmt.Println("1. Rotatez immédiatement toutes les clés actives détectées")
		fmt.Println("2. Utilisez des variables d'environnement ou un gestionnaire de secrets")
		fmt.Println("3. Vérifiez l'historique Git pour les secrets exposés")
		fmt.Println("4. Activez la rotation automatique des clés si disponible")
		fmt.Println("5. Surveillez les logs d'accès pour détecter des utilisations suspectes")
	}

	return nil
}
