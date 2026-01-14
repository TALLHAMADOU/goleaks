package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/TALLHAMADOU/goleaks/output"
	"github.com/TALLHAMADOU/goleaks/scan"

	"github.com/fatih/color"
	"github.com/urfave/cli/v2"
)

const (
	version = "1.0.0"
	name    = "SecretHunter"
)

func main() {
	app := &cli.App{
		Name:    name,
		Usage:   "Détecteur de secrets ultra-rapide et précis pour votre code",
		Version: version,
		Authors: []*cli.Author{
			{
				Name:  "SecretHunter Team",
				Email: "team@secrethunter.dev",
			},
		},
		Commands: []*cli.Command{
			{
				Name:      "scan",
				Aliases:   []string{"s"},
				Usage:     "Scanner un répertoire ou fichier pour détecter les secrets",
				UsageText: "secrethunter scan [chemin] [options]",
				Flags: []cli.Flag{
					&cli.BoolFlag{
						Name:    "smart",
						Aliases: []string{"s"},
						Usage:   "Mode intelligent pour réduire les faux positifs (ignore tests/docs/exemples, vérifie entropie)",
					},
					&cli.BoolFlag{
						Name:    "verify-light",
						Aliases: []string{"v"},
						Usage:   "Vérifie seulement 10-15 secrets dangereux avec requêtes HEAD légères",
					},
					&cli.BoolFlag{
						Name:    "diff-only",
						Aliases: []string{"d"},
						Usage:   "Scanner seulement les changements (pour vitesse x2 sur gros repos)",
					},
					&cli.StringFlag{
						Name:    "output",
						Aliases: []string{"o"},
						Usage:   "Format de sortie: terminal, json, sarif, pdf",
						Value:   "terminal",
					},
					&cli.StringSliceFlag{
						Name:    "ignore-dirs",
						Aliases: []string{"i"},
						Usage:   "Dossiers à ignorer (séparés par des virgules)",
						Value:   cli.NewStringSlice(".git", "node_modules", "vendor", "dist", "build"),
					},
					&cli.BoolFlag{
						Name:  "iac-support",
						Usage: "Support basique pour scan IaC (Terraform, Dockerfiles) - teaser version pro",
					},
				},
				Action: scanAction,
			},
		},
	}

	if err := app.Run(os.Args); err != nil {
		color.Red("❌ Erreur: %v\n", err)
		os.Exit(1)
	}
}

func scanAction(c *cli.Context) error {
	// Récupérer le chemin à scanner
	path := c.Args().First()
	if path == "" {
		path = "."
	}

	// Vérifier que le chemin existe
	absPath, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("erreur lors de la résolution du chemin: %v", err)
	}

	info, err := os.Stat(absPath)
	if err != nil {
		return fmt.Errorf("le chemin n'existe pas: %s", absPath)
	}

	// Configuration des options
	opts := scan.DefaultScanOptions()
	opts.SmartMode = c.Bool("smart")
	opts.VerifyLight = c.Bool("verify-light")
	opts.DiffOnly = c.Bool("diff-only")
	opts.IACSupport = c.Bool("iac-support")

	// Gérer les dossiers à ignorer
	if c.IsSet("ignore-dirs") {
		opts.IgnoreDirs = c.StringSlice("ignore-dirs")
	}

	// Déterminer le format de sortie tôt pour savoir si on affiche le header
	outputFormatStr := strings.ToLower(strings.TrimSpace(c.String("output")))
	var format output.OutputFormat
	switch outputFormatStr {
	case "json":
		format = output.FormatJSON
	case "sarif":
		format = output.FormatSARIF
	case "pdf":
		format = output.FormatPDF
	default:
		format = output.FormatTerminal
	}

	// Afficher le header seulement en mode terminal ou PDF (pas pour JSON/SARIF)
	if format != output.FormatJSON && format != output.FormatSARIF {
		color.Cyan("\n🔍 SecretHunter v%s - Scan de secrets\n", version)
		color.HiBlack("Chemin: %s\n", absPath)

		// Mode diff-only
		if opts.DiffOnly {
			color.Yellow("⚠️  Mode diff-only activé (scanne les changements Git)")
		}

		// Démarrer le scan
		color.HiBlack("Démarrage du scan...\n")
	}

	var result *scan.ScanResult

	if info.IsDir() {
		// Utiliser git diff si --diff-only est activé
		if opts.DiffOnly {
			result, err = scan.ScanGitDiff(absPath, opts)
			if err != nil {
				return fmt.Errorf("erreur lors du scan Git diff: %v", err)
			}
		} else {
			result, err = scan.ScanDirectory(absPath, opts)
		}
	} else {
		// Scanner un seul fichier
		secrets, scanErr := scan.ScanFile(absPath, opts)
		if scanErr != nil {
			return fmt.Errorf("erreur lors du scan: %v", scanErr)
		}
		result = &scan.ScanResult{
			Secrets: secrets,
			Files:   1,
			Errors:  []string{},
		}
	}

	if err != nil {
		return fmt.Errorf("erreur lors du scan: %v", err)
	}

	// Vérification légère si demandée
	if opts.VerifyLight && len(result.Secrets) > 0 {
		if format == output.FormatTerminal {
			color.Yellow("\n🔎 Vérification légère des secrets détectés...")
		}
		// Filtrer les secrets high-risk et limiter à 15
		highRiskSecrets := make([]scan.Secret, 0)
		for _, secret := range result.Secrets {
			if secret.IsHighRisk {
				highRiskSecrets = append(highRiskSecrets, secret)
			}
		}

		maxVerify := 15
		if len(highRiskSecrets) > maxVerify {
			highRiskSecrets = highRiskSecrets[:maxVerify]
			if format == output.FormatTerminal {
				color.HiBlack("(Limité à %d secrets high-risk pour la vérification)\n", maxVerify)
			}
		}

		// Vérifier chaque secret high-risk
		verifiedSecrets := make([]scan.Secret, 0)
		for _, secret := range highRiskSecrets {
			isValid := scan.VerifySecretLight(secret)
			if isValid {
				verifiedSecrets = append(verifiedSecrets, secret)
			}
		}

		// Mettre à jour les résultats avec seulement les secrets vérifiés
		if opts.VerifyLight {
			result.Secrets = verifiedSecrets
		}
	}

	// Afficher les résultats
	if err := output.PrintResults(result, format, opts.VerifyLight); err != nil {
		return fmt.Errorf("erreur lors de l'affichage: %v", err)
	}

	// Code de sortie
	if len(result.Secrets) > 0 {
		os.Exit(1) // Code d'erreur pour CI/CD
	}

	return nil
}
