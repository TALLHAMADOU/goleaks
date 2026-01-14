# 🔍 Goleaks

![Go Version](https://img.shields.io/badge/go-1.21+-00ADD8?style=flat-square&logo=go)
![License](https://img.shields.io/badge/license-MIT-blue.svg?style=flat-square)
![Version](https://img.shields.io/badge/version-1.0.0-green.svg?style=flat-square)
![CLI](https://img.shields.io/badge/CLI-Go-blue?style=flat-square&logo=go)

> 🚀 **[Goleaks Pro - Coming Soon](https://goleaks.pro)** - Version Pro avec +700 patterns, dashboard SaaS, alertes Slack, et plus encore !

**Goleaks** est un **outil CLI en Go** (Golang) ultra-rapide et précis pour détecter les secrets sensibles (clés API, mots de passe, tokens) dans vos fichiers de code ou répertoires.

**🔑 Mots-clés :** `cli` `go` `golang` `secrets` `security` `api-keys` `trufflehog-alternative` `gitleaks-alternative` `secret-detection` `security-scanning` `devsecops` `git-secrets` `env-files` `ci-cd` `security-tool`

Version: **1.0.0**

## ✨ Fonctionnalités Principales

- ⚡ **Ultra-rapide** : Scan optimisé avec compilation de regex au démarrage, scan récursif efficace avec `filepath.WalkDir`
- 🎯 **Précis** : Réduction des faux positifs grâce au mode intelligent (`--smart`) et vérification d'entropie
- 🔒 **20 Patterns** : Détection des secrets les plus courants en 2026 (OpenAI, AWS, GitHub, Stripe, etc.)
- 🎨 **Affichage coloré** : Terminal avec couleurs, emojis et formatage lisible
- 📊 **Multi-formats** : Export JSON, SARIF (pour CI/CD), et texte formaté (pour audits)
- 🧠 **Mode intelligent** : Ignore automatiquement tests/docs/exemples, vérifie entropie pour filtrer UUID/hashes
- 🚀 **Diff-only** : Scan seulement les changements Git (`--diff-only`) pour vitesse x2 sur gros repos
- 🔍 **Verify-light** : Vérification légère avec requêtes HTTP HEAD pour les secrets high-risk (`--verify-light`)
- 🐳 **Support IaC** : Support basique pour Terraform, Dockerfiles (`--iac-support`)

## 📦 Installation

### Installation

#### Via go install (recommandé)

```bash
# Installer directement depuis GitHub
go install github.com/TALLHAMADOU/goleaks/cmd/goleaks@latest

# Vérifier l'installation
goleaks --version
```

#### Depuis les sources

```bash
# Cloner le repository
git clone https://github.com/TALLHAMADOU/goleaks.git
cd goleaks

# Télécharger les dépendances
go mod download

# Compiler
go build -o goleaks ./cmd/goleaks

# Ou installer directement
go install ./cmd/goleaks
```

### Prérequis

- Go 1.21 ou supérieur
- Git (pour le mode `--diff-only`)

## 🚀 Utilisation

### Commande de base

```bash
# Afficher l'aide
goleaks --help
goleaks scan --help

# Scanner le répertoire courant
goleaks scan

# Scanner un répertoire spécifique
goleaks scan /path/to/project

# Scanner un fichier
goleaks scan config.env
```

### Options disponibles

| Option | Alias | Description |
|--------|-------|-------------|
| `--smart` | `-s` | Mode intelligent pour réduire les faux positifs (ignore tests/docs/exemples, vérifie entropie) |
| `--verify-light` | `-v` | Vérifie seulement 10-15 secrets dangereux avec requêtes HEAD légères (timeout 2s, user-agent Goleaks/1.0) |
| `--diff-only` | `-d` | Scanner seulement les changements Git (unstaged + staged) pour vitesse x2 sur gros repos |
| `--output` | `-o` | Format de sortie : `terminal` (par défaut), `json`, `sarif`, `report-txt` (texte formaté pour audits) |
| `--ignore-dirs` | `-i` | Dossiers à ignorer (séparés par des virgules) |
| `--iac-support` | | Support basique pour scan IaC (Terraform, Dockerfiles) - teaser version pro |

### Exemples d'utilisation

#### Scan standard

```bash
# Scan complet du répertoire courant
goleaks scan

# Résultat :
# 🔍 Goleaks v1.0.0 - Scan de secrets
# Chemin: /path/to/project
# Démarrage du scan...
#
# ⚠️  SECRETS DÉTECTÉS ⚠️
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 
# 📄 Fichier: config.env
#   └─ Ligne 8: [high] AWS Access Key - AKIA...MPLE
#      Contexte: AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
#
# 📊 Résumé: 1 secret(s) trouvé(s) dans 1 fichier(s)
```

#### Mode intelligent (`--smart`)

```bash
# Réduit les faux positifs en ignorant tests/docs/exemples et en vérifiant l'entropie
goleaks scan --smart

# Ignore automatiquement :
# - Dossiers : test/, spec/, example/, sample/, demo/, mock/
# - Fichiers : README, CHANGELOG, LICENSE, CONTRIBUTING
# - Filtre les UUID et hashes hexadécimaux simples (entropie < 4.0)
```

#### Diff-only (`--diff-only`)

```bash
# Scanner seulement les changements Git (unstaged + staged)
goleaks scan --diff-only

# Utile pour :
# - Pré-commit hooks
# - CI/CD sur gros repos
# - Scan rapide des modifications récentes
```

#### Verify-light (`--verify-light`)

```bash
# Vérifie les secrets high-risk avec requêtes HTTP HEAD légères
goleaks scan --verify-light

# Vérifie uniquement les secrets marqués IsHighRisk (max 15) :
# - OpenAI, Grok xAI, Anthropic
# - AWS Access Key
# - GitHub PAT
# - Stripe (sk_live_)
# - Alibaba
# - Cloudflare
# - Azure AD
```

#### Export JSON

```bash
# Export JSON pour CI/CD ou traitement automatique
goleaks scan --output json > results.json

# Structure JSON :
# {
#   "summary": {
#     "total_secrets": 2,
#     "total_files": 1,
#     "scanned_files": 150
#   },
#   "secrets": [
#     {
#       "file": "config.env",
#       "line": 8,
#       "service": "AWS Access Key",
#       "match": "AKIA...MPLE",
#       "risk": "high",
#       "context": "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"
#     }
#   ],
#   "errors": []
# }
```

#### Export SARIF

```bash
# Export SARIF pour GitHub Security / CodeQL
goleaks scan --output sarif > results.sarif

# Compatible avec :
# - GitHub Security tab
# - Azure DevOps Security
# - CodeQL
```

#### Export texte formaté (`report-txt`)

```bash
# Export texte formaté pour audits (pas un vrai PDF)
goleaks scan --output report-txt > audit-report.txt

# Note: Génération PDF réelle avec gofpdf prévue pour la version Pro
```

#### Options combinées

```bash
# Scan intelligent avec vérification légère
goleaks scan --smart --verify-light

# Scan seulement les changements Git avec export JSON
goleaks scan --diff-only --output json > changes.json

# Scan avec dossiers personnalisés à ignorer
goleaks scan --ignore-dirs ".git,node_modules,vendor,tmp,dist"

# Scan avec support IaC
goleaks scan --iac-support
```

## 📋 Patterns détectés

Goleaks détecte actuellement **20 patterns** de secrets prioritaires :

| # | Service | Pattern | Risque | High-Risk* |
|---|---------|---------|--------|------------|
| 1 | **OpenAI** | `sk-[a-zA-Z0-9]{48}` | high | ✅ |
| 2 | **Grok xAI** | `sk-grok-[a-zA-Z0-9_\-]{93}AA` | high | ✅ |
| 3 | **Anthropic** | `sk-ant-api03-[a-zA-Z0-9_\-]{93}AA` | high | ✅ |
| 4 | **AWS Access Key** | `(AKIA\|ASIA\|ABIA\|ACCA)[A-Z0-9]{16}` | high | ✅ |
| 5 | **GitHub PAT** | `ghp_[a-zA-Z0-9]{36}` | high | ✅ |
| 6 | **Vercel** | `vercel_[a-zA-Z0-9]{32}` | high | ❌ |
| 7 | **Supabase** | `eyJ[a-zA-Z0-9._-]{100,}` | high | ❌ |
| 8 | **Fly.io** | `flyv1_[a-zA-Z0-9]{40}` | high | ❌ |
| 9 | **Stripe** | `sk_live_[a-zA-Z0-9]{24}` | high | ✅ |
| 10 | **Slack Bot** | `xoxb-[0-9]{11}-[0-9]{12}-[a-zA-Z0-9]{24}` | high | ❌ |
| 11 | **Discord Bot** | `[a-zA-Z0-9]{24}\.[a-zA-Z0-9]{6}\.[a-zA-Z0-9_\-]{27}` | high | ❌ |
| 12 | **Adobe** | `p8e-[a-z0-9]{32}` | medium | ❌ |
| 13 | **Airtable PAT** | `pat[a-zA-Z0-9]{14}\.[a-f0-9]{64}` | high | ❌ |
| 14 | **Algolia** | `[a-z0-9]{32}` (contexte requis*) | medium | ❌ |
| 15 | **Alibaba** | `LTAI[a-z0-9]{20}` | high | ✅ |
| 16 | **Asana** | `[a-z0-9]{32}` (contexte requis*) | medium | ❌ |
| 17 | **Cloudflare** | `[a-z0-9_-]{40}` | high | ✅ |
| 18 | **Bitbucket** | `[a-z0-9=_\-]{64}` | high | ❌ |
| 19 | **Atlassian** | `ATATT3[A-Za-z0-9_\-=]{186}` | high | ❌ |
| 20 | **Azure AD** | `[a-zA-Z0-9_~.]{3}\dQ~[a-zA-Z0-9_~.-]{31,34}` | high | ✅ |

\* **High-Risk** : Secrets vérifiés avec `--verify-light` (requêtes HTTP HEAD)  
\*\* **Contexte requis** : En mode `--smart`, le nom du service (ex: "algolia", "asana") doit être présent dans la ligne de contexte pour être considéré comme un secret valide (évite les faux positifs avec des hashes génériques)

## 🎯 Exemples d'utilisation avancés

### Intégration CI/CD (GitHub Actions)

```yaml
name: Secret Scan

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout code
        uses: actions/checkout@v3
      
      - name: Setup Go
        uses: actions/setup-go@v4
        with:
          go-version: '1.21'
      
      - name: Install Goleaks
        run: go install github.com/TALLHAMADOU/goleaks@latest
      
      - name: Run Goleaks
        run: goleaks scan --smart --output sarif > results.sarif
        continue-on-error: true
      
      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: results.sarif
```

### Pré-commit hook

```bash
#!/bin/bash
# .git/hooks/pre-commit

# Scanner seulement les changements
if goleaks scan --diff-only --output json | jq -e '.summary.total_secrets > 0' > /dev/null 2>&1; then
    echo "❌ Secrets détectés dans les changements !"
    goleaks scan --diff-only
    exit 1
fi
```

### Script de monitoring

```bash
#!/bin/bash
# scan-daily.sh

# Scan complet avec export JSON
goleaks scan --smart --output json > daily-scan-$(date +%Y%m%d).json

# Analyser les résultats
SECRETS=$(jq '.summary.total_secrets' daily-scan-$(date +%Y%m%d).json)

if [ "$SECRETS" -gt 0 ]; then
    echo "⚠️  $SECRETS secret(s) détecté(s) !"
    # Envoyer une alerte (Slack, email, etc.)
fi
```

## 🔧 Configuration

### Dossiers ignorés par défaut

- `.git`
- `node_modules`
- `vendor`
- `dist`
- `build`
- `.next`
- `.venv`
- `__pycache__`

### Extensions de fichiers scannées

**Code :**
- `.go`, `.js`, `.ts`, `.jsx`, `.tsx`
- `.py`, `.java`, `.rb`, `.php`, `.cs`

**Config :**
- `.env`, `.yaml`, `.yml`, `.json`, `.toml`
- `.conf`, `.config`

**IaC (avec `--iac-support`) :**
- `.tf`, `.tfvars`, `.hcl`
- `Dockerfile`, `docker-compose.*`

**Autres :**
- `.md`, `.txt`, `.xml`, `.html`, `.css`, `.scss`

### Mode intelligent (`--smart`)

Le mode intelligent applique plusieurs filtres pour réduire les faux positifs :

1. **Ignorer les dossiers** : `test/`, `spec/`, `example/`, `sample/`, `demo/`, `mock/`
2. **Ignorer les fichiers de documentation** : `README*`, `CHANGELOG*`, `LICENSE*`, `CONTRIBUTING*`
3. **Vérification d'entropie** : Filtre les UUID et hashes hexadécimaux simples (entropie < 4.0)
4. **Contexte requis** : Pour certains patterns génériques (Algolia, Asana), vérifie la présence du nom du service dans le contexte

### Verify-light (`--verify-light`)

La vérification légère effectue des requêtes HTTP HEAD pour valider les secrets high-risk :

- **Timeout** : 2 secondes par requête
- **User-Agent** : `Goleaks/1.0 (https://github.com/goleaks)`
- **Limite** : Maximum 15 secrets high-risk
- **Services vérifiés** : OpenAI, GitHub PAT, Stripe, Cloudflare, Azure AD, etc.

⚠️ **Note** : Cette fonctionnalité effectue des requêtes réseau. Utilisez-la avec précaution.

## 🛠️ Développement

### Structure du projet

```
goleaks/
├── cmd/
│   └── goleaks/
│       └── main.go          # Point d'entrée CLI (urfave/cli/v2)
├── patterns/
│   └── patterns.go          # Package patterns : 20 patterns regex optimisés avec IsHighRisk
├── scan/
│   ├── scan.go              # Package scan : Logique de scan récursif (filepath.WalkDir)
│   ├── git.go               # Support Git diff (--diff-only)
│   └── verify.go            # Vérification légère HTTP HEAD (--verify-light)
├── output/
│   └── output.go            # Package output : Affichage terminal, JSON, SARIF, PDF
├── go.mod                   # Module: github.com/TALLHAMADOU/goleaks
├── go.sum
└── README.md
```

### Installation en tant que package Go

```bash
# Installation globale (recommandé)
go install github.com/TALLHAMADOU/goleaks/cmd/goleaks@latest

# Vérifier que $GOPATH/bin est dans votre PATH
echo $PATH | grep -q "$HOME/go/bin" || export PATH=$PATH:$HOME/go/bin

# Utiliser goleaks
goleaks scan
```

### Compiler depuis les sources

```bash
# Télécharger les dépendances
go mod download

# Compiler le binaire CLI
go build -o goleaks ./cmd/goleaks

# Ou avec optimisations
go build -ldflags="-s -w" -o goleaks ./cmd/goleaks
```

### Dépendances

- `github.com/urfave/cli/v2` - CLI framework
- `github.com/fatih/color` - Couleurs terminal
- `github.com/jung-kurt/gofpdf` - Génération PDF (optionnel)
- `github.com/cheggaaa/pb/v3` - Barre de progression (optionnel)

### Tests

```bash
# Lancer tous les tests
go test ./...

# Tests avec couverture
go test -cover ./...

# Tests d'un package spécifique
go test ./scan
```

## 📝 Remédiation

Si Goleaks détecte des secrets :

1. **Rotatez immédiatement** toutes les clés actives détectées
   - AWS : [console.aws.amazon.com/iam](https://console.aws.amazon.com/iam)
   - GitHub : [github.com/settings/tokens](https://github.com/settings/tokens)
   - Stripe : [dashboard.stripe.com/apikeys](https://dashboard.stripe.com/apikeys)

2. **Utilisez des variables d'environnement** ou un gestionnaire de secrets
   - AWS Secrets Manager
   - HashiCorp Vault
   - Azure Key Vault
   - Google Secret Manager

3. **Vérifiez l'historique Git** pour les secrets exposés
   ```bash
   git log --all --full-history -- config.env
   git filter-repo --path config.env --invert-paths  # Nettoyer l'historique
   ```

4. **Activez la rotation automatique** des clés si disponible

5. **Surveillez les logs d'accès** pour détecter des utilisations suspectes

6. **Ajoutez des règles de pré-commit** pour empêcher les commits futurs

## 🚧 Roadmap / Version Pro

Fonctionnalités prévues pour la version Pro :

- [ ] **+700 patterns** : Base de données étendue de patterns
- [ ] **Dashboard SaaS** : Interface web pour visualisation et monitoring
- [ ] **Alertes Slack/Email** : Notifications automatiques
- [ ] **Vérification avancée** : Validation complète des secrets
- [ ] **Support Git complet** : Scan de l'historique Git complet
- [ ] **Remédiation automatique** : Suggestions de correction intelligentes
- [ ] **API REST** : Intégration avec vos outils existants
- [ ] **Scan parallèle** : Optimisation multi-thread pour très gros repos

## 🤝 Contribution

Les contributions sont les bienvenues ! Pour contribuer :

1. Fork le projet
2. Créez une branche (`git checkout -b feature/AmazingFeature`)
3. Committez vos changements (`git commit -m 'Add some AmazingFeature'`)
4. Push vers la branche (`git push origin feature/AmazingFeature`)
5. Ouvrez une Pull Request

### Guidelines

- Respectez le formatage Go (`gofmt`)
- Ajoutez des tests pour les nouvelles fonctionnalités
- Documentez les changements dans le README
- Suivez les conventions de nommage Go

## 📄 Licence

Ce projet est sous licence MIT. Voir le fichier `LICENSE` pour plus de détails.

## 🙏 Remerciements

- Inspiré par **TruffleHog** et **Gitleaks**
- Construit avec [urfave/cli](https://github.com/urfave/cli) pour le CLI
- Couleurs avec [fatih/color](https://github.com/fatih/color)

## 📞 Support

- 🐛 **Issues** : [GitHub Issues](https://github.com/TALLHAMADOU/goleaks/issues)
- 💬 **Discussions** : [GitHub Discussions](https://github.com/TALLHAMADOU/goleaks/discussions)
- 📧 **Email** : team@goleaks.dev

---

**Goleaks** - Détectez les secrets avant qu'ils ne soient compromis 🔒

*Version 1.0.0 - Dernière mise à jour : 2026*
