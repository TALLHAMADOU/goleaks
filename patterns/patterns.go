package patterns

import (
	"regexp"
)

// Pattern représente un pattern de détection de secret
type Pattern struct {
	Service    string
	Regex      *regexp.Regexp
	Risk       string // "high", "medium", "low"
	IsHighRisk bool   // true pour verify-light (secrets dangereux prioritaires)
}

// Patterns contient tous les patterns de détection optimisés
var Patterns []Pattern

func init() {
	// Compilation des regex au démarrage pour optimiser les performances
	Patterns = []Pattern{
		{
			Service:    "OpenAI",
			Regex:      regexp.MustCompile(`\bsk-[a-zA-Z0-9]{48}\b`),
			Risk:       "high",
			IsHighRisk: true,
		},
		{
			Service:    "Grok xAI",
			Regex:      regexp.MustCompile(`\bsk-grok-[a-zA-Z0-9_\-]{93}AA\b`),
			Risk:       "high",
			IsHighRisk: true,
		},
		{
			Service:    "Anthropic",
			Regex:      regexp.MustCompile(`\bsk-ant-api03-[a-zA-Z0-9_\-]{93}AA\b`),
			Risk:       "high",
			IsHighRisk: true,
		},
		{
			Service:    "AWS Access Key",
			Regex:      regexp.MustCompile(`\b(AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}\b`),
			Risk:       "high",
			IsHighRisk: true,
		},
		{
			Service:    "GitHub PAT",
			Regex:      regexp.MustCompile(`\bghp_[a-zA-Z0-9]{36}\b`),
			Risk:       "high",
			IsHighRisk: true,
		},
		{
			Service:    "Vercel",
			Regex:      regexp.MustCompile(`\bvercel_[a-zA-Z0-9]{32}\b`),
			Risk:       "high",
			IsHighRisk: false,
		},
		{
			Service:    "Supabase",
			Regex:      regexp.MustCompile(`\beyJ[a-zA-Z0-9._-]{100,}\b`),
			Risk:       "high",
			IsHighRisk: false,
		},
		{
			Service:    "Fly.io",
			Regex:      regexp.MustCompile(`\bflyv1_[a-zA-Z0-9]{40}\b`),
			Risk:       "high",
			IsHighRisk: false,
		},
		{
			Service:    "Stripe",
			Regex:      regexp.MustCompile(`\bsk_live_[a-zA-Z0-9]{24}\b`),
			Risk:       "high",
			IsHighRisk: true,
		},
		{
			Service:    "Slack Bot",
			Regex:      regexp.MustCompile(`\bxoxb-[0-9]{11}-[0-9]{12}-[a-zA-Z0-9]{24}\b`),
			Risk:       "high",
			IsHighRisk: false,
		},
		{
			Service:    "Discord Bot",
			Regex:      regexp.MustCompile(`\b[a-zA-Z0-9]{24}\.[a-zA-Z0-9]{6}\.[a-zA-Z0-9_\-]{27}\b`),
			Risk:       "high",
			IsHighRisk: false,
		},
		{
			Service:    "Adobe",
			Regex:      regexp.MustCompile(`\bp8e-[a-z0-9]{32}\b`),
			Risk:       "medium",
			IsHighRisk: false,
		},
		{
			Service:    "Airtable PAT",
			Regex:      regexp.MustCompile(`\bpat[a-zA-Z0-9]{14}\.[a-f0-9]{64}\b`),
			Risk:       "high",
			IsHighRisk: false,
		},
		{
			Service:    "Algolia",
			Regex:      regexp.MustCompile(`\b[a-z0-9]{32}\b`),
			Risk:       "medium", // Nécessite contexte pour éviter faux positifs
			IsHighRisk: false,
		},
		{
			Service:    "Alibaba",
			Regex:      regexp.MustCompile(`\bLTAI[a-z0-9]{20}\b`),
			Risk:       "high",
			IsHighRisk: true,
		},
		{
			Service:    "Asana",
			Regex:      regexp.MustCompile(`\b[a-z0-9]{32}\b`),
			Risk:       "medium", // Nécessite contexte pour éviter faux positifs
			IsHighRisk: false,
		},
		{
			Service:    "Cloudflare",
			Regex:      regexp.MustCompile(`\b[a-z0-9_-]{40}\b`),
			Risk:       "high",
			IsHighRisk: true,
		},
		{
			Service:    "Bitbucket",
			Regex:      regexp.MustCompile(`\b[a-z0-9=_\-]{64}\b`),
			Risk:       "high",
			IsHighRisk: false,
		},
		{
			Service:    "Atlassian",
			Regex:      regexp.MustCompile(`\b(ATATT3[A-Za-z0-9_\-=]{186})\b`),
			Risk:       "high",
			IsHighRisk: false,
		},
		{
			Service:    "Azure AD",
			Regex:      regexp.MustCompile(`\b[a-zA-Z0-9_~.]{3}\dQ~[a-zA-Z0-9_~.-]{31,34}\b`),
			Risk:       "high",
			IsHighRisk: true,
		},
	}
}

// GetPatterns retourne tous les patterns compilés
func GetPatterns() []Pattern {
	return Patterns
}

// PatternCount retourne le nombre total de patterns
func PatternCount() int {
	return len(Patterns)
}
