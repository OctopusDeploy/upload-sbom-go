package main

import (
	"strings"
	"testing"

	"github.com/spf13/pflag"
)

// newFlagSet returns a FlagSet populated with the same flags as the real CLI.
func newFlagSet() *pflag.FlagSet {
	flags := pflag.NewFlagSet("test", pflag.ContinueOnError)
	setFlags(flags)
	return flags
}

func TestLoadConfig_StringsFromEnvVars(t *testing.T) {
	t.Setenv("SBOM_UPLOADER_URL", "https://example.com")
	t.Setenv("SBOM_UPLOADER_API_KEY", "my-api-key")
	t.Setenv("SBOM_UPLOADER_NAME", "my-project")
	t.Setenv("SBOM_UPLOADER_VERSION", "1.2.3")
	t.Setenv("SBOM_UPLOADER_PARENT", "my-parent")
	t.Setenv("SBOM_UPLOADER_TAGS", "tag1,tag2")
	t.Setenv("SBOM_UPLOADER_SBOM", "/path/to/sbom.json")

	cfg, err := loadConfig(newFlagSet())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.URL != "https://example.com" {
		t.Errorf("URL: got %q, want %q", cfg.URL, "https://example.com")
	}
	if cfg.APIKey != "my-api-key" {
		t.Errorf("APIKey: got %q, want %q", cfg.APIKey, "my-api-key")
	}
	if cfg.Name != "my-project" {
		t.Errorf("Name: got %q, want %q", cfg.Name, "my-project")
	}
	if cfg.Version != "1.2.3" {
		t.Errorf("Version: got %q, want %q", cfg.Version, "1.2.3")
	}
	if cfg.Parent != "my-parent" {
		t.Errorf("Parent: got %q, want %q", cfg.Parent, "my-parent")
	}
	if cfg.Tags != "tag1,tag2" {
		t.Errorf("Tags: got %q, want %q", cfg.Tags, "tag1,tag2")
	}
	if cfg.SBOM != "/path/to/sbom.json" {
		t.Errorf("SBOM: got %q, want %q", cfg.SBOM, "/path/to/sbom.json")
	}
}

func TestLoadConfig_PollFromEnvVar(t *testing.T) {
	t.Setenv("SBOM_UPLOADER_POLL", "true")

	cfg, err := loadConfig(newFlagSet())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !cfg.Poll {
		t.Error("Poll: expected true from SBOM_UPLOADER_POLL env var, got false")
	}
}

func TestLoadConfig_LatestFromEnvVar(t *testing.T) {
	t.Setenv("SBOM_UPLOADER_LATEST", "false")

	cfg, err := loadConfig(newFlagSet())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Latest {
		t.Error("Latest: expected false from SBOM_UPLOADER_LATEST env var, got true")
	}
}

func TestLoadConfig_FromFlags(t *testing.T) {
	flags := newFlagSet()
	err := flags.Parse([]string{
		"--url", "https://from-flag.com",
		"--api-key", "flag-key",
		"--name", "flag-project",
		"--version", "2.0.0",
		"--parent", "flag-parent",
		"--tags", "a,b",
		"--sbom", "/flag/sbom.json",
		"--poll",
		"--latest=false",
	})
	if err != nil {
		t.Fatalf("failed to parse flags: %v", err)
	}

	cfg, err := loadConfig(flags)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.URL != "https://from-flag.com" {
		t.Errorf("URL: got %q, want %q", cfg.URL, "https://from-flag.com")
	}
	if cfg.APIKey != "flag-key" {
		t.Errorf("APIKey: got %q, want %q", cfg.APIKey, "flag-key")
	}
	if cfg.Name != "flag-project" {
		t.Errorf("Name: got %q, want %q", cfg.Name, "flag-project")
	}
	if cfg.Version != "2.0.0" {
		t.Errorf("Version: got %q, want %q", cfg.Version, "2.0.0")
	}
	if cfg.Parent != "flag-parent" {
		t.Errorf("Parent: got %q, want %q", cfg.Parent, "flag-parent")
	}
	if cfg.Tags != "a,b" {
		t.Errorf("Tags: got %q, want %q", cfg.Tags, "a,b")
	}
	if cfg.SBOM != "/flag/sbom.json" {
		t.Errorf("SBOM: got %q, want %q", cfg.SBOM, "/flag/sbom.json")
	}
	if !cfg.Poll {
		t.Error("Poll: expected true from --poll flag, got false")
	}
	if cfg.Latest {
		t.Error("Latest: expected false from --latest=false flag, got true")
	}
}

func TestLoadConfig_FlagOverridesEnvVar(t *testing.T) {
	t.Setenv("SBOM_UPLOADER_URL", "https://from-env.com")

	flags := newFlagSet()
	if err := flags.Parse([]string{"--url", "https://from-flag.com"}); err != nil {
		t.Fatalf("failed to parse flags: %v", err)
	}

	cfg, err := loadConfig(flags)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.URL != "https://from-flag.com" {
		t.Errorf("URL: expected flag to override env var, got %q", cfg.URL)
	}
}

func TestLoadConfig_Defaults(t *testing.T) {
	cfg, err := loadConfig(newFlagSet())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Poll {
		t.Error("Poll: expected false by default, got true")
	}
	if !cfg.Latest {
		t.Error("Latest: expected true by default, got false")
	}
}

// --- Config.validate ---

func validConfig() *Config {
	return &Config{
		URL:     "https://example.com",
		APIKey:  "key",
		Name:    "project",
		Parent:  "parent",
		Version: "1.0.0",
	}
}

func TestValidate_PassesWithAllRequiredFields(t *testing.T) {
	if err := validConfig().validate(); err != nil {
		t.Errorf("expected no error, got: %v", err)
	}
}

func TestValidate_RequiredFields(t *testing.T) {
	tests := []struct {
		field   string
		mutate  func(*Config)
		wantMsg string
	}{
		{"URL", func(c *Config) { c.URL = "" }, "url"},
		{"APIKey", func(c *Config) { c.APIKey = "" }, "api-key"},
		{"Name", func(c *Config) { c.Name = "" }, "name"},
		{"Parent", func(c *Config) { c.Parent = "" }, "parent"},
		{"Version", func(c *Config) { c.Version = "" }, "version"},
	}

	for _, tt := range tests {
		t.Run(tt.field, func(t *testing.T) {
			cfg := validConfig()
			tt.mutate(cfg)
			err := cfg.validate()
			if err == nil {
				t.Fatalf("expected error for missing %s, got nil", tt.field)
			}
			if !strings.Contains(err.Error(), tt.wantMsg) {
				t.Errorf("error %q does not mention %q", err.Error(), tt.wantMsg)
			}
		})
	}
}
