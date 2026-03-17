package main

import (
	"errors"
	"fmt"
	"strings"

	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

type Config struct {
	URL     string
	APIKey  string
	Name    string
	Version string
	Parent  string
	Tags    string
	SBOM    string
	Poll    bool
	Latest  bool
}

func (c *Config) validate() error {
	if c.URL == "" {
		return fmt.Errorf("missing required input: url (via --url or SBOM_UPLOADER_URL)")
	}
	if c.APIKey == "" {
		return fmt.Errorf("missing required input: api-key (via --api-key or SBOM_UPLOADER_API_KEY)")
	}
	if c.Name == "" {
		return fmt.Errorf("missing required input: name (via --name or SBOM_UPLOADER_NAME)")
	}
	if c.Parent == "" {
		return fmt.Errorf("missing required input: parent (via --parent or SBOM_UPLOADER_PARENT)")
	}
	if c.Version == "" {
		return fmt.Errorf("missing required input: version (via --version or SBOM_UPLOADER_VERSION)")
	}
	return nil
}

// loadConfig resolves configuration from flags and environment variables.
// Flags take precedence over env vars; env vars take precedence over defaults.
//
// AutomaticEnv + BindPFlags has a known issue where bool flags with a false
// default have their pflag default shadow the env var. We work around it with
// explicit BindEnv calls for bool flags.
// See https://github.com/spf13/viper/issues/671
func loadConfig(flags *pflag.FlagSet) (*Config, error) {
	v := viper.New()
	v.SetEnvPrefix("SBOM_UPLOADER")
	v.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))
	v.AutomaticEnv()
	if err := errors.Join(
		v.BindPFlags(flags),
		v.BindEnv("poll", "SBOM_UPLOADER_POLL"),
		v.BindEnv("latest", "SBOM_UPLOADER_LATEST"),
	); err != nil {
		return nil, err
	}
	return &Config{
		URL:     v.GetString("url"),
		APIKey:  v.GetString("api-key"),
		Name:    v.GetString("name"),
		Version: v.GetString("version"),
		Parent:  v.GetString("parent"),
		Tags:    v.GetString("tags"),
		SBOM:    v.GetString("sbom"),
		Poll:    v.GetBool("poll"),
		Latest:  v.GetBool("latest"),
	}, nil
}

func setFlags(s *pflag.FlagSet) {
	s.String("url", "", "Dependency-Track API base URL or env SBOM_UPLOADER_URL")
	s.String("api-key", "", "Dependency-Track API key or env SBOM_UPLOADER_API_KEY")
	s.String("name", "", "Project name or env SBOM_UPLOADER_NAME")
	s.String("version", "", "Project version or env SBOM_UPLOADER_VERSION")
	s.String("parent", "", "Parent project name or env SBOM_UPLOADER_PARENT")
	s.Bool("latest", true, "Mark as latest version (default true)")
	s.Bool("poll", false, "Poll until import completes or env SBOM_UPLOADER_POLL")
	s.String("tags", "", "Comma-separated project tags or env SBOM_UPLOADER_TAGS")
	s.String("sbom", "", "Path to SBOM file (optional; otherwise read from stdin)")
}
