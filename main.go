package main

import (
	"bytes"
	"fmt"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"strings"
)

var (
	v *viper.Viper
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "sbom-uploader",
		Short: "Uploads SBOM to Dependency-Track",
		RunE:  runUploader,
	}

	// Initialise flags
	setFlags(rootCmd.Flags())

	// Create the viper instance
	v = viper.New()
	v.SetEnvPrefix("SBOM_UPLOADER")
	v.AutomaticEnv()
	err := v.BindPFlags(rootCmd.Flags())
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Failed to bind flags: %v\n", err)
		os.Exit(1)
	}

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Execution failed: %v\n", err)
		os.Exit(1)
	}
}

func runUploader(cmd *cobra.Command, args []string) error {

	dependencyTrackUrl := v.GetString("url")
	dependencyTrackKey := v.GetString("api-key")
	projectName := v.GetString("name")
	projectVersion := v.GetString("version")
	sbomFilePath := v.GetString("sbom")
	// Check required inputs
	if dependencyTrackUrl == "" || dependencyTrackKey == "" || projectName == "" || projectVersion == "" {
		return fmt.Errorf("missing required inputs: url, api-key, name, or version (via flags or env)")
	}

	// Read SBOM from file or stdin
	var sbomContent []byte
	var err error
	if sbomFilePath != "" {
		sbomContent, err = os.ReadFile(sbomFilePath)
		if err != nil {
			return fmt.Errorf("failed to read SBOM file: %w", err)
		}
	} else {
		sbomContent, err = io.ReadAll(os.Stdin)
		if err != nil {
			return fmt.Errorf("failed to read SBOM from stdin: %w", err)
		}
		if len(sbomContent) == 0 {
			return fmt.Errorf("no SBOM content provided (empty stdin)")
		}
	}

	// Prepare multipart/form-data
	var requestBody bytes.Buffer
	writer := multipart.NewWriter(&requestBody)

	// Add SBOM file part
	sbomPart, err := writer.CreateFormFile("bom", "sbom.json")
	if err != nil {
		return fmt.Errorf("failed to create SBOM form part: %w", err)
	}
	if _, err := sbomPart.Write(sbomContent); err != nil {
		return fmt.Errorf("failed to write SBOM content: %w", err)
	}

	// Add metadata fields
	_ = writer.WriteField("projectName", projectName)
	_ = writer.WriteField("projectVersion", projectVersion)
	_ = writer.WriteField("autoCreate", "true")

	if v.GetBool("latest") {
		_ = writer.WriteField("isLatest", "true")
	}
	if v := v.GetString("parent"); v != "" {
		_ = writer.WriteField("parentName", v)
	}
	if projectTags := v.GetString("tags"); projectTags != "" {
		_ = writer.WriteField("projectTags", projectTags)
	}

	// Close writer to finalize body
	if err := writer.Close(); err != nil {
		return fmt.Errorf("failed to finalize multipart body: %w", err)
	}

	// Create HTTP request
	url := fmt.Sprintf("%s/api/v1/bom", strings.TrimRight(dependencyTrackUrl, "/"))
	req, err := http.NewRequest("POST", url, &requestBody)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", writer.FormDataContentType())
	req.Header.Set("X-Api-Key", dependencyTrackKey)

	// Execute request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusAccepted && resp.StatusCode != http.StatusOK {
		return fmt.Errorf("upload failed (%d): %s", resp.StatusCode, string(respBody))
	}

	fmt.Println("✅ SBOM upload successful.")
	return nil
}

func fallback(primary, fallback string) string {
	if primary != "" {
		return primary
	}
	return fallback
}

func setFlags(s *pflag.FlagSet) {
	s.String("url", "", "Dependency-Track API base URL or env DEPENDENCY_TRACK_URL")
	s.String("api-key", "", "Dependency-Track API key or env DEPENDENCY_TRACK_KEY")
	s.String("name", "", "Project name or env PROJECT_NAME")
	s.String("version", "", "Project version or env PROJECT_VERSION")
	s.String("parent", "", "Parent project name or env PROJECT_PARENT")
	s.Bool("latest", true, "Mark as latest version (default true)")
	s.String("tags", "", "Comma-separated project tags or env PROJECT_TAGS")
	s.String("sbom", "", "Path to SBOM file (optional; otherwise read from stdin)")
}
