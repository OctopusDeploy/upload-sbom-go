package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"

	"github.com/hashicorp/go-retryablehttp"
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
	v.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))
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
	if dependencyTrackUrl == "" {
		return fmt.Errorf("missing required inputs: url (via flags or env)")
	}
	if dependencyTrackKey == "" {
		return fmt.Errorf("missing required inputs: api-key (via flags or env)")
	}
	if projectName == "" {
		return fmt.Errorf("missing required inputs: name (via flags or env)")
	}
	if projectVersion == "" {
		return fmt.Errorf("missing required inputs: version (via flags or env)")
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
	req, err := retryablehttp.NewRequest("POST", url, &requestBody)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", writer.FormDataContentType())
	req.Header.Set("X-Api-Key", dependencyTrackKey)

	// Execute request
	retryClient := retryablehttp.NewClient()
	retryClient.RetryMax = 20
	retryClient.CheckRetry = checkRetry
	resp, err := retryClient.Do(req)
	if err != nil {
		return fmt.Errorf("HTTP request failed: %w", err)
	}
	defer func(Body io.ReadCloser) {
		_ = Body.Close()
	}(resp.Body)

	respBody, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusAccepted && resp.StatusCode != http.StatusOK {
		return fmt.Errorf("upload failed (%d): %s", resp.StatusCode, string(respBody))
	}

	fmt.Println("✅ SBOM upload successful.")
	return nil
}

func setFlags(s *pflag.FlagSet) {
	s.String("url", "", "Dependency-Track API base URL or env SBOM_UPLOADER_URL")
	s.String("api-key", "", "Dependency-Track API key or env SBOM_UPLOADER_API_KEY")
	s.String("name", "", "Project name or env SBOM_UPLOADER_NAME")
	s.String("version", "", "Project version or env SBOM_UPLOADER_VERSION")
	s.String("parent", "", "Parent project name or env SBOM_UPLOADER_PARENT")
	s.Bool("latest", true, "Mark as latest version (default true)")
	s.String("tags", "", "Comma-separated project tags or env SBOM_UPLOADER_TAGS")
	s.String("sbom", "", "Path to SBOM file (optional; otherwise read from stdin)")
}

func checkRetry(ctx context.Context, resp *http.Response, err error) (bool, error) {
	if resp != nil && resp.StatusCode >= 404 {
		return true, nil
	}
	return retryablehttp.DefaultRetryPolicy(ctx, resp, err)
}
