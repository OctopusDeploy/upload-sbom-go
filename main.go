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

	"github.com/hashicorp/go-retryablehttp"
	"github.com/spf13/cobra"
)

var (
	dependencyTrackUrl string
	dependencyTrackKey string
	projectName        string
	projectVersion     string
	parentName         string
	isLatest           bool
	projectTags        string
	sbomFilePath       string
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "sbom-uploader",
		Short: "Uploads SBOM to Dependency-Track",
		RunE:  runUploader,
	}

	rootCmd.Flags().StringVar(&dependencyTrackUrl, "url", "", "Dependency-Track API base URL or env DEPENDENCY_TRACK_URL")
	rootCmd.Flags().StringVar(&dependencyTrackKey, "api-key", "", "Dependency-Track API key or env DEPENDENCY_TRACK_KEY")
	rootCmd.Flags().StringVar(&projectName, "name", "", "Project name or env PROJECT_NAME")
	rootCmd.Flags().StringVar(&projectVersion, "version", "", "Project version or env PROJECT_VERSION")
	rootCmd.Flags().StringVar(&parentName, "parent", "", "Parent project name or env PROJECT_PARENT")
	rootCmd.Flags().BoolVar(&isLatest, "latest", true, "Mark as latest version (default true)")
	rootCmd.Flags().StringVar(&projectTags, "tags", "", "Comma-separated project tags or env PROJECT_TAGS")
	rootCmd.Flags().StringVar(&sbomFilePath, "sbom", "", "Path to SBOM file (optional; otherwise read from stdin)")

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Execution failed: %v\n", err)
		os.Exit(1)
	}
}

func runUploader(cmd *cobra.Command, args []string) error {
	dependencyTrackUrl = fallback(dependencyTrackUrl, os.Getenv("DEPENDENCY_TRACK_URL"))
	dependencyTrackKey = fallback(dependencyTrackKey, os.Getenv("DEPENDENCY_TRACK_KEY"))
	projectName = fallback(projectName, os.Getenv("PROJECT_NAME"))
	projectVersion = fallback(projectVersion, os.Getenv("PROJECT_VERSION"))
	parentName = fallback(parentName, os.Getenv("PROJECT_PARENT"))
	projectTags = fallback(projectTags, os.Getenv("PROJECT_TAGS"))

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
	writer.WriteField("projectName", projectName)
	writer.WriteField("projectVersion", projectVersion)
	writer.WriteField("autoCreate", "true")

	if isLatest {
		writer.WriteField("isLatest", "true")
	}
	if parentName != "" {
		writer.WriteField("parentName", parentName)
	}
	if projectTags != "" {
		writer.WriteField("projectTags", projectTags)
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

func fallback(primary, fallback string) string {
	if primary != "" {
		return primary
	}
	return fallback
}

func checkRetry(ctx context.Context, resp *http.Response, err error) (bool, error) {
	if resp != nil && resp.StatusCode >= 404 {
		return true, nil
	}
	return retryablehttp.DefaultRetryPolicy(ctx, resp, err)
}
