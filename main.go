package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"

	"github.com/hashicorp/go-retryablehttp"
)

var (
	v *viper.Viper
)

type Tag struct {
	Name string `json:"name"`
}

type Metrics struct {
	Components      int `json:"components"`
	Vulnerabilities int `json:"vulnerabilities"`
}

type Project struct {
	UUID            string    `json:"uuid,omitempty"`
	Name            string    `json:"name"`
	Classifier      string    `json:"classifier,omitempty"`
	Version         string    `json:"version,omitempty"`
	Description     string    `json:"description,omitempty"`
	Active          bool      `json:"active,omitempty"`
	Tags            []Tag     `json:"tags,omitempty"`
	Children        []Project `json:"children,omitempty"`
	Parent          *Project  `json:"parent,omitempty"`
	CollectionLogic string    `json:"collectionLogic,omitempty"`
	Metrics         *Metrics  `json:"metrics,omitempty"`
}

func newDefaultRetryClient() *retryablehttp.Client {
	c := retryablehttp.NewClient()
	c.RetryMax = 20
	c.CheckRetry = checkRetry
	c.Logger = &httpLogger{}
	return c
}

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

func createParent(dependencyTrackUrl string, dependencyTrackKey string, parentName string, tags string, client *retryablehttp.Client) (string, error) {
	url := fmt.Sprintf("%s/api/v1/project", strings.TrimRight(dependencyTrackUrl, "/"))
	newProject := &Project{
		Name:            parentName,
		Classifier:      "APPLICATION",
		CollectionLogic: "AGGREGATE_LATEST_VERSION_CHILDREN",
		Tags:            []Tag{},
	}

	for _, tag := range strings.Split(tags, ",") {
		newProject.Tags = append(newProject.Tags, Tag{Name: tag})
	}

	jsonBody, err := json.Marshal(newProject)
	if err != nil {
		return "", fmt.Errorf("failed to marshal request body: %w", err)
	}
	reqBody := bytes.NewBuffer(jsonBody)

	req, err := retryablehttp.NewRequest("PUT", url, reqBody)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("X-Api-Key", dependencyTrackKey)
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("HTTP request failed: %w", err)
	}
	defer func(Body io.ReadCloser) {
		_ = Body.Close()
	}(resp.Body)

	if resp.StatusCode != http.StatusCreated {
		respBody, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("failed to create parent project, status %d: %s", resp.StatusCode, respBody)
	}

	var created Project
	if err := json.NewDecoder(resp.Body).Decode(&created); err != nil {
		return "", fmt.Errorf("failed to parse create project response: %w", err)
	}
	return created.UUID, nil
}

func ensureParentExists(dependencyTrackUrl string, dependencyTrackKey string, parentName string, tags string, client *retryablehttp.Client) error {
	fmt.Printf("Ensuring parent project %q exists...\n", parentName)
	url := fmt.Sprintf("%s/api/v1/project/lookup?name=%s", strings.TrimRight(dependencyTrackUrl, "/"), parentName)
	req, err := retryablehttp.NewRequest("GET", url, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("X-Api-Key", dependencyTrackKey)

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("HTTP request failed: %w", err)
	}
	defer func(Body io.ReadCloser) {
		_ = Body.Close()
	}(resp.Body)

	if resp.StatusCode == http.StatusNotFound {
		fmt.Printf("Parent project %q not found, creating it...\n", parentName)
		uuid, err := createParent(dependencyTrackUrl, dependencyTrackKey, parentName, tags, client)
		if err != nil {
			return err
		}
		fmt.Printf("Parent project %q created (uuid: %s).\n", parentName, uuid)
		return nil
	}

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("parent project lookup failed with status %d: %s", resp.StatusCode, respBody)
	}

	var project Project
	if err := json.NewDecoder(resp.Body).Decode(&project); err != nil {
		return fmt.Errorf("unable to decode response: %w", err)
	}
	fmt.Printf("Parent project %q found (uuid: %s).\n", parentName, project.UUID)
	return nil
}

func uploadSbom(dependencyTrackUrl string, dependencyTrackKey string, projectName string, parentName string, projectVersion string, sbomFilePath string, tags string, client *retryablehttp.Client) (string, error) {
	// Read SBOM from file or stdin
	var sbomContent []byte
	var err error
	if sbomFilePath != "" {
		fmt.Printf("Reading SBOM from file: %s\n", sbomFilePath)
		sbomContent, err = os.ReadFile(sbomFilePath)
		if err != nil {
			return "", fmt.Errorf("failed to read SBOM file: %w", err)
		}
		fmt.Printf("SBOM file read (%d bytes).\n", len(sbomContent))
	} else {
		fmt.Println("Reading SBOM from stdin...")
		sbomContent, err = io.ReadAll(os.Stdin)
		if err != nil {
			return "", fmt.Errorf("failed to read SBOM from stdin: %w", err)
		}
		if len(sbomContent) == 0 {
			return "", fmt.Errorf("no SBOM content provided (empty stdin)")
		}
		fmt.Printf("SBOM read from stdin (%d bytes).\n", len(sbomContent))
	}

	// Prepare multipart/form-data
	var requestBody bytes.Buffer
	writer := multipart.NewWriter(&requestBody)

	// Add SBOM file part
	sbomPart, err := writer.CreateFormFile("bom", "sbom.json")
	if err != nil {
		return "", fmt.Errorf("failed to create SBOM form part: %w", err)
	}
	if _, err := sbomPart.Write(sbomContent); err != nil {
		return "", fmt.Errorf("failed to write SBOM content: %w", err)
	}

	// Add metadata fields
	_ = writer.WriteField("projectName", projectName)
	_ = writer.WriteField("parentName", parentName)
	_ = writer.WriteField("projectVersion", projectVersion)
	_ = writer.WriteField("autoCreate", "true")
	_ = writer.WriteField("tags", tags)

	if v.GetBool("latest") {
		_ = writer.WriteField("isLatest", "true")
	}

	// Close writer to finalize body
	if err := writer.Close(); err != nil {
		return "", fmt.Errorf("failed to finalize multipart body: %w", err)
	}

	fmt.Printf("Uploading SBOM for project %q version %q (parent: %q)...\n", projectName, projectVersion, parentName)
	// Create HTTP request
	url := fmt.Sprintf("%s/api/v1/bom", strings.TrimRight(dependencyTrackUrl, "/"))
	req, err := retryablehttp.NewRequest("POST", url, &requestBody)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", writer.FormDataContentType())
	req.Header.Set("X-Api-Key", dependencyTrackKey)

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("HTTP request failed: %w", err)
	}
	defer func(Body io.ReadCloser) {
		_ = Body.Close()
	}(resp.Body)

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("upload failed with status %d: %s", resp.StatusCode, respBody)
	}

	var uploadResp struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&uploadResp); err != nil {
		return "", fmt.Errorf("failed to parse upload response: %w", err)
	}
	fmt.Printf("SBOM queued for import (token: %s).\n", uploadResp.Token)
	return uploadResp.Token, nil
}

func pollImport(dependencyTrackUrl string, dependencyTrackKey string, token string, client *retryablehttp.Client, interval time.Duration) error {
	const timeout = 5 * time.Minute
	url := fmt.Sprintf("%s/api/v1/bom/token/%s", strings.TrimRight(dependencyTrackUrl, "/"), token)
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		req, err := retryablehttp.NewRequest("GET", url, nil)
		if err != nil {
			return fmt.Errorf("failed to create poll request: %w", err)
		}
		req.Header.Set("X-Api-Key", dependencyTrackKey)

		resp, err := client.Do(req)
		if err != nil {
			return fmt.Errorf("poll request failed: %w", err)
		}

		if resp.StatusCode != http.StatusOK {
			respBody, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			return fmt.Errorf("poll request failed with status %d: %s", resp.StatusCode, respBody)
		}

		var tokenResp struct {
			Processing bool `json:"processing"`
		}
		err = json.NewDecoder(resp.Body).Decode(&tokenResp)
		_ = resp.Body.Close()
		if err != nil {
			return fmt.Errorf("failed to parse poll response: %w", err)
		}

		if !tokenResp.Processing {
			return nil
		}
		fmt.Println("Still processing, waiting...")
		time.Sleep(interval)
	}
	return fmt.Errorf("timed out waiting for import to complete after %s", timeout)
}

func fetchProjectSummary(dependencyTrackUrl string, dependencyTrackKey string, projectName string, projectVersion string, client *retryablehttp.Client) (*Project, error) {
	url := fmt.Sprintf("%s/api/v1/project/lookup?name=%s&version=%s",
		strings.TrimRight(dependencyTrackUrl, "/"), projectName, projectVersion)
	req, err := retryablehttp.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("X-Api-Key", dependencyTrackKey)

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTP request failed: %w", err)
	}
	defer func(Body io.ReadCloser) {
		_ = Body.Close()
	}(resp.Body)

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to fetch project summary, status %d: %s", resp.StatusCode, respBody)
	}

	var project Project
	if err := json.NewDecoder(resp.Body).Decode(&project); err != nil {
		return nil, fmt.Errorf("failed to parse project response: %w", err)
	}
	return &project, nil
}

func runUploader(cmd *cobra.Command, args []string) error {

	dependencyTrackUrl := v.GetString("url")
	dependencyTrackKey := v.GetString("api-key")
	projectName := v.GetString("name")
	parentName := v.GetString("parent")
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
	if parentName == "" {
		return fmt.Errorf("missing required inputs: name (via flags or env)")
	}
	if projectVersion == "" {
		return fmt.Errorf("missing required inputs: version (via flags or env)")
	}
	tags := ""
	if projectTags := v.GetString("tags"); projectTags != "" {
		tags = projectTags
	}

	client := newDefaultRetryClient()

	err := ensureParentExists(dependencyTrackUrl, dependencyTrackKey, parentName, tags, client)
	if err != nil {
		return err
	}
	token, err := uploadSbom(dependencyTrackUrl, dependencyTrackKey, projectName, parentName, projectVersion, sbomFilePath, tags, client)
	if err != nil {
		return err
	}

	fmt.Println("✅ SBOM upload successful.")
	if v.GetBool("poll") {
		fmt.Println("⏳ Polling until fully imported...")
		if err := pollImport(dependencyTrackUrl, dependencyTrackKey, token, client, 2*time.Second); err != nil {
			return err
		}
		project, err := fetchProjectSummary(dependencyTrackUrl, dependencyTrackKey, projectName, projectVersion, client)
		if err != nil {
			return err
		}
		components, vulnerabilities := 0, 0
		if project.Metrics != nil {
			components = project.Metrics.Components
			vulnerabilities = project.Metrics.Vulnerabilities
		}
		fmt.Printf("✅ SBOM imported successfully (%d components, %d vulnerabilities).\n", components, vulnerabilities)
	}

	return nil
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

func checkRetry(ctx context.Context, resp *http.Response, err error) (bool, error) {
	if resp != nil && resp.StatusCode >= 400 && resp.StatusCode < 500 {
		return false, nil
	}
	return retryablehttp.DefaultRetryPolicy(ctx, resp, err)
}
