package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hashicorp/go-retryablehttp"
	"github.com/spf13/viper"
)

// setupViper initialises the global viper instance that uploadSbom() reads from.
func setupViper() {
	v = viper.New()
}

// noRetryClient returns a client with retries disabled, suitable for unit tests.
func noRetryClient() *retryablehttp.Client {
	c := retryablehttp.NewClient()
	c.RetryMax = 0
	return c
}

// writeTempSbom writes content to a temp file and returns its path.

func writeTempSbom(t *testing.T, content []byte) string {
	t.Helper()
	tmp, err := os.CreateTemp(t.TempDir(), "sbom-*.json")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	if _, err := tmp.Write(content); err != nil {
		t.Fatalf("failed to write temp file: %v", err)
	}
	tmp.Close()
	return tmp.Name()
}

// --- checkRetry ---

func TestCheckRetry_4xxDoesNotRetry(t *testing.T) {
	for _, status := range []int{400, 401, 403, 404, 422} {
		resp := &http.Response{StatusCode: status}
		retry, err := checkRetry(context.Background(), resp, nil)
		if retry || err != nil {
			t.Errorf("status %d: expected (false, nil), got (%v, %v)", status, retry, err)
		}
	}
}

// --- uploadSbom ---

func TestUploadSbom_Returns200(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/bom" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if r.Header.Get("X-Api-Key") != "test-key" {
			t.Errorf("unexpected API key: %s", r.Header.Get("X-Api-Key"))
		}
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]string{"token": "abc-123"})
	}))
	defer server.Close()

	setupViper()
	sbomPath := writeTempSbom(t, []byte(`{"bomFormat":"CycloneDX"}`))

	_, err := uploadSbom(server.URL, "test-key", "my-project", "my-parent", "1.0.0", sbomPath, "", noRetryClient())
	if err != nil {
		t.Errorf("expected nil error, got: %v", err)
	}
}

func TestUploadSbom_400ReturnsError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, `{"status":400,"title":"The uploaded BOM is invalid","detail":"BOM is neither valid JSON nor XML"}`)
	}))
	defer server.Close()

	setupViper()
	sbomPath := writeTempSbom(t, []byte(`THIS IS NOT JSON`))

	_, err := uploadSbom(server.URL, "test-key", "my-project", "my-parent", "1.0.0", sbomPath, "", noRetryClient())
	if err == nil {
		t.Error("expected error for HTTP 400, got nil")
	}
}

func TestUploadSbom_500ReturnsError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	setupViper()
	sbomPath := writeTempSbom(t, []byte(`{}`))

	_, err := uploadSbom(server.URL, "test-key", "my-project", "my-parent", "1.0.0", sbomPath, "", noRetryClient())
	if err == nil {
		t.Error("expected error for HTTP 500, got nil")
	}
}

func TestUploadSbom_SendsFormFields(t *testing.T) {
	var gotProjectName, gotParentName, gotVersion, gotAutoCreate, gotTags string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseMultipartForm(1 << 20); err != nil {
			t.Errorf("failed to parse multipart form: %v", err)
		}
		gotProjectName = r.FormValue("projectName")
		gotParentName = r.FormValue("parentName")
		gotVersion = r.FormValue("projectVersion")
		gotAutoCreate = r.FormValue("autoCreate")
		gotTags = r.FormValue("tags")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]string{"token": "abc-123"})
	}))
	defer server.Close()

	setupViper()
	sbomPath := writeTempSbom(t, []byte(`{"bomFormat":"CycloneDX"}`))

	_, err := uploadSbom(server.URL, "test-key", "my-project", "my-parent", "2.0.0", sbomPath, "tag1,tag2", noRetryClient())
	if err != nil {
		t.Fatalf("uploadSbom returned unexpected error: %v", err)
	}

	if gotProjectName != "my-project" {
		t.Errorf("projectName: got %q, want %q", gotProjectName, "my-project")
	}
	if gotParentName != "my-parent" {
		t.Errorf("parentName: got %q, want %q", gotParentName, "my-parent")
	}
	if gotVersion != "2.0.0" {
		t.Errorf("projectVersion: got %q, want %q", gotVersion, "2.0.0")
	}
	if gotAutoCreate != "true" {
		t.Errorf("autoCreate: got %q, want %q", gotAutoCreate, "true")
	}
	if gotTags != "tag1,tag2" {
		t.Errorf("tags: got %q, want %q", gotTags, "tag1,tag2")
	}
}

func TestUploadSbom_IsLatestFieldSentWhenTrue(t *testing.T) {
	var gotIsLatest string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseMultipartForm(1 << 20); err != nil {
			t.Errorf("failed to parse multipart form: %v", err)
		}
		gotIsLatest = r.FormValue("isLatest")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]string{"token": "abc-123"})
	}))
	defer server.Close()

	setupViper()
	v.Set("latest", true)
	sbomPath := writeTempSbom(t, []byte(`{"bomFormat":"CycloneDX"}`))

	_, err := uploadSbom(server.URL, "test-key", "my-project", "my-parent", "1.0.0", sbomPath, "", noRetryClient())
	if err != nil {
		t.Fatalf("uploadSbom returned unexpected error: %v", err)
	}
	if gotIsLatest != "true" {
		t.Errorf("isLatest: got %q, want %q", gotIsLatest, "true")
	}
}

func TestUploadSbom_IsLatestFieldAbsentWhenFalse(t *testing.T) {
	var gotIsLatest string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseMultipartForm(1 << 20); err != nil {
			t.Errorf("failed to parse multipart form: %v", err)
		}
		gotIsLatest = r.FormValue("isLatest")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]string{"token": "abc-123"})
	}))
	defer server.Close()

	setupViper()
	// v.GetBool("latest") defaults to false
	sbomPath := writeTempSbom(t, []byte(`{"bomFormat":"CycloneDX"}`))

	_, err := uploadSbom(server.URL, "test-key", "my-project", "my-parent", "1.0.0", sbomPath, "", noRetryClient())
	if err != nil {
		t.Fatalf("uploadSbom returned unexpected error: %v", err)
	}
	if gotIsLatest != "" {
		t.Errorf("isLatest: expected field absent, got %q", gotIsLatest)
	}
}

func TestUploadSbom_MissingFileReturnsError(t *testing.T) {
	setupViper()
	_, err := uploadSbom("http://localhost", "key", "proj", "parent", "1.0", "/nonexistent/path.json", "", noRetryClient())
	if err == nil {
		t.Error("expected error for missing file, got nil")
	}
}

// --- ensureParentExists ---

func TestEnsureParentExists_ParentFoundSkipsCreation(t *testing.T) {
	putCalled := false
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/project/lookup", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(Project{Name: "existing-parent"})
	})
	mux.HandleFunc("/api/v1/project", func(w http.ResponseWriter, r *http.Request) {
		putCalled = true
		w.WriteHeader(http.StatusCreated)
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	err := ensureParentExists(server.URL, "test-key", "existing-parent", "", noRetryClient())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if putCalled {
		t.Error("createParent was called even though parent already exists")
	}
}

func TestEnsureParentExists_ParentNotFoundCreatesIt(t *testing.T) {
	putCalled := false
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/project/lookup", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(Project{}) // empty Name signals not found
	})
	mux.HandleFunc("/api/v1/project", func(w http.ResponseWriter, r *http.Request) {
		putCalled = true
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(Project{Name: "new-parent"})
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	err := ensureParentExists(server.URL, "test-key", "new-parent", "", noRetryClient())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !putCalled {
		t.Error("createParent was not called for missing parent")
	}
}

func TestEnsureParentExists_LookupErrorReturnsError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(w, `{"status":401,"title":"Unauthorized"}`)
	}))
	defer server.Close()

	err := ensureParentExists(server.URL, "bad-key", "my-parent", "", noRetryClient())
	if err == nil {
		t.Error("expected error for HTTP 401, got nil")
	}
}

// --- createParent ---

func TestCreateParent_SendsCorrectPayload(t *testing.T) {
	var gotProject Project
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			t.Errorf("expected PUT, got %s", r.Method)
		}
		if err := json.NewDecoder(r.Body).Decode(&gotProject); err != nil {
			t.Errorf("failed to decode request body: %v", err)
		}
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(gotProject)
	}))
	defer server.Close()

	_, err := createParent(server.URL, "test-key", "my-parent", "team-a,team-b", noRetryClient())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if gotProject.Name != "my-parent" {
		t.Errorf("name: got %q, want %q", gotProject.Name, "my-parent")
	}
	if gotProject.Classifier != "APPLICATION" {
		t.Errorf("classifier: got %q, want %q", gotProject.Classifier, "APPLICATION")
	}
	if gotProject.CollectionLogic != "AGGREGATE_LATEST_VERSION_CHILDREN" {
		t.Errorf("collectionLogic: got %q, want %q", gotProject.CollectionLogic, "AGGREGATE_LATEST_VERSION_CHILDREN")
	}
	if len(gotProject.Tags) != 2 || gotProject.Tags[0].Name != "team-a" || gotProject.Tags[1].Name != "team-b" {
		t.Errorf("tags: got %v, want [{team-a} {team-b}]", gotProject.Tags)
	}
}

func TestCreateParent_NonCreatedStatusReturnsError(t *testing.T) {
	for _, status := range []int{http.StatusBadRequest, http.StatusConflict, http.StatusInternalServerError} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(status)
				_, _ = fmt.Fprintf(w, `{"status":%d,"title":"error"}`, status)
			}))
			defer server.Close()

			_, err := createParent(server.URL, "test-key", "my-parent", "", noRetryClient())
			if err == nil {
				t.Errorf("expected error for status %d, got nil", status)
			}
		})
	}
}

// --- pollImport ---

func TestPollImport_ReturnsWhenProcessingFalse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]bool{"processing": false})
	}))
	defer server.Close()

	err := pollImport(server.URL, "test-key", "test-token", noRetryClient(), 0)
	if err != nil {
		t.Errorf("expected nil error, got: %v", err)
	}
}

func TestPollImport_PollsUntilProcessingFalse(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Return processing=true for the first two calls, then false
		processing := calls.Add(1) <= 2
		_ = json.NewEncoder(w).Encode(map[string]bool{"processing": processing})
	}))
	defer server.Close()

	err := pollImport(server.URL, "test-key", "test-token", noRetryClient(), 0)
	if err != nil {
		t.Fatalf("expected nil error, got: %v", err)
	}
	if calls.Load() != 3 {
		t.Errorf("expected 3 poll calls, got %d", calls.Load())
	}
}

func TestPollImport_UsesCorrectTokenInURL(t *testing.T) {
	var gotPath string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		_ = json.NewEncoder(w).Encode(map[string]bool{"processing": false})
	}))
	defer server.Close()

	_ = pollImport(server.URL, "test-key", "abc-123", noRetryClient(), 0)

	if gotPath != "/api/v1/bom/token/abc-123" {
		t.Errorf("path: got %q, want %q", gotPath, "/api/v1/bom/token/abc-123")
	}
}

func TestPollImport_TimesOut(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]bool{"processing": true})
	}))
	defer server.Close()

	// Use a negative interval so the loop exits immediately on the deadline check,
	// and a tiny timeout via a custom call won't work — instead we rely on the
	// server always returning processing=true and a zero interval so it spins fast.
	// The real timeout is 5 minutes, so we test the error path by closing the server
	// to force a request failure instead.
	server.Close()

	err := pollImport(server.URL, "test-key", "test-token", noRetryClient(), 0)
	if err == nil {
		t.Error("expected error when server is unreachable, got nil")
	}
}

func TestUploadSbom_ReturnsToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]string{"token": "my-token-xyz"})
	}))
	defer server.Close()

	setupViper()
	sbomPath := writeTempSbom(t, []byte(`{"bomFormat":"CycloneDX"}`))

	token, err := uploadSbom(server.URL, "test-key", "my-project", "my-parent", "1.0.0", sbomPath, "", noRetryClient())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if token != "my-token-xyz" {
		t.Errorf("token: got %q, want %q", token, "my-token-xyz")
	}
}

func TestPollImport_SetsApiKeyHeader(t *testing.T) {
	var gotKey string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotKey = r.Header.Get("X-Api-Key")
		_ = json.NewEncoder(w).Encode(map[string]bool{"processing": false})
	}))
	defer server.Close()

	_ = pollImport(server.URL, "my-api-key", "test-token", noRetryClient(), 0)

	if gotKey != "my-api-key" {
		t.Errorf("X-Api-Key: got %q, want %q", gotKey, "my-api-key")
	}
}

func TestPollImport_NonOKStatusReturnsError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(w, `{"status":401,"title":"Unauthorized"}`)
	}))
	defer server.Close()

	err := pollImport(server.URL, "bad-key", "test-token", noRetryClient(), 0)
	if err == nil {
		t.Error("expected error for HTTP 401, got nil")
	}
}

// Ensure time import is used (interval parameter in tests)
var _ = time.Second
