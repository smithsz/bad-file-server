package main

import (
	"bytes"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestViewFileHandler(t *testing.T) {
	// Create a temporary test file
	tmpFile, err := os.CreateTemp("", "test-*.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())

	testContent := "test file content"
	if _, err := tmpFile.WriteString(testContent); err != nil {
		t.Fatal(err)
	}
	tmpFile.Close()

	req := httptest.NewRequest("GET", "/view?file="+tmpFile.Name(), nil)
	w := httptest.NewRecorder()

	viewFileHandler(w, req)

	resp := w.Result()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	if string(body) != testContent {
		t.Errorf("Expected %q, got %q", testContent, string(body))
	}
}

func TestViewFileHandler_PathTraversal(t *testing.T) {
	// Test that path traversal works (demonstrating the vulnerability)
	req := httptest.NewRequest("GET", "/view?file=../../../etc/hosts", nil)
	w := httptest.NewRecorder()

	viewFileHandler(w, req)

	resp := w.Result()
	// On most systems, this will either succeed or fail based on permissions
	// The test just verifies the handler doesn't crash
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNotFound {
		t.Logf("Path traversal attempt returned status: %d", resp.StatusCode)
	}
}

func TestMetadataHandler(t *testing.T) {
	// Create a temporary test file
	tmpFile, err := os.CreateTemp("", "test-*.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())
	tmpFile.Close()

	req := httptest.NewRequest("GET", "/metadata?file="+tmpFile.Name(), nil)
	w := httptest.NewRecorder()

	metadataHandler(w, req)

	resp := w.Result()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	// Should contain file information from ls -l
	if !strings.Contains(string(body), filepath.Base(tmpFile.Name())) {
		t.Errorf("Expected output to contain filename, got: %s", string(body))
	}
}

func TestMetadataHandler_CommandInjection(t *testing.T) {
	// Test command injection vulnerability (demonstrating it exists)
	req := httptest.NewRequest("GET", "/metadata?file=test.txt;echo%20injected", nil)
	w := httptest.NewRecorder()

	metadataHandler(w, req)

	resp := w.Result()
	// The handler will execute the command, demonstrating the vulnerability
	if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusInternalServerError {
		t.Logf("Command injection attempt completed with status: %d", resp.StatusCode)
	}
}

func TestUploadHandler(t *testing.T) {
	// Create a multipart form with a file
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	part, err := writer.CreateFormFile("file", "test-upload.txt")
	if err != nil {
		t.Fatal(err)
	}

	testContent := "uploaded file content"
	part.Write([]byte(testContent))
	writer.Close()

	req := httptest.NewRequest("POST", "/upload", body)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	w := httptest.NewRecorder()

	uploadHandler(w, req)

	resp := w.Result()
	respBody, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	if !strings.Contains(string(respBody), "uploaded successfully") {
		t.Errorf("Expected success message, got: %s", string(respBody))
	}

	// Clean up uploaded file
	uploadPath := filepath.Join("/tmp", "test-upload.txt")
	os.Remove(uploadPath)
}

func TestSessionHandler(t *testing.T) {
	req := httptest.NewRequest("GET", "/session?user=testuser", nil)
	w := httptest.NewRecorder()

	sessionHandler(w, req)

	resp := w.Result()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	// Should return a session token (MD5 hash)
	if !strings.Contains(string(body), "Session token:") {
		t.Errorf("Expected session token in response, got: %s", string(body))
	}

	// Verify token was stored
	if _, exists := sessionTokens["testuser"]; !exists {
		t.Error("Expected session token to be stored")
	}
}

func TestAdminHandler_Authorized(t *testing.T) {
	req := httptest.NewRequest("GET", "/admin", nil)
	req.Header.Set("X-API-Key", AdminKey)
	w := httptest.NewRecorder()

	adminHandler(w, req)

	resp := w.Result()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	if !strings.Contains(string(body), "Admin access granted") {
		t.Errorf("Expected admin access message, got: %s", string(body))
	}
}

func TestAdminHandler_Unauthorized(t *testing.T) {
	req := httptest.NewRequest("GET", "/admin", nil)
	req.Header.Set("X-API-Key", "wrong-key")
	w := httptest.NewRecorder()

	adminHandler(w, req)

	resp := w.Result()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("Expected status 401, got %d", resp.StatusCode)
	}
}

func TestProcessDataHandler_Panics(t *testing.T) {
	// This test demonstrates the nil pointer dereference vulnerability
	// We expect it to panic
	defer func() {
		if r := recover(); r == nil {
			t.Error("Expected panic from nil pointer dereference, but didn't get one")
		}
	}()

	req := httptest.NewRequest("GET", "/process?data=test", nil)
	w := httptest.NewRecorder()

	processDataHandler(w, req)
}

func TestViewFileHandler_MissingParameter(t *testing.T) {
	req := httptest.NewRequest("GET", "/view", nil)
	w := httptest.NewRecorder()

	viewFileHandler(w, req)

	resp := w.Result()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", resp.StatusCode)
	}
}

func TestMetadataHandler_MissingParameter(t *testing.T) {
	req := httptest.NewRequest("GET", "/metadata", nil)
	w := httptest.NewRecorder()

	metadataHandler(w, req)

	resp := w.Result()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", resp.StatusCode)
	}
}
