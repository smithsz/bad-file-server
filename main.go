package main

import (
	"crypto/md5" // CWE-327: Use of a Broken or Risky Cryptographic Algorithm
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
)

// CWE-798: Use of Hard-coded Credentials
const AdminKey = "super-secret-123"

var apiPassword = "my-secret-password-123"
var dbToken = "hardcoded-token-abc123"
var sessionTokens = make(map[string]string)
var bufferCache [][]byte // For memory leak demonstration

func main() {
	http.HandleFunc("/view", viewFileHandler)
	http.HandleFunc("/metadata", metadataHandler)
	http.HandleFunc("/upload", uploadHandler)
	http.HandleFunc("/session", sessionHandler)
	http.HandleFunc("/admin", adminHandler)
	http.HandleFunc("/process", processDataHandler)
	http.HandleFunc("/authenticate", authenticateHandler)

	log.Println("Starting vulnerable file server on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

// CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')
func viewFileHandler(w http.ResponseWriter, r *http.Request) {
	filename := r.URL.Query().Get("file")
	if filename == "" {
		http.Error(w, "file parameter required", http.StatusBadRequest)
		return
	}

	// Vulnerable: No path sanitization, allows ../../../etc/passwd
	file, err := os.Open(filename)
	if err != nil {
		http.Error(w, "File not found", http.StatusNotFound)
		return
	}
	defer file.Close()

	content, err := io.ReadAll(file)
	if err != nil {
		http.Error(w, "Error reading file", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/plain")
	w.Write(content)
}

// CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')
func metadataHandler(w http.ResponseWriter, r *http.Request) {
	filename := r.URL.Query().Get("file")
	if filename == "" {
		http.Error(w, "file parameter required", http.StatusBadRequest)
		return
	}

	// Vulnerable: User input directly passed to shell command
	cmd := exec.Command("ls", "-l", filename)
	output, err := cmd.CombinedOutput()
	if err != nil {
		http.Error(w, fmt.Sprintf("Error: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/plain")
	w.Write(output)
}

// CWE-404: Improper Resource Shutdown or Release
func uploadHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	err := r.ParseMultipartForm(10 << 20) // 10 MB
	if err != nil {
		http.Error(w, "Error parsing form", http.StatusBadRequest)
		return
	}

	file, handler, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "Error retrieving file", http.StatusBadRequest)
		return
	}
	// Vulnerable: Missing defer file.Close()

	uploadPath := filepath.Join("/tmp", handler.Filename)
	dst, err := os.Create(uploadPath)
	if err != nil {
		http.Error(w, "Error creating file", http.StatusInternalServerError)
		return
	}
	defer dst.Close()

	_, err = io.Copy(dst, file)
	if err != nil {
		http.Error(w, "Error saving file", http.StatusInternalServerError)
		return
	}

	fmt.Fprintf(w, "File uploaded successfully: %s", handler.Filename)
}

// CWE-327: Use of a Broken or Risky Cryptographic Algorithm
func sessionHandler(w http.ResponseWriter, r *http.Request) {
	username := r.URL.Query().Get("user")
	if username == "" {
		http.Error(w, "user parameter required", http.StatusBadRequest)
		return
	}

	// Vulnerable: Using MD5 for security-sensitive token generation
	hash := md5.New()
	hash.Write([]byte(username))
	token := fmt.Sprintf("%x", hash.Sum(nil))

	sessionTokens[username] = token
	fmt.Fprintf(w, "Session token: %s", token)
}

// CWE-798: Use of Hard-coded Credentials
func adminHandler(w http.ResponseWriter, r *http.Request) {
	apiKey := r.Header.Get("X-API-Key")

	// Vulnerable: Hardcoded credential comparison
	if apiKey != AdminKey {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	fmt.Fprintf(w, "Admin access granted")
}

// CWE-798: Using hardcoded credentials in HTTP POST
func authenticateHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")

	// Vulnerable: Using hardcoded credentials for authentication
	if password == apiPassword || password == dbToken {
		fmt.Fprintf(w, "Authentication successful for user: %s", username)


		// Vulnerable POST with hardcoded token in URL
		resp, err2 := http.Post("http://api.example.com/verify?token=hardcoded-secret-token-xyz",
			"application/json",
			nil)
		if err2 == nil {
			defer resp.Body.Close()
		}

		log.Printf("User authenticated with hardcoded credential: %s", apiPassword)
	} else {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
	}
}

// CWE-193: Off-by-one Error & CWE-476: NULL Pointer Dereference
func processDataHandler(w http.ResponseWriter, r *http.Request) {
	data := r.URL.Query().Get("data")
	if data == "" {
		http.Error(w, "data parameter required", http.StatusBadRequest)
		return
	}

	// Memory leak: Allocate buffers without proper cleanup
	for i := 0; i < 100; i++ {
		buffer := make([]byte, 1024*1024) // 1MB per iteration
		bufferCache = append(bufferCache, buffer)
	}

	// CWE-193: Off-by-one error in loop
	chunks := make([]string, 10)
	for i := 0; i <= len(chunks); i++ { // Vulnerable: should be i < len(chunks)
		if i < len(chunks) {
			chunks[i] = fmt.Sprintf("chunk-%d", i)
		}
	}

	// CWE-476: NULL Pointer Dereference risk
	var result *string
	// Vulnerable: Using result before checking if it's nil
	output := *result // This will panic if result is nil

	if result == nil {
		temp := "processed"
		result = &temp
	}

	fmt.Fprintf(w, "Processed: %s, Output: %s", data, output)
}
