# CodeQL Queries for Bad File Server

This directory contains custom CodeQL queries designed to detect the security vulnerabilities present in the bad-file-server project.

## Queries

### 1. PathTraversal.ql
- **CWE**: CWE-022 (Path Traversal)
- **Severity**: Error
- **Description**: Detects when user input flows directly to file operations like `os.Open()` without sanitization
- **Target**: `viewFileHandler` function

### 2. CommandInjection.ql
- **CWE**: CWE-078 (OS Command Injection)
- **Severity**: Error
- **Description**: Detects when user input flows to `exec.Command()` without proper sanitization
- **Target**: `metadataHandler` function

### 3. HardcodedCredentials.ql
- **CWE**: CWE-798 (Hard-coded Credentials)
- **Severity**: Error
- **Description**: Finds hard-coded passwords, secrets, API keys, and tokens in source code
- **Targets**: `AdminKey` constant, `apiPassword` variable, `dbToken` variable

### 4. hardcoded-credentials-dataflow.ql
- **CWE**: CWE-798 (Hard-coded Credentials - Data Flow)
- **Severity**: Warning
- **Description**: Tracks hard-coded secrets from their definition to sensitive sinks like HTTP POST requests
- **Target**: `authenticateHandler` function where hardcoded secrets flow to `http.Post()`

### 5. WeakCryptography.ql
- **CWE**: CWE-327 (Weak Cryptographic Algorithm)
- **Severity**: Warning
- **Description**: Detects use of MD5 or SHA1 cryptographic algorithms
- **Target**: `sessionHandler` function

### 6. ResourceLeak.ql
- **CWE**: CWE-404 (Improper Resource Shutdown)
- **Severity**: Warning
- **Description**: Finds file operations without proper `defer close()` calls
- **Target**: `uploadHandler` function

## Prerequisites

1. Install CodeQL CLI:
```bash
# macOS
brew install codeql

# Or download from: https://github.com/github/codeql-cli-binaries/releases
```

2. Download CodeQL standard libraries for Go:
```bash
git clone https://github.com/github/codeql-go.git
```

## Usage

### Step 1: Create CodeQL Database

First, create a CodeQL database from the source code:

```bash
# From the project root directory
codeql database create codeql-db --language=go
```

### Step 2: Run Individual Queries

Run a specific query against the database:

```bash
# Path Traversal
codeql query run codeql-queries/PathTraversal.ql --database=codeql-db

# Command Injection
codeql query run codeql-queries/CommandInjection.ql --database=codeql-db

# Hard-coded Credentials
codeql query run codeql-queries/HardcodedCredentials.ql --database=codeql-db

# Hard-coded Credentials Data Flow
codeql query run codeql-queries/hardcoded-credentials-dataflow.ql --database=codeql-db

# Weak Cryptography
codeql query run codeql-queries/WeakCryptography.ql --database=codeql-db

# Resource Leak
codeql query run codeql-queries/ResourceLeak.ql --database=codeql-db
```

### Step 3: Run All Queries

Create a query suite file to run all queries at once:

```bash
# Create a query suite file
cat > codeql-queries/security-suite.qls << 'EOF'
- queries: .
  from: codeql-queries
EOF

# Run the suite
codeql database analyze codeql-db codeql-queries/security-suite.qls --format=sarif-latest --output=results.sarif
```

### Step 4: View Results

View results in different formats:

```bash
# CSV format
codeql database analyze codeql-db codeql-queries/ --format=csv --output=results.csv

# SARIF format (for GitHub integration)
codeql database analyze codeql-db codeql-queries/ --format=sarif-latest --output=results.sarif

# Human-readable text
codeql database analyze codeql-db codeql-queries/ --format=text
```

## Expected Results

When running these queries against the bad-file-server code, you should see:

1. **PathTraversal.ql**: 1 result in `viewFileHandler`
2. **CommandInjection.ql**: 1 result in `metadataHandler`
3. **HardcodedCredentials.ql**: 3 results (`AdminKey`, `apiPassword`, `dbToken`)
4. **hardcoded-credentials-dataflow.ql**: 1+ results showing data flow from hardcoded secrets to `http.Post()` in `authenticateHandler`
5. **WeakCryptography.ql**: 1 result in `sessionHandler` (MD5 usage)
6. **ResourceLeak.ql**: 1 result in `uploadHandler` (missing defer close)

## Integration with GitHub

To use these queries in GitHub Code Scanning:

1. Create `.github/workflows/codeql.yml`:
```yaml
name: "CodeQL"

on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]

jobs:
  analyze:
    name: Analyze
    runs-on: ubuntu-latest
    
    steps:
    - name: Checkout repository
      uses: actions/checkout@v3
    
    - name: Initialize CodeQL
      uses: github/codeql-action/init@v2
      with:
        languages: go
        queries: ./codeql-queries
    
    - name: Autobuild
      uses: github/codeql-action/autobuild@v2
    
    - name: Perform CodeQL Analysis
      uses: github/codeql-action/analyze@v2
```

## Learning Resources

- [CodeQL Documentation](https://codeql.github.com/docs/)
- [CodeQL for Go](https://codeql.github.com/docs/codeql-language-guides/codeql-for-go/)
- [Writing CodeQL Queries](https://codeql.github.com/docs/writing-codeql-queries/)
- [CodeQL Query Help](https://codeql.github.com/codeql-query-help/)

## Notes

- These queries are simplified for educational purposes
- Production queries should include more sophisticated data flow analysis
- Consider using CodeQL's standard security queries in addition to these custom ones
- The queries may need adjustment based on your CodeQL version and Go library version
