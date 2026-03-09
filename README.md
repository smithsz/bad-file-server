# Bad File Server

foo

⚠️ **WARNING: This is an intentionally vulnerable application for educational purposes only. DO NOT use in production or expose to the internet!**

## Overview

This is a deliberately insecure file server written in Go that demonstrates various common security vulnerabilities (CWEs). It is designed for security training, testing security tools, and understanding common web application vulnerabilities.

## Demonstrated Vulnerabilities

This application contains the following security issues:

### CWE-22: Path Traversal
- **Endpoint**: `/view?file=<path>`
- **Issue**: No path sanitization allows reading arbitrary files using `../` sequences
- **Example**: `/view?file=../../../etc/passwd`

### CWE-78: OS Command Injection
- **Endpoint**: `/metadata?file=<filename>`
- **Issue**: User input is directly passed to shell commands without sanitization
- **Example**: `/metadata?file=test.txt;cat /etc/passwd`

### CWE-327: Weak Cryptographic Algorithm
- **Endpoint**: `/session?user=<username>`
- **Issue**: Uses MD5 for generating security tokens
- **Impact**: Tokens are predictable and can be easily cracked

### CWE-404: Improper Resource Shutdown
- **Endpoint**: `/upload` (POST)
- **Issue**: File handles are not properly closed, leading to resource leaks
- **Impact**: Can exhaust file descriptors under load

### CWE-798: Hard-coded Credentials
- **Endpoint**: `/admin` (requires `X-API-Key` header)
- **Issue**: Admin API key is hardcoded in source code
- **Credential**: `super-secret-123`

### CWE-193: Off-by-one Error
- **Endpoint**: `/process?data=<input>`
- **Issue**: Loop condition uses `<=` instead of `<`, causing out-of-bounds access

### CWE-476: NULL Pointer Dereference
- **Endpoint**: `/process?data=<input>`
- **Issue**: Dereferencing pointer before nil check
- **Impact**: Causes application panic

### Memory Leak
- **Endpoint**: `/process?data=<input>`
- **Issue**: Allocates large buffers without cleanup
- **Impact**: Unbounded memory growth

## Installation

```bash
# Clone the repository
git clone <repository-url>
cd bad-file-server

# Build the application
go build -o vulnerable-file-server

# Run the server
./vulnerable-file-server
```

## Usage

The server runs on port 8080 by default.

### View File (Path Traversal)
```bash
curl "http://localhost:8080/view?file=main.go"
curl "http://localhost:8080/view?file=../../../etc/passwd"  # Vulnerable!
```

### Get File Metadata (Command Injection)
```bash
curl "http://localhost:8080/metadata?file=main.go"
curl "http://localhost:8080/metadata?file=test.txt;whoami"  # Vulnerable!
```

### Upload File (Resource Leak)
```bash
curl -X POST -F "file=@test.txt" http://localhost:8080/upload
```

### Create Session (Weak Crypto)
```bash
curl "http://localhost:8080/session?user=admin"
```

### Admin Access (Hard-coded Credentials)
```bash
curl -H "X-API-Key: super-secret-123" http://localhost:8080/admin
```

### Process Data (Multiple Issues)
```bash
curl "http://localhost:8080/process?data=test"  # Will panic!
```

## Testing

Run the test suite:

```bash
go test -v
```

## Educational Use

This application is intended for:
- Security training and workshops
- Testing security scanning tools (SAST/DAST)
- Demonstrating secure coding practices by contrast
- Penetration testing practice in controlled environments

## Security Recommendations

To fix these vulnerabilities in a real application:

1. **Path Traversal**: Use `filepath.Clean()` and validate paths are within allowed directories
2. **Command Injection**: Avoid shell commands; use Go's native file operations or sanitize inputs
3. **Weak Crypto**: Use cryptographically secure random generators and modern algorithms
4. **Resource Leaks**: Always use `defer` to close resources
5. **Hard-coded Credentials**: Use environment variables or secure secret management
6. **Off-by-one Errors**: Carefully review loop conditions and array bounds
7. **Nil Checks**: Always check pointers before dereferencing
8. **Memory Management**: Implement proper cleanup and resource limits

## License

This project is provided as-is for educational purposes.

## Disclaimer

This software is intentionally vulnerable and should never be deployed in production environments or exposed to untrusted networks. The authors are not responsible for any misuse of this code.
