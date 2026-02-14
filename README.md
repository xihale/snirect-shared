# Snirect Shared Library

Common Go code shared between the desktop and Android implementations of Snirect.

## Packages

### pattern
Pattern matching library for domain/host patterns with support for:
- Wildcards: `*.example.com`, `example*`, `*example.com`
- Exclusion operator: `pattern^exclude` (e.g., `*.yahoo.com^*.media.yahoo.com`)
- Ignore prefixes: `#`, `$`, `^` at the start

### cert
Certificate Authority management for HTTPS proxy:
- Root CA generation and loading
- Leaf certificate signing
- Certificate caching with automatic cleanup

## Usage

### Pattern Matching
```go
import "github.com/xihale/snirect/shared/pattern"

matched := pattern.MatchPattern("*.yahoo.com^*.media.yahoo.com", "www.yahoo.com")
// matched == true

matched := pattern.MatchPattern("*.yahoo.com^*.media.yahoo.com", "media.yahoo.com")
// matched == false (excluded)
```

### Certificate Management
```go
import "github.com/xihale/snirect/shared/cert"

cm, err := cert.NewCertManager(caCertPath, caKeyPath)
if err != nil {
    log.Fatal(err)
}
defer cm.Close()

// Sign a leaf certificate for a host
certBytes, privKey, err := cm.SignLeafCert([]string{"example.com"})
```

## Development

Run tests:
```bash
go test ./...
```

## License

MIT
