## VulnSpectra

VulnSpectra is an advanced static security analysis tool that performs taint analysis on PHP, JavaScript, Java, Python, and Go source code to detect common security vulnerabilities.

## Features

- **Taint Analysis Engine**: Tracks data flow from user input sources to vulnerable sinks
- **Confidence Scoring**: Assigns confidence levels (Low, Medium, High, Critical) to findings
- **Severity Classification**: Categorizes issues as Info, Warning, or Critical
- **Sanitizer Detection**: Recognizes proper sanitization functions that remove taint
- **Multi-Language Support**: Scans PHP, JS, Java, Python, and Go files

## Detected Vulnerability Types

| Type | Description | Severity |
|------|-------------|----------|
| **LFI** | Local File Inclusion - User input used in file inclusion functions | Critical |
| **RCE** | Remote Code Execution - User input passed to command execution functions | Critical |
| **SQLI** | SQL Injection - User input concatenated into SQL queries | Critical |
| **XSS** | Cross-Site Scripting - User input output without encoding | Warning |
| **SSRF** | Server-Side Request Forgery - User input used in outbound requests | Critical |
| **PathTraversal** | Path Traversal - User input used in file paths without sanitization | Warning |
| **XXE** | XML External Entity - User input in XML parsing without entity restriction | Critical |

## Installation

**Using Go:**
```
go install github.com/rix4uni/VulnSpectra@latest
```

**Pre-built Binaries:**
```
wget https://github.com/rix4uni/VulnSpectra/releases/download/v0.0.1/VulnSpectra-linux-amd64-0.0.1.tgz
tar -xvzf VulnSpectra-linux-amd64-0.0.1.tgz
mv VulnSpectra ~/go/bin/
```

**From Source:**
```
git clone --depth 1 https://github.com/rix4uni/VulnSpectra.git
cd VulnSpectra; go install
```

## Usage

```console
Usage of VulnSpectra:
  -c, --confidence string         Minimum confidence level (Low, Medium, High, Critical) (default "Medium")
  -e, --ext string                Comma-separated file extensions to scan (default "php,js,java,py,go")
  -f, --filesystem string         Directory to scan (default ".")
  -i, --ignore-vulncheck string   Ignore specific vulnerability types (e.g., XSS, SQLI, LFI, RCE)
  -o, --output string             Output report file (optional)
      --silent                    Silent mode.
      --version                   Print the version of the tool and exit.
  -v, --vulncheck string          Filter by specific vulnerability types (e.g., XSS, SQLI, LFI, RCE)
```

## Examples

```console
# Basic scan of current directory
VulnSpectra

# Scan specific directory with all file types
VulnSpectra -f /path/to/code -e php,js,java

# High confidence findings only
VulnSpectra -c High

# Focus on specific vulnerability types
VulnSpectra -v XSS,SQLI

# Ignore certain vulnerability types
VulnSpectra -i LFI

# Save report to file
VulnSpectra -o security_report.txt
```
