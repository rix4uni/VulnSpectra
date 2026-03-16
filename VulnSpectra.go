package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/spf13/pflag"

	"github.com/rix4uni/VulnSpectra/banner"
)

// Confidence levels for findings
type Confidence int

const (
	Low Confidence = iota
	Medium
	High
	Critical
)

func (c Confidence) String() string {
	return [...]string{"Low", "Medium", "High", "Critical"}[c]
}

// Severity levels
type Severity int

const (
	Info Severity = iota
	Warning
	CriticalSev
)

func (s Severity) String() string {
	return [...]string{"Info", "Warning", "Critical"}[s]
}

// Finding represents a detected vulnerability
type Finding struct {
	FilePath     string
	LineNumber   int
	BugType      string
	Confidence   Confidence
	Severity     Severity
	CodeSnippet  string
	Explanation  string
	Remediation  string
}

// VulnerabilityRule defines a vulnerability pattern with context awareness
type VulnerabilityRule struct {
	Name                string
	Description         string
	SourcePatterns      []*regexp.Regexp
	SinkPatterns        []*regexp.Regexp
	SanitizerPatterns   []*regexp.Regexp
	SafeContextPatterns []*regexp.Regexp
	Severity            Severity
}

// TaintAnalyzer performs data flow analysis
type TaintAnalyzer struct {
	rules        []VulnerabilityRule
	findings     []Finding
	scannedFiles int
}

func NewTaintAnalyzer() *TaintAnalyzer {
	return &TaintAnalyzer{
		rules: []VulnerabilityRule{
			// LFI - Local File Inclusion
			{
				Name:        "LFI",
				Description: "Local File Inclusion - User input used in file inclusion functions",
				SourcePatterns: []*regexp.Regexp{
					regexp.MustCompile(`(?i)\$_GET\s*\[`),
					regexp.MustCompile(`(?i)\$_POST\s*\[`),
					regexp.MustCompile(`(?i)\$_REQUEST\s*\[`),
					regexp.MustCompile(`(?i)\$_COOKIE\s*\[`),
					regexp.MustCompile(`(?i)\$_FILES\s*\[`),
					regexp.MustCompile(`(?i)file\s*\(\s*['"]php://input['"]\s*\)`),
				},
				SinkPatterns: []*regexp.Regexp{
					regexp.MustCompile(`(?i)include\s*\([^)]+\$`),
					regexp.MustCompile(`(?i)include_once\s*\([^)]+\$`),
					regexp.MustCompile(`(?i)require\s*\([^)]+\$`),
					regexp.MustCompile(`(?i)require_once\s*\([^)]+\$`),
					regexp.MustCompile(`(?i)file_get_contents\s*\([^)]+\$`),
					regexp.MustCompile(`(?i)fopen\s*\([^)]+\$`),
					regexp.MustCompile(`(?i)readfile\s*\([^)]+\$`),
					regexp.MustCompile(`(?i)highlight_file\s*\([^)]+\$`),
					regexp.MustCompile(`(?i)show_source\s*\([^)]+\$`),
				},
				SanitizerPatterns: []*regexp.Regexp{
					regexp.MustCompile(`(?i)basename\s*\(`),
					regexp.MustCompile(`(?i)realpath\s*\(`),
					regexp.MustCompile(`(?i)pathinfo\s*\(`),
					regexp.MustCompile(`str_replace\s*\(\s*['"]\.\.['"]`),
					regexp.MustCompile(`preg_replace\s*\([^)]*\.\.`),
				},
				SafeContextPatterns: []*regexp.Regexp{
					regexp.MustCompile(`['"][a-zA-Z0-9_]+\.php['"]`),
				},
				Severity: CriticalSev,
			},
			// RCE - Remote Code Execution
			{
				Name:        "RCE",
				Description: "Remote Code Execution - User input passed to command execution functions",
				SourcePatterns: []*regexp.Regexp{
					regexp.MustCompile(`(?i)\$_GET\s*\[`),
					regexp.MustCompile(`(?i)\$_POST\s*\[`),
					regexp.MustCompile(`(?i)\$_REQUEST\s*\[`),
					regexp.MustCompile(`(?i)\$_COOKIE\s*\[`),
					regexp.MustCompile(`(?i)\$_SERVER\s*\[`),
				},
				SinkPatterns: []*regexp.Regexp{
					regexp.MustCompile(`(?i)eval\s*\([^)]+\$`),
					regexp.MustCompile(`(?i)assert\s*\([^)]+\$`),
					regexp.MustCompile(`(?i)preg_replace\s*\([^)]*\/e`),
					regexp.MustCompile(`(?i)create_function\s*\(`),
					regexp.MustCompile(`(?i)shell_exec\s*\([^)]+\$`),
					regexp.MustCompile(`(?i)exec\s*\([^)]+\$`),
					regexp.MustCompile(`(?i)system\s*\([^)]+\$`),
					regexp.MustCompile(`(?i)passthru\s*\([^)]+\$`),
					regexp.MustCompile(`(?i)popen\s*\([^)]+\$`),
					regexp.MustCompile(`(?i)proc_open\s*\([^)]+\$`),
					regexp.MustCompile(`(?i)unserialize\s*\([^)]+\$`),
					regexp.MustCompile(`(?i)mail\s*\([^)]*\$`),
					regexp.MustCompile(`(?i)mb_send_mail\s*\([^)]*\$`),
				},
				SanitizerPatterns: []*regexp.Regexp{
					regexp.MustCompile(`(?i)escapeshellarg\s*\(`),
					regexp.MustCompile(`(?i)escapeshellcmd\s*\(`),
					regexp.MustCompile(`(?i)intval\s*\(`),
					regexp.MustCompile(`(?i)floatval\s*\(`),
					regexp.MustCompile(`(?i)filter_input\s*\([^)]*FILTER_VALIDATE_INT`),
				},
				SafeContextPatterns: []*regexp.Regexp{},
				Severity:            CriticalSev,
			},
			// SQL Injection
			{
				Name:        "SQLI",
				Description: "SQL Injection - User input concatenated into SQL queries",
				SourcePatterns: []*regexp.Regexp{
					regexp.MustCompile(`(?i)\$_GET\s*\[`),
					regexp.MustCompile(`(?i)\$_POST\s*\[`),
					regexp.MustCompile(`(?i)\$_REQUEST\s*\[`),
					regexp.MustCompile(`(?i)\$_COOKIE\s*\[`),
					regexp.MustCompile(`(?i)\$_SERVER\s*\[`),
				},
				SinkPatterns: []*regexp.Regexp{
					regexp.MustCompile(`(?i)mysql_query\s*\([^)]+\$`),
					regexp.MustCompile(`(?i)mysqli_query\s*\([^)]+\$`),
					regexp.MustCompile(`(?i)mysqli_real_query\s*\([^)]+\$`),
					regexp.MustCompile(`(?i)mysqli_multi_query\s*\([^)]+\$`),
					regexp.MustCompile(`(?i)mysqli_prepare.*\$`),
					regexp.MustCompile(`(?i)PDO->query\s*\([^)]+\$`),
					regexp.MustCompile(`(?i)PDO->exec\s*\([^)]+\$`),
					regexp.MustCompile(`(?i)PDO->prepare\s*\([^)]*\$`),
					regexp.MustCompile(`(?i)sqlite_query\s*\([^)]+\$`),
					regexp.MustCompile(`(?i)pg_query\s*\([^)]+\$`),
					regexp.MustCompile(`(?i)pg_send_query\s*\([^)]+\$`),
					regexp.MustCompile(`(?i)oci_parse\s*\([^)]+\$`),
					regexp.MustCompile(`(?i)sqlsrv_query\s*\([^)]+\$`),
				},
				SanitizerPatterns: []*regexp.Regexp{
					regexp.MustCompile(`(?i)mysql_real_escape_string\s*\(`),
					regexp.MustCompile(`(?i)mysqli_real_escape_string\s*\(`),
					regexp.MustCompile(`(?i)addslashes\s*\(`),
					regexp.MustCompile(`(?i)intval\s*\(`),
					regexp.MustCompile(`(?i)prepare\s*\([^)]*\?`),
					regexp.MustCompile(`(?i):[a-zA-Z_]+\s*=>`),
				},
				SafeContextPatterns: []*regexp.Regexp{},
				Severity:            CriticalSev,
			},
			// XSS - Cross Site Scripting
			{
				Name:        "XSS",
				Description: "Cross-Site Scripting - User input output without encoding",
				SourcePatterns: []*regexp.Regexp{
					regexp.MustCompile(`(?i)\$_GET\s*\[`),
					regexp.MustCompile(`(?i)\$_POST\s*\[`),
					regexp.MustCompile(`(?i)\$_REQUEST\s*\[`),
					regexp.MustCompile(`(?i)\$_COOKIE\s*\[`),
					regexp.MustCompile(`(?i)\$_SERVER\s*\[`),
					regexp.MustCompile(`(?i)\$_(FILES|ENV|SESSION)\s*\[`),
				},
				SinkPatterns: []*regexp.Regexp{
					regexp.MustCompile(`(?i)echo\s+[^;]*\$`),
					regexp.MustCompile(`(?i)print\s+[^;]*\$`),
					regexp.MustCompile(`(?i)printf\s*\([^)]+\$`),
					regexp.MustCompile(`(?i)sprintf\s*\([^)]+\$`),
					regexp.MustCompile(`(?i)print_r\s*\([^)]+\$`),
					regexp.MustCompile(`(?i)var_dump\s*\([^)]+\$`),
					regexp.MustCompile(`(?i)die\s*\([^)]+\$`),
					regexp.MustCompile(`(?i)exit\s*\([^)]+\$`),
					regexp.MustCompile(`(?i)\.innerHTML\s*=`),
					regexp.MustCompile(`(?i)document\.write\s*\(`),
					regexp.MustCompile(`(?i)\.html\s*\(`),
				},
				SanitizerPatterns: []*regexp.Regexp{
					regexp.MustCompile(`(?i)htmlspecialchars\s*\(`),
					regexp.MustCompile(`(?i)htmlentities\s*\(`),
					regexp.MustCompile(`(?i)strip_tags\s*\(`),
					regexp.MustCompile(`(?i)filter_input\s*\([^)]*FILTER_SANITIZE`),
					regexp.MustCompile(`(?i)intval\s*\(`),
					regexp.MustCompile(`(?i)json_encode\s*\(`),
					regexp.MustCompile(`(?i)encodeURIComponent\s*\(`),
					regexp.MustCompile(`(?i)urlencode\s*\(`),
					// WordPress/Laravel/CMS escapes (from Semgrep)
					regexp.MustCompile(`(?i)esc_html\s*\(`),
					regexp.MustCompile(`(?i)esc_attr\s*\(`),
					regexp.MustCompile(`(?i)wp_kses\s*\(`),
					regexp.MustCompile(`(?i)e\s*\(`),
					regexp.MustCompile(`(?i)twig_escape_filter\s*\(`),
					regexp.MustCompile(`(?i)xss_clean\s*\(`),
					regexp.MustCompile(`(?i)html_escape\s*\(`),
					regexp.MustCompile(`(?i)Html::escape\s*\(`),
					regexp.MustCompile(`(?i)Xss::filter\s*\(`),
					regexp.MustCompile(`(?i)escapeHtml\s*\(`),
					regexp.MustCompile(`(?i)escapeHtmlAttr\s*\(`),
				},
				SafeContextPatterns: []*regexp.Regexp{
					regexp.MustCompile(`JSON\.stringify\s*\([^)]+\$`),
				},
				Severity: Warning,
			},
			// SSRF - Server Side Request Forgery
			{
				Name:        "SSRF",
				Description: "Server-Side Request Forgery - User input used in outbound requests",
				SourcePatterns: []*regexp.Regexp{
					regexp.MustCompile(`(?i)\$_GET\s*\[`),
					regexp.MustCompile(`(?i)\$_POST\s*\[`),
					regexp.MustCompile(`(?i)\$_REQUEST\s*\[`),
					regexp.MustCompile(`(?i)\$_SERVER\s*\[`),
				},
				SinkPatterns: []*regexp.Regexp{
					regexp.MustCompile(`(?i)file_get_contents\s*\([^)]+\$`),
					regexp.MustCompile(`(?i)fopen\s*\([^)]+\$`),
					regexp.MustCompile(`(?i)curl_init\s*\([^)]+\$`),
					regexp.MustCompile(`(?i)curl_setopt.*CURLOPT_URL`),
					regexp.MustCompile(`(?i)fsockopen\s*\([^)]+\$`),
					regexp.MustCompile(`(?i)socket_connect\s*\([^)]+\$`),
					regexp.MustCompile(`(?i)get_headers\s*\([^)]+\$`),
					regexp.MustCompile(`(?i)get_meta_tags\s*\([^)]+\$`),
					regexp.MustCompile(`(?i)simplexml_load_file\s*\([^)]+\$`),
				},
				SanitizerPatterns: []*regexp.Regexp{
					regexp.MustCompile(`(?i)filter_var\s*\([^)]*FILTER_VALIDATE_URL`),
					regexp.MustCompile(`(?i)whitelist|allowlist`),
					regexp.MustCompile(`(?i)preg_match\s*\([^)]*http`),
				},
				SafeContextPatterns: []*regexp.Regexp{},
				Severity:            CriticalSev,
			},
			// Path Traversal
			{
				Name:        "PathTraversal",
				Description: "Path Traversal - User input used in file paths without sanitization",
				SourcePatterns: []*regexp.Regexp{
					regexp.MustCompile(`(?i)\$_GET\s*\[`),
					regexp.MustCompile(`(?i)\$_POST\s*\[`),
					regexp.MustCompile(`(?i)\$_REQUEST\s*\[`),
					regexp.MustCompile(`(?i)\$_COOKIE\s*\[`),
				},
				SinkPatterns: []*regexp.Regexp{
					regexp.MustCompile(`(?i)file\s*\([^)]+\$`),
					regexp.MustCompile(`(?i)file_exists\s*\([^)]+\$`),
					regexp.MustCompile(`(?i)is_file\s*\([^)]+\$`),
					regexp.MustCompile(`(?i)is_dir\s*\([^)]+\$`),
					regexp.MustCompile(`(?i)unlink\s*\([^)]+\$`),
					regexp.MustCompile(`(?i)copy\s*\([^)]+\$`),
					regexp.MustCompile(`(?i)rename\s*\([^)]+\$`),
					regexp.MustCompile(`(?i)move_uploaded_file\s*\([^)]+\$`),
				},
				SanitizerPatterns: []*regexp.Regexp{
					regexp.MustCompile(`(?i)basename\s*\(`),
					regexp.MustCompile(`(?i)realpath\s*\(`),
					regexp.MustCompile(`(?i)str_replace\s*\([^)]*\.\.`),
				},
				SafeContextPatterns: []*regexp.Regexp{},
				Severity:            Warning,
			},
			// XXE - XML External Entity
			{
				Name:        "XXE",
				Description: "XML External Entity - User input in XML parsing without entity restriction",
				SourcePatterns: []*regexp.Regexp{
					regexp.MustCompile(`(?i)\$_GET\s*\[`),
					regexp.MustCompile(`(?i)\$_POST\s*\[`),
					regexp.MustCompile(`(?i)file_get_contents\s*\(['"]php://input['"]\s*\)`),
					regexp.MustCompile(`(?i)\$HTTP_RAW_POST_DATA`),
				},
				SinkPatterns: []*regexp.Regexp{
					regexp.MustCompile(`(?i)simplexml_load_string\s*\([^)]+\$`),
					regexp.MustCompile(`(?i)simplexml_load_file\s*\([^)]+\$`),
					regexp.MustCompile(`(?i)DOMDocument->loadXML\s*\([^)]+\$`),
					regexp.MustCompile(`(?i)xml_parse\s*\([^)]+\$`),
					regexp.MustCompile(`(?i)xml_parser_create`),
				},
				SanitizerPatterns: []*regexp.Regexp{
					regexp.MustCompile(`(?i)libxml_disable_entity_loader\s*\(\s*true`),
					regexp.MustCompile(`(?i)LIBXML_NONET|LIBXML_DTDLOAD`),
				},
				SafeContextPatterns: []*regexp.Regexp{},
				Severity:            CriticalSev,
			},
		},
		findings: []Finding{},
	}
}

// AnalyzeFile performs deep analysis on a single file
func (ta *TaintAnalyzer) AnalyzeFile(filePath string, content string) {
	ta.scannedFiles++
	lines := strings.Split(content, "\n")

	// Track variable assignments and their taint status
	variableTaint := make(map[string]bool)

	for lineNum, line := range lines {
		currentLine := lineNum + 1

		// Track variable assignments from user input (SOURCES)
		for varName, isTainted := range ta.findVariableSources(line) {
			variableTaint[varName] = isTainted
		}

		// Check for sanitization that removes taint
		for varName := range ta.findSanitizers(line) {
			if _, exists := variableTaint[varName]; exists {
				variableTaint[varName] = false // Remove taint
			}
		}

		// Check each rule for vulnerabilities
		for _, rule := range ta.rules {
			confidence := ta.analyzeLine(line, rule, variableTaint)
			if confidence > Low {
				finding := Finding{
					FilePath:    filePath,
					LineNumber:  currentLine,
					BugType:     rule.Name,
					Confidence:  confidence,
					Severity:    rule.Severity,
					CodeSnippet: strings.TrimSpace(line),
					Explanation: rule.Description,
					Remediation: ta.getRemediation(rule.Name),
				}
				ta.findings = append(ta.findings, finding)
			}
		}
	}
}

// findVariableSources identifies variables assigned from user input
// This includes direct assignments AND variables receiving user input through function calls
func (ta *TaintAnalyzer) findVariableSources(line string) map[string]bool {
	result := make(map[string]bool)

	// Pattern 1: Direct assignment $var = $_GET['param']
	patterns := []string{
		`(?i)\$([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*\$_(GET|POST|REQUEST|COOKIE|FILES|SERVER|ENV|SESSION)\s*\[`,
		`(?i)\$([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*.*file_get_contents\s*\(\s*['"]php://input['"]`,
		`(?i)\$([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*.*\$HTTP_RAW_POST_DATA`,
	}

	for _, pattern := range patterns {
		re := regexp.MustCompile(pattern)
		matches := re.FindAllStringSubmatch(line, -1)
		for _, match := range matches {
			if len(match) > 1 {
				result["$"+match[1]] = true
			}
		}
	}

	// Pattern 2: Assignment where $_GET/$_POST appears anywhere in the right-hand side
	// This catches: $re = str_replace('script', '', $_GET['lname']);
	varAssignmentPattern := regexp.MustCompile(`(?i)\$([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*[^;]*\$_(GET|POST|REQUEST|COOKIE|SERVER)`)
	matches := varAssignmentPattern.FindStringSubmatch(line)
	if len(matches) > 1 {
		result["$"+matches[1]] = true
	}

	return result
}

// findSanitizers detects if a variable is being sanitized with PROPER sanitization
// Note: str_replace is NOT a general sanitizer - it's only valid for path traversal when removing '..'
func (ta *TaintAnalyzer) findSanitizers(line string) map[string]bool {
	result := make(map[string]bool)

	// Patterns for PROPER sanitization functions only
	// IMPORTANT: str_replace is NOT included here because:
	// - str_replace('script', '', ...) is bypassable: <scrscriptipt>
	// - str_replace('<', '', ...) is bypassable: <<script>>
	// Only specific context-aware replacements in PathTraversal rule use str_replace
	sanitizerPatterns := []string{
		`(?i)\$[a-zA-Z_][a-zA-Z0-9_]*\s*=\s*htmlspecialchars\s*\(`,
		`(?i)\$[a-zA-Z_][a-zA-Z0-9_]*\s*=\s*htmlentities\s*\(`,
		`(?i)\$[a-zA-Z_][a-zA-Z0-9_]*\s*=\s*strip_tags\s*\(`,
		`(?i)\$[a-zA-Z_][a-zA-Z0-9_]*\s*=\s*intval\s*\(`,
		`(?i)\$[a-zA-Z_][a-zA-Z0-9_]*\s*=\s*floatval\s*\(`,
		`(?i)\$[a-zA-Z_][a-zA-Z0-9_]*\s*=\s*basename\s*\(`,
		`(?i)\$[a-zA-Z_][a-zA-Z0-9_]*\s*=\s*realpath\s*\(`,
		`(?i)\$[a-zA-Z_][a-zA-Z0-9_]*\s*=\s*escapeshellarg\s*\(`,
		`(?i)\$[a-zA-Z_][a-zA-Z0-9_]*\s*=\s*escapeshellcmd\s*\(`,
		`(?i)\$[a-zA-Z_][a-zA-Z0-9_]*\s*=\s*mysql_real_escape_string\s*\(`,
		`(?i)\$[a-zA-Z_][a-zA-Z0-9_]*\s*=\s*mysqli_real_escape_string\s*\(`,
		`(?i)\$[a-zA-Z_][a-zA-Z0-9_]*\s*=\s*addslashes\s*\(`,
		`(?i)\$[a-zA-Z_][a-zA-Z0-9_]*\s*=\s*filter_input\s*\(`,
		`(?i)\$[a-zA-Z_][a-zA-Z0-9_]*\s*=\s*filter_var\s*\(`,
		`(?i)\$[a-zA-Z_][a-zA-Z0-9_]*\s*=\s*json_encode\s*\(`,
		`(?i)\$[a-zA-Z_][a-zA-Z0-9_]*\s*=\s*urlencode\s*\(`,
		// WordPress/Laravel/Symfony/CMS sanitizers (from Semgrep rules)
		`(?i)\$[a-zA-Z_][a-zA-Z0-9_]*\s*=\s*esc_html\s*\(`,
		`(?i)\$[a-zA-Z_][a-zA-Z0-9_]*\s*=\s*esc_attr\s*\(`,
		`(?i)\$[a-zA-Z_][a-zA-Z0-9_]*\s*=\s*wp_kses\s*\(`,
		`(?i)\$[a-zA-Z_][a-zA-Z0-9_]*\s*=\s*e\s*\(`,
		`(?i)\$[a-zA-Z_][a-zA-Z0-9_]*\s*=\s*twig_escape_filter\s*\(`,
		`(?i)\$[a-zA-Z_][a-zA-Z0-9_]*\s*=\s*xss_clean\s*\(`,
		`(?i)\$[a-zA-Z_][a-zA-Z0-9_]*\s*=\s*html_escape\s*\(`,
		`(?i)\$[a-zA-Z_][a-zA-Z0-9_]*\s*=\s*Html::escape\s*\(`,
		`(?i)\$[a-zA-Z_][a-zA-Z0-9_]*\s*=\s*Xss::filter\s*\(`,
		`(?i)\$[a-zA-Z_][a-zA-Z0-9_]*\s*=\s*escapeHtml\s*\(`,
		`(?i)\$[a-zA-Z_][a-zA-Z0-9_]*\s*=\s*escapeHtmlAttr\s*\(`,
	}

	for _, pattern := range sanitizerPatterns {
		re := regexp.MustCompile(pattern)
		if re.MatchString(line) {
			// Extract variable name from assignment
			varPattern := regexp.MustCompile(`(?i)\$([a-zA-Z_][a-zA-Z0-9_]*)\s*=`)
			matches := varPattern.FindStringSubmatch(line)
			if len(matches) > 1 {
				result["$"+matches[1]] = true
			}
		}
	}

	return result
}

// analyzeLine determines the confidence level of a vulnerability
func (ta *TaintAnalyzer) analyzeLine(line string, rule VulnerabilityRule, variableTaint map[string]bool) Confidence {
	hasSink := false
	hasSource := false
	hasSanitizer := false
	hasSafeContext := false

	// Check for sinks (dangerous functions)
	for _, sinkPattern := range rule.SinkPatterns {
		if sinkPattern.MatchString(line) {
			hasSink = true
			break
		}
	}

	if !hasSink {
		return Low
	}

	// Check for direct user input sources
	for _, sourcePattern := range rule.SourcePatterns {
		if sourcePattern.MatchString(line) {
			hasSource = true
			break
		}
	}

	// Check for tainted variables being used
	if !hasSource {
		for varName := range variableTaint {
			if variableTaint[varName] && strings.Contains(line, varName) {
				hasSource = true
				break
			}
		}
	}

	if !hasSource {
		return Low
	}

	// Check for sanitizers
	for _, sanitizerPattern := range rule.SanitizerPatterns {
		if sanitizerPattern.MatchString(line) {
			hasSanitizer = true
			break
		}
	}

	// Check for safe context patterns
	for _, safePattern := range rule.SafeContextPatterns {
		if safePattern.MatchString(line) {
			hasSafeContext = true
			break
		}
	}

	// Determine confidence based on findings
	if hasSanitizer || hasSafeContext {
		return Low
	}

	if hasSink && hasSource {
		// Check for direct flow (higher confidence)
		for _, sourcePattern := range rule.SourcePatterns {
			if sourcePattern.MatchString(line) {
				return Critical
			}
		}
		return High
	}

	return Medium
}

// getRemediation returns remediation advice for each vulnerability type
func (ta *TaintAnalyzer) getRemediation(bugType string) string {
	remediations := map[string]string{
		"LFI":           "Use basename(), realpath(), or maintain a whitelist of allowed files. Avoid user input in include/require paths.",
		"RCE":           "Never pass user input to eval(), exec(), system(), etc. Use escapeshellarg()/escapeshellcmd() for command arguments.",
		"SQLI":          "Use prepared statements with PDO or MySQLi. Never concatenate user input into SQL queries.",
		"XSS":           "Use htmlspecialchars() or htmlentities() with ENT_QUOTES when outputting user data in HTML context.",
		"SSRF":          "Validate and whitelist URLs. Disable URL schemas like file://, dict://, ftp://. Use allowlists for domains.",
		"PathTraversal": "Use basename(), realpath(), or pathinfo() to extract filename only. Remove path traversal sequences.",
		"XXE":           "Disable external entity loading: libxml_disable_entity_loader(true). Use LIBXML_NONET flag.",
	}
	if rem, ok := remediations[bugType]; ok {
		return rem
	}
	return "Review and sanitize all user input before use."
}

// PrintResults outputs findings in a professional format
func (ta *TaintAnalyzer) PrintResults() {
	fmt.Println("\n" + strings.Repeat("=", 80))
	fmt.Println("VULNSPECTRA SECURITY SCAN RESULTS")
	fmt.Println(strings.Repeat("=", 80))
	fmt.Printf("Files Scanned: %d\n", ta.scannedFiles)
	fmt.Printf("Vulnerabilities Found: %d\n\n", len(ta.findings))

	if len(ta.findings) == 0 {
		fmt.Println("✓ No vulnerabilities detected with high confidence.")
		return
	}

	// Group by severity
	criticalCount, highCount, mediumCount, lowCount := 0, 0, 0, 0
	for _, f := range ta.findings {
		switch f.Confidence {
		case Critical:
			criticalCount++
		case High:
			highCount++
		case Medium:
			mediumCount++
		default:
			lowCount++
		}
	}

	fmt.Printf("Severity Distribution: CRITICAL: %d | HIGH: %d | MEDIUM: %d | LOW: %d\n\n",
		criticalCount, highCount, mediumCount, lowCount)

	// Print findings
	for i, finding := range ta.findings {
		severityIcon := "ℹ"
		if finding.Severity == CriticalSev {
			severityIcon = "🚨"
		} else if finding.Severity == Warning {
			severityIcon = "⚠"
		}

		fmt.Printf("\n%s FINDING #%d: %s [%s Confidence]\n", severityIcon, i+1, finding.BugType, finding.Confidence)
		fmt.Println(strings.Repeat("-", 60))
		fmt.Printf("File: %s\n", finding.FilePath)
		fmt.Printf("Line: %d\n", finding.LineNumber)
		fmt.Printf("Code: %s\n", finding.CodeSnippet)
		fmt.Printf("Description: %s\n", finding.Explanation)
		fmt.Printf("Remediation: %s\n", finding.Remediation)
	}

	fmt.Println("\n" + strings.Repeat("=", 80))
}

// SaveResultsToFile saves findings to a report file (appends if file exists)
func (ta *TaintAnalyzer) SaveResultsToFile(filename string) error {
	// Open file in append mode, create if doesn't exist
	file, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	fmt.Fprintf(writer, "VulnSpectra Security Scan Report\n")
	fmt.Fprintf(writer, "Files Scanned: %d\n", ta.scannedFiles)
	fmt.Fprintf(writer, "Vulnerabilities Found: %d\n\n", len(ta.findings))

	for i, finding := range ta.findings {
		fmt.Fprintf(writer, "\nFINDING #%d: %s [%s Confidence]\n", i+1, finding.BugType, finding.Confidence)
		fmt.Fprintf(writer, "File: %s\n", finding.FilePath)
		fmt.Fprintf(writer, "Line: %d\n", finding.LineNumber)
		fmt.Fprintf(writer, "Code: %s\n", finding.CodeSnippet)
		fmt.Fprintf(writer, "Description: %s\n", finding.Explanation)
		fmt.Fprintf(writer, "Remediation: %s\n", finding.Remediation)
		fmt.Fprintln(writer, strings.Repeat("-", 60))
	}

	return writer.Flush()
}

func main() {
	// Command line flags
	filesystem := pflag.StringP("filesystem", "f", ".", "Directory to scan")
	extensions := pflag.StringP("ext", "e", "php,js,java,py,go", "Comma-separated file extensions to scan")
	output := pflag.StringP("output", "o", "", "Output report file (optional)")
	minConfidence := pflag.StringP("confidence", "c", "Medium", "Minimum confidence level (Low, Medium, High, Critical)")
	vulnCheck := pflag.StringP("vulncheck", "v", "", "Filter by specific vulnerability types (e.g., XSS, SQLI, LFI, RCE)")
	ignoreVulnCheck := pflag.StringP("ignore-vulncheck", "i", "", "Ignore specific vulnerability types (e.g., XSS, SQLI, LFI, RCE)")
	silent := pflag.Bool("silent", false, "Silent mode.")
	version := pflag.Bool("version", false, "Print the version of the tool and exit.")
	pflag.Parse()

	// Print version and exit if -version flag is provided
	if *version {
		banner.PrintBanner()
		banner.PrintVersion()
		return
	}

	// Don't Print banner if -silnet flag is provided
	if !*silent {
		banner.PrintBanner()
	}

	// Parse minimum confidence
	confidenceLevels := map[string]Confidence{
		"Low":      Low,
		"Medium":   Medium,
		"High":     High,
		"Critical": Critical,
	}
	minConf := confidenceLevels[strings.Title(strings.ToLower(*minConfidence))]

	// Parse extensions
	extMap := make(map[string]bool)
	for _, ext := range strings.Split(*extensions, ",") {
		extMap["."+strings.TrimSpace(strings.ToLower(ext))] = true
	}

	// Parse vulnerability filter
	vulnFilter := make(map[string]bool)
	if *vulnCheck != "" {
		for _, v := range strings.Split(*vulnCheck, ",") {
			vulnFilter[strings.TrimSpace(strings.ToUpper(v))] = true
		}
	}

	// Parse vulnerability ignore filter
	ignoreVulnFilter := make(map[string]bool)
	if *ignoreVulnCheck != "" {
		for _, v := range strings.Split(*ignoreVulnCheck, ",") {
			ignoreVulnFilter[strings.TrimSpace(strings.ToUpper(v))] = true
		}
	}

	// Create analyzer
	analyzer := NewTaintAnalyzer()

	fmt.Printf("🔍 VulnSpectra - Advanced Taint Analysis Engine\n")
	fmt.Printf("   Scanning: %s\n", *filesystem)
	fmt.Printf("   Extensions: %s\n", *extensions)
	fmt.Printf("   Min Confidence: %s\n", *minConfidence)
	if *vulnCheck != "" {
		fmt.Printf("   Vuln Filter: %s\n", *vulnCheck)
	}
	if *ignoreVulnCheck != "" {
		fmt.Printf("   Ignore Vuln: %s\n", *ignoreVulnCheck)
	}
	fmt.Println()

	// Walk directory
	err := filepath.Walk(*filesystem, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() {
			return nil
		}

		ext := strings.ToLower(filepath.Ext(path))
		if !extMap[ext] {
			return nil
		}

		content, err := os.ReadFile(path)
		if err != nil {
			fmt.Printf("⚠ Error reading %s: %v\n", path, err)
			return nil
		}

		analyzer.AnalyzeFile(path, string(content))
		return nil
	})

	if err != nil {
		fmt.Printf("Error walking directory: %v\n", err)
		os.Exit(1)
	}

	// Filter findings by confidence and vulnerability type
	var filteredFindings []Finding
	for _, f := range analyzer.findings {
		// Check confidence level
		if f.Confidence < minConf {
			continue
		}
		// Check vulnerability filter if specified
		if len(vulnFilter) > 0 {
			if !vulnFilter[strings.ToUpper(f.BugType)] {
				continue
			}
		}
		// Check vulnerability ignore filter if specified
		if len(ignoreVulnFilter) > 0 {
			if ignoreVulnFilter[strings.ToUpper(f.BugType)] {
				continue
			}
		}
		filteredFindings = append(filteredFindings, f)
	}
	analyzer.findings = filteredFindings

	// Print results
	analyzer.PrintResults()

	// Save to file if requested
	if *output != "" {
		if err := analyzer.SaveResultsToFile(*output); err != nil {
			fmt.Printf("Error saving report: %v\n", err)
		} else {
			fmt.Printf("\n📄 Report saved to: %s\n", *output)
		}
	}
}
