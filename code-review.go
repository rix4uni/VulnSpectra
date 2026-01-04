package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// extractParameterName extracts the parameter name from matched text using regex
// match array contains pairs: [fullMatchStart, fullMatchEnd, group1Start, group1End, ...]
func extractParameterName(content string, match []int, re *regexp.Regexp) string {
	// Check if we have at least the first capturing group (indices 2 and 3)
	if len(match) >= 4 && match[2] >= 0 && match[3] >= 0 {
		// Extract the parameter name from the first capturing group
		return content[match[2]:match[3]]
	}

	// Fallback: try to extract from the full matched text
	if len(match) >= 2 && match[0] >= 0 && match[1] >= 0 {
		matchedText := content[match[0]:match[1]]

		// Look for $_GET['param'] or $_POST['param'] pattern
		paramRegex := regexp.MustCompile(`\$(?:_GET|_POST)\[['"]([^'"]+)['"]\]`)
		paramMatches := paramRegex.FindStringSubmatch(matchedText)
		if len(paramMatches) > 1 {
			return paramMatches[1]
		}
	}

	return "param" // Default fallback
}

// isSanitized checks if the code uses proper sanitization functions
// In real-world code, sanitization might be:
// 1. On the same line: echo htmlspecialchars($_GET['param']);
// 2. In a variable assignment before: $safe = htmlspecialchars($_GET['param']); echo $safe;
// 3. In a ternary operator: echo isset($_GET['param']) ? htmlspecialchars($_GET['param']) : ”;
// Returns: true if properly sanitized, false if not sanitized
// Note: str_replace is considered inadequate sanitization and returns false
func isSanitized(content string, matchStart int, matchEnd int, paramName string) bool {
	// Get the line number where the match occurs
	lineStart := strings.LastIndex(content[:matchStart], "\n")
	if lineStart < 0 {
		lineStart = 0
	} else {
		lineStart++ // Move past the newline
	}

	// Find the end of the line (next newline or end of content)
	lineEnd := strings.Index(content[matchEnd:], "\n")
	if lineEnd < 0 {
		lineEnd = len(content)
	} else {
		lineEnd = matchEnd + lineEnd
	}

	// Get the full line containing the match
	matchedLine := content[lineStart:lineEnd]

	// Check if sanitization is in the same line (most common in real-world code)
	// Patterns like: echo htmlspecialchars($_GET['param']); or echo htmlentities($var);
	sanitizationInLine := regexp.MustCompile(`(htmlspecialchars|htmlentities|filter_var|mysqli_real_escape_string|addslashes|html_entity_decode|strip_tags)\s*\(`)
	if sanitizationInLine.MatchString(matchedLine) {
		// Check if the sanitization function wraps the vulnerable parameter
		// Look for pattern: sanitize_function(...$_GET['param']...)
		// Escape paramName to handle special regex characters
		escapedParamName := regexp.QuoteMeta(paramName)
		paramPattern := regexp.MustCompile(`\$_GET\[['"]` + escapedParamName + `['"]\]|\$_POST\[['"]` + escapedParamName + `['"]\]`)
		if paramPattern.MatchString(matchedLine) {
			// Check if sanitization function appears before the parameter in the same statement
			paramPos := strings.Index(matchedLine, "$_GET[\""+paramName+"\"]")
			if paramPos < 0 {
				paramPos = strings.Index(matchedLine, "$_GET['"+paramName+"']")
			}
			if paramPos < 0 {
				paramPos = strings.Index(matchedLine, "$_POST[\""+paramName+"\"]")
			}
			if paramPos < 0 {
				paramPos = strings.Index(matchedLine, "$_POST['"+paramName+"']")
			}

			if paramPos >= 0 {
				// Check if sanitization function call appears before the parameter
				beforeParam := matchedLine[:paramPos]
				if sanitizationInLine.MatchString(beforeParam) {
					// Find the opening parenthesis of the sanitization function
					// Make sure it's not closed before the parameter
					sanitizePos := strings.LastIndex(beforeParam, "htmlspecialchars")
					if sanitizePos < 0 {
						sanitizePos = strings.LastIndex(beforeParam, "htmlentities")
					}
					if sanitizePos < 0 {
						sanitizePos = strings.LastIndex(beforeParam, "filter_var")
					}

					if sanitizePos >= 0 {
						// Check if there's a matching opening parenthesis
						parenCount := 0
						for i := sanitizePos; i < paramPos; i++ {
							if matchedLine[i] == '(' {
								parenCount++
							} else if matchedLine[i] == ')' {
								parenCount--
							}
						}
						// If parenCount > 0, the sanitization function wraps the parameter
						if parenCount > 0 {
							return true
						}
					}
				}
			}
		}
	}

	// Check for sanitization in variable assignments before the match (within same function/scope)
	// Look back up to 500 characters or 10 lines
	start := matchStart - 500
	if start < 0 {
		start = 0
	}

	// Find the start of the current statement/block
	contextBefore := content[start:matchStart]

	// Check for variable assignments with sanitization
	// Pattern: $var = htmlspecialchars($_GET['param']);
	// Escape paramName to handle special regex characters
	escapedParamName := regexp.QuoteMeta(paramName)
	varAssignPatternGET := regexp.MustCompile(`\$[a-zA-Z_][a-zA-Z0-9_]*\s*=\s*(htmlspecialchars|htmlentities|filter_var|mysqli_real_escape_string|addslashes)\s*\([^)]*\$_GET\[['"]` + escapedParamName + `['"]\]`)
	varAssignPatternPOST := regexp.MustCompile(`\$[a-zA-Z_][a-zA-Z0-9_]*\s*=\s*(htmlspecialchars|htmlentities|filter_var|mysqli_real_escape_string|addslashes)\s*\([^)]*\$_POST\[['"]` + escapedParamName + `['"]\]`)
	if varAssignPatternGET.MatchString(contextBefore) || varAssignPatternPOST.MatchString(contextBefore) {
		// Check if that variable is used in the output
		varMatch := regexp.MustCompile(`\$([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*(htmlspecialchars|htmlentities|filter_var)`)
		matches := varMatch.FindAllStringSubmatch(contextBefore, -1)
		for _, match := range matches {
			if len(match) > 1 {
				varName := match[1]
				// Escape varName for regex
				escapedVarName := regexp.QuoteMeta(varName)
				// Check if this variable is used in the matched line
				varUsagePattern := regexp.MustCompile(`\$` + escapedVarName + `\b`)
				if varUsagePattern.MatchString(matchedLine) {
					return true
				}
			}
		}
	}

	// Check for ternary operators with sanitization
	// Pattern: echo isset($_GET['param']) ? htmlspecialchars($_GET['param']) : '';
	ternaryPattern := regexp.MustCompile(`\?(?:\s*htmlspecialchars\s*\(|\s*htmlentities\s*\(|\s*filter_var\s*\()\s*\$_(?:GET|POST)\[['"]` + escapedParamName + `['"]\]`)
	if ternaryPattern.MatchString(matchedLine) {
		return true
	}

	return false
}

// extractCodeSnippet extracts the code line and surrounding context
func extractCodeSnippet(content string, lineNumber int, matchStart int, matchEnd int) string {
	lines := strings.Split(content, "\n")
	if lineNumber < 1 || lineNumber > len(lines) {
		return ""
	}

	// Get context lines (2 before and 2 after)
	contextLines := []string{}
	startLine := lineNumber - 3
	if startLine < 0 {
		startLine = 0
	}
	endLine := lineNumber + 1
	if endLine > len(lines) {
		endLine = len(lines)
	}

	for i := startLine; i < endLine; i++ {
		line := strings.TrimRight(lines[i], "\r\n")
		if i == lineNumber-1 {
			contextLines = append(contextLines, fmt.Sprintf(">>> %s", line)) // Mark vulnerable line
		} else {
			contextLines = append(contextLines, fmt.Sprintf("    %s", line))
		}
	}

	return strings.Join(contextLines, "\n")
}

// getVulnerabilityReason returns a human-readable explanation of why the code is vulnerable
func getVulnerabilityReason(bugType string, isSanitized bool, codeSnippet string) string {
	if isSanitized {
		return "Potentially vulnerable - check sanitization effectiveness"
	}

	// Check for inadequate sanitization (str_replace)
	if strings.Contains(codeSnippet, "str_replace") && bugType == "XSS" {
		return "Inadequate sanitization using str_replace - easily bypassed, use htmlspecialchars() or htmlentities() instead - Cross-Site Scripting vulnerability"
	}

	switch bugType {
	case "XSS":
		return "Unsanitized user input directly output to HTML - Cross-Site Scripting vulnerability"
	case "LFI":
		return "User input used in file inclusion without proper validation - Local File Inclusion vulnerability"
	case "SQLI":
		return "User input used in SQL query without proper escaping - SQL Injection vulnerability"
	case "SSRF":
		return "User input used in network request without validation - Server-Side Request Forgery vulnerability"
	case "RCE":
		return "User input used in shell command execution - Remote Code Execution vulnerability"
	default:
		return "Security vulnerability detected"
	}
}

// findAllParameters finds all $_GET and $_POST parameters used in the file
func findAllParameters(content string) []string {
	paramMap := make(map[string]bool)
	paramRegex := regexp.MustCompile(`\$(?:_GET|_POST)\[['"]([^'"]+)['"]\]`)

	matches := paramRegex.FindAllStringSubmatch(content, -1)
	for _, match := range matches {
		if len(match) > 1 {
			paramMap[match[1]] = true
		}
	}

	// Convert map to sorted slice
	params := make([]string, 0, len(paramMap))
	for param := range paramMap {
		params = append(params, param)
	}

	// Simple sort
	for i := 0; i < len(params)-1; i++ {
		for j := i + 1; j < len(params); j++ {
			if params[i] > params[j] {
				params[i], params[j] = params[j], params[i]
			}
		}
	}

	return params
}

func main() {
	// Define command-line flags for directory and file extensions
	dirPtr := flag.String("filesystem", ".", "Directory to scan") // Default to current directory
	extPtr := flag.String("ext", "", "Comma-separated list of file extensions to include (e.g., php,java)")

	flag.Parse()

	// Check if the directory is provided as an argument
	if flag.NArg() > 0 {
		*dirPtr = flag.Arg(0) // Override the default with the provided directory
	}

	// Define regex patterns and their associated bug types
	// Patterns use capturing groups to extract parameter names
	patterns := map[string]string{
		// Local File Inclusion - match include/require with $_GET or $_POST
		// `include\([^)]*\$(?:_GET|_POST)\[['"]([^'"]+)['"]\]`:      "LFI",
		// `include_once\([^)]*\$(?:_GET|_POST)\[['"]([^'"]+)['"]\]`: "LFI",
		// `require\([^)]*\$(?:_GET|_POST)\[['"]([^'"]+)['"]\]`:      "LFI",
		// `require_once\([^)]*\$(?:_GET|_POST)\[['"]([^'"]+)['"]\]`: "LFI",

		// // SQL Injection - match SQL queries with $_GET or $_POST
		// `SELECT\s+\*\s+FROM[^;]*\$(?:_GET|_POST)\[['"]([^'"]+)['"]\]`: "SQLI",

		// // Server Side Request Forgery
		// `file_get_contents\([^)]*\$(?:_GET|_POST)\[['"]([^'"]+)['"]\]`: "SSRF",
		// `curl_exec\([^)]*\$(?:_GET|_POST)\[['"]([^'"]+)['"]\]`:         "SSRF",

		// // Remote Code Execution
		// `shell_exec\([^)]*\$(?:_GET|_POST)\[['"]([^'"]+)['"]\]`: "RCE",

		// Cross-Site Scripting - direct echo/print with $_GET/$_POST
		`echo\s+\$(?:_GET|_POST)\[['"]([^'"]+)['"]\]`:       "XSS",
		`print\s+\$(?:_GET|_POST)\[['"]([^'"]+)['"]\]`:      "XSS",
		`<\?=\s*\$(?:_GET|_POST)\[['"]([^'"]+)['"]\]\s*\?>`: "XSS", // <?= $_GET['param'] ?>
		// XSS patterns with str_replace - need to capture parameter name
		`\$[a-zA-Z_][a-zA-Z0-9_]*\s*=\s*str_replace\([^,]+,\s*['"]\s*['"],\s*\$(?:_GET|_POST)\[['"]([^'"]+)['"]\]\)`: "XSS", // $var = str_replace(..., '', $_GET['param'])
		`echo\s+\$[a-zA-Z_][a-zA-Z0-9_]*\s*;`:  "XSS", // echo $var; (will need to trace back)
		`print\s+\$[a-zA-Z_][a-zA-Z0-9_]*\s*;`: "XSS", // print $var; (will need to trace back)
	}

	// Compile regex patterns
	regexes := make(map[*regexp.Regexp]string)
	for pattern, bugType := range patterns {
		regexes[regexp.MustCompile(pattern)] = bugType
	}

	// Parse the file extensions from the flag
	var extensions map[string]bool
	if *extPtr != "" {
		extensions = make(map[string]bool)
		for _, ext := range strings.Split(*extPtr, ",") {
			extensions["."+strings.TrimSpace(ext)] = true
		}
	}

	// Get the base directory name
	baseDirName := filepath.Base(filepath.Clean(*dirPtr))
	fmt.Printf("Directory Name: %s\n", baseDirName)

	// Traverse the directory and its subdirectories
	err := filepath.Walk(*dirPtr, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Process only files that match the specified extensions or all files if no extension is specified
		if !info.IsDir() && (extensions == nil || extensions[filepath.Ext(path)]) {
			data, err := ioutil.ReadFile(path)
			if err != nil {
				return err
			}

			content := string(data)

			// Find all parameters in the file
			allParams := findAllParameters(content)

			// Track vulnerabilities found
			vulnerabilities := []map[string]interface{}{}

			for re, bugType := range regexes {
				// Find all matches with submatches to extract parameter names
				allMatches := re.FindAllStringSubmatchIndex(content, -1)
				for _, match := range allMatches {
					if len(match) < 2 {
						continue
					}

					// Find the line number
					lineNumber := strings.Count(content[:match[0]], "\n") + 1

					// Extract parameter name from the match
					paramName := extractParameterName(content, match, re)

					// For echo $var or print $var patterns, try to trace back to find the source
					// Real-world code might use: $var = $_GET['param']; or $var = isset($_GET['param']) ? $_GET['param'] : '';
					if paramName == "param" && (bugType == "XSS") {
						// Try to find if $var was assigned from $_GET/$_POST
						matchedText := content[match[0]:match[1]]
						varMatch := regexp.MustCompile(`\$([a-zA-Z_][a-zA-Z0-9_]*)`).FindStringSubmatch(matchedText)
						if len(varMatch) > 1 {
							varName := varMatch[1]
							// Look backwards for assignment from $_GET/$_POST (up to 1000 chars)
							start := match[0] - 1000
							if start < 0 {
								start = 0
							}
							contextBefore := content[start:match[0]]

							// Pattern 1: Direct assignment: $var = $_GET['param'];
							escapedVarName := regexp.QuoteMeta(varName)
							assignPattern := regexp.MustCompile(`\$` + escapedVarName + `\s*=\s*\$_(?:GET|POST)\[['"]([^'"]+)['"]\]`)
							assignMatch := assignPattern.FindStringSubmatch(contextBefore)
							if len(assignMatch) > 1 {
								paramName = assignMatch[1]
							} else {
								// Pattern 2: Ternary operator: $var = isset($_GET['param']) ? $_GET['param'] : 'default';
								ternaryPattern := regexp.MustCompile(`\$` + escapedVarName + `\s*=\s*[^?]*\?\s*\$_(?:GET|POST)\[['"]([^'"]+)['"]\]`)
								ternaryMatch := ternaryPattern.FindStringSubmatch(contextBefore)
								if len(ternaryMatch) > 1 {
									paramName = ternaryMatch[1]
								} else {
									// Pattern 3: Assignment with function call: $var = some_function($_GET['param']);
									funcPattern := regexp.MustCompile(`\$` + escapedVarName + `\s*=\s*[^(]*\([^)]*\$_(?:GET|POST)\[['"]([^'"]+)['"]\]`)
									funcMatch := funcPattern.FindStringSubmatch(contextBefore)
									if len(funcMatch) > 1 {
										paramName = funcMatch[1]
									}
								}
							}
						}
					}

					// Check if sanitized
					sanitized := isSanitized(content, match[0], match[1], paramName)

					// Extract code snippet
					codeSnippet := extractCodeSnippet(content, lineNumber, match[0], match[1])

					// Get vulnerability reason
					vulnReason := getVulnerabilityReason(bugType, sanitized, codeSnippet)

					// Format path as URL (convert backslashes to forward slashes)
					urlPath := filepath.ToSlash(path)
					// Remove leading "./" if present
					urlPath = strings.TrimPrefix(urlPath, "./")

					// Build vulnerable path URL
					vulnerablePath := fmt.Sprintf("http://127.0.0.1/%s?%s=", urlPath, paramName)

					vuln := map[string]interface{}{
						"line":           lineNumber,
						"param":          paramName,
						"bugType":        bugType,
						"vulnerablePath": vulnerablePath,
						"sanitized":      sanitized,
						"codeSnippet":    codeSnippet,
						"reason":         vulnReason,
					}
					vulnerabilities = append(vulnerabilities, vuln)
				}
			}

			// Output results for this file
			if len(vulnerabilities) > 0 || len(allParams) > 0 {
				fmt.Printf("\n" + strings.Repeat("=", 80) + "\n")
				fmt.Printf("File: %s\n", path)
				fmt.Printf(strings.Repeat("=", 80) + "\n")

				// List all parameters found
				if len(allParams) > 0 {
					fmt.Printf("\nAll Parameters Found: %s\n", strings.Join(allParams, ", "))
				}

				// Show vulnerabilities
				if len(vulnerabilities) > 0 {
					fmt.Printf("\nVulnerabilities Found:\n")
					fmt.Printf(strings.Repeat("-", 80) + "\n")

					for i, vuln := range vulnerabilities {
						fmt.Printf("\n[%d] Vulnerability #%d\n", i+1, i+1)
						fmt.Printf("Parameter: %s\n", vuln["param"])
						fmt.Printf("Bug Type: %s\n", vuln["bugType"])
						fmt.Printf("Line: %d\n", vuln["line"])
						fmt.Printf("Vulnerable Path: %s\n", vuln["vulnerablePath"])

						// Determine sanitization status with more context
						sanitized := vuln["sanitized"].(bool)
						codeSnippet := vuln["codeSnippet"].(string)
						var sanitizationStatus string
						if sanitized {
							sanitizationStatus = "Potentially Sanitized"
						} else if strings.Contains(codeSnippet, "str_replace") && vuln["bugType"] == "XSS" {
							sanitizationStatus = "Inadequate Sanitization (str_replace used)"
						} else {
							sanitizationStatus = "NOT Sanitized"
						}
						fmt.Printf("Sanitization: %s\n", sanitizationStatus)
						fmt.Printf("Reason: %s\n", vuln["reason"])
						fmt.Printf("Vulnerable Code:\n%s\n", vuln["codeSnippet"])
					}
				} else {
					fmt.Printf("\nNo vulnerabilities detected in this file.\n")
				}
				fmt.Printf("\n")
			}
		}
		return nil
	})

	if err != nil {
		fmt.Println("Error:", err)
	}
}
