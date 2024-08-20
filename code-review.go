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
    patterns := map[string]string{
        // Local File Inclusion
        `include\(.*\$_GET|$_POST\(`: "LFI",
        `include_once\(.*\$_GET|$_POST\(`: "LFI",
        `require\(.*\$_GET|$_POST\(`: "LFI",
        `require_once\(.*\$_GET|$_POST\(`: "LFI",
        `isset\(.*\$_GET|$_POST\(`: "LFI", // Not sure this is 100% LFI

        // SQL Injection
        `SELECT \* FROM.*\$_(GET|POST)`: "SQLI",

        // Server Side Request Forgery
        `file_get_contents\(.*\$_(GET|POST)|curl_exec\(.*\$_(GET|POST)`: "SSRF",

        // Remote Code Execution
        `shell_exec\(.*\$_(GET|POST)`: "RCE", // Not sure this is 100% RCE

        // Cross-Site Scripting
        // : "XSS"
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

            for re, bugType := range regexes {
                matches := re.FindAllStringIndex(content, -1)
                if matches != nil {
                    for _, match := range matches {
                        // Find the line number
                        lineNumber := strings.Count(content[:match[0]], "\n") + 1

                        fmt.Printf("Filename: %s\n", path)
                        fmt.Printf("Line: %d\n", lineNumber)
                        fmt.Printf("Bug Type: %s\n", bugType)
                        fmt.Printf("Vulnerable Path: %s\n", "http://127.0.0.1"+"/"+path+"?"+"param=")
                        fmt.Println() // Print a blank line for separation
                    }
                }
            }
        }
        return nil
    })

    if err != nil {
        fmt.Println("Error:", err)
    }
}
