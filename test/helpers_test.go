package test

import (
	"os"
)

// tmpFile creates a temp file with the given content and returns its path.
// The file has a .yaml extension so viper recognizes it.
func tmpFile(content string) (string, error) {
	f, err := os.CreateTemp("", "dredge-test-*.yaml")
	if err != nil {
		return "", err
	}
	defer f.Close()

	if _, err := f.WriteString(content); err != nil {
		return "", err
	}
	return f.Name(), nil
}
