package masque

import (
	"fmt"
	"io"
	"os"
)

// logDest is where the CLI-constructed logger writes.
func logDest() io.Writer { return os.Stdout }

// readFile reads a required PEM file, turning an empty path into a clear error
// rather than an obscure "open : no such file".
func readFile(path string) ([]byte, error) {
	if path == "" {
		return nil, fmt.Errorf("no path given")
	}
	return os.ReadFile(path)
}
