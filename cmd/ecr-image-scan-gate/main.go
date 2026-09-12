// Command ecr-image-scan-gate turns Amazon ECR image scan findings into an
// exit code so a HIGH/CRITICAL CVE fails CI instead of shipping.
package main

import (
	"context"
	"fmt"
	"os"

	"github.com/moveeeax/ecr-image-scan-gate/internal/cli"
)

func main() {
	if err := cli.NewRootCmd().ExecuteContext(context.Background()); err != nil {
		// Cobra already prints the error; keep exit codes meaningful:
		// the scan command sets its own code via os.Exit on a tripped gate,
		// so reaching here means a usage/runtime error.
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(2)
	}
}
