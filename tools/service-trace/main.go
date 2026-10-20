// Command service-trace hosts the shared fake services peer for the Rust SDK's
// trace tests. Its Go tests drive the Go libraries against the same peer and
// write the golden traces in testdata.
package main

import (
	"fmt"
	"os"

	"github.com/cinnabar-mc/bedrock-services/tools/service-trace/fake"
)

func main() {
	if len(os.Args) != 2 || os.Args[1] != "serve" {
		fmt.Fprintln(os.Stderr, "usage: service-trace serve")
		os.Exit(2)
	}
	if err := fake.Serve(os.Stdin, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "service-trace:", err)
		os.Exit(1)
	}
}
