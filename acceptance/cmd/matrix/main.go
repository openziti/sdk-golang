/*
	Copyright NetFoundry Inc.

	Licensed under the Apache License, Version 2.0 (the "License");
	you may not use this file except in compliance with the License.
	You may obtain a copy of the License at

	https://www.apache.org/licenses/LICENSE-2.0

	Unless required by applicable law or agreed to in writing, software
	distributed under the License is distributed on an "AS IS" BASIS,
	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
	See the License for the specific language governing permissions and
	limitations under the License.
*/

// Command matrix runs the acceptance suite once per ziti version selector and
// prints a per-version summary. The selector list defaults to the versions.yaml
// labels plus "latest"; arguments override it, and anything after "--" is passed
// through to go test.
//
// Usage:
//
//	go run ./cmd/matrix                          # full suite, default selectors
//	go run ./cmd/matrix -fail-fast               # stop at the first failing version
//	go run ./cmd/matrix maint-lts latest         # subset of selectors
//	go run ./cmd/matrix -- -run Test_Smoke -v    # one test across the matrix
package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"time"

	"github.com/openziti/sdk-golang/acquire"
)

func main() {
	failFast := flag.Bool("fail-fast", false, "stop after the first failing version")
	flag.Parse()
	selectors, extraArgs := splitArgs(flag.Args())

	cfgPath, err := acquire.FindVersionsFile()
	if err != nil {
		fatal(err)
	}
	moduleRoot := filepath.Dir(cfgPath)

	if len(selectors) == 0 {
		cfg, err := acquire.LoadVersions(cfgPath)
		if err != nil {
			fatal(err)
		}
		selectors = defaultSelectors(cfg)
	}

	type result struct {
		selector string
		err      error
		elapsed  time.Duration
	}
	var results []result
	for _, sel := range selectors {
		fmt.Printf("\n==== ZITI_ACCEPTANCE_VERSION=%s ====\n", sel)
		start := time.Now()
		err := runSuite(moduleRoot, sel, extraArgs)
		results = append(results, result{selector: sel, err: err, elapsed: time.Since(start).Round(time.Second)})
		if err != nil && *failFast {
			break
		}
	}

	fmt.Printf("\n==== matrix summary ====\n")
	failed := false
	for _, r := range results {
		status := "PASS"
		if r.err != nil {
			status = "FAIL"
			failed = true
		}
		fmt.Printf("%-12s %s  (%s)\n", r.selector, status, r.elapsed)
	}
	if len(results) < len(selectors) {
		fmt.Printf("%d selector(s) skipped by -fail-fast\n", len(selectors)-len(results))
	}
	if failed {
		os.Exit(1)
	}
}

// runSuite runs the tagged acceptance suite for one selector, streaming output.
// -count=1 is forced: go test's cache cannot see controller-side state, so a
// cached pass would be meaningless here.
func runSuite(moduleRoot, selector string, extraArgs []string) error {
	args := append([]string{"test", "-tags", "acceptance", "-count=1", "./..."}, extraArgs...)
	cmd := exec.Command("go", args...)
	cmd.Dir = moduleRoot
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = append(os.Environ(), "ZITI_ACCEPTANCE_VERSION="+selector)
	return cmd.Run()
}

// defaultSelectors is the versions.yaml labels (sorted) plus "latest".
func defaultSelectors(cfg acquire.Versions) []string {
	var sels []string
	for label := range cfg.Labels {
		sels = append(sels, label)
	}
	sort.Strings(sels)
	return append(sels, "latest")
}

// splitArgs separates selector arguments from pass-through go test arguments at
// the "--" marker.
func splitArgs(args []string) (selectors, extra []string) {
	for i, a := range args {
		if a == "--" {
			return args[:i], args[i+1:]
		}
	}
	return args, nil
}

func fatal(err error) {
	fmt.Fprintf(os.Stderr, "matrix: %v\n", err)
	os.Exit(1)
}
