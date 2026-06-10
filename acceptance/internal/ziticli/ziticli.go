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

// Package ziticli is a thin exec wrapper over an acquired ziti binary. Every
// invocation runs with an isolated ZITI_CONFIG_DIR and a scrubbed environment, so
// harness CLI logins never collide with the developer's own ziti CLI state or
// inherit stray ZITI_* settings from the shell.
package ziticli

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// Cli runs a specific ziti binary with an isolated CLI configuration directory.
type Cli struct {
	binPath   string
	configDir string
	extraEnv  []string
}

// New returns a Cli for the binary at binPath, storing CLI state (logins,
// identities) under configDir. The ziti CLI honors ZITI_CONFIG_DIR for its
// ziti-cli.json location (note: ZITI_HOME does not govern it).
func New(binPath, configDir string) *Cli {
	return &Cli{binPath: binPath, configDir: configDir}
}

// WithEnv returns a copy of the Cli that sets additional KEY=VALUE pairs for its
// invocations, e.g. the ZITI_* variables the config generators read.
func (c *Cli) WithEnv(kv ...string) *Cli {
	clone := *c
	clone.extraEnv = append(append([]string{}, c.extraEnv...), kv...)
	return &clone
}

// BinPath returns the path of the wrapped ziti binary.
func (c *Cli) BinPath() string {
	return c.binPath
}

// Env returns the environment for an invocation: the parent environment with every
// ZITI_* variable removed, then ZITI_CONFIG_DIR and any extra pairs applied.
func (c *Cli) Env() []string {
	var env []string
	for _, kv := range os.Environ() {
		if strings.HasPrefix(kv, "ZITI_") {
			continue
		}
		env = append(env, kv)
	}
	env = append(env, "ZITI_CONFIG_DIR="+c.configDir)
	return append(env, c.extraEnv...)
}

// Run executes the ziti binary with args and returns its stdout. On failure the
// error carries the command line, exit status, and stderr.
func (c *Cli) Run(ctx context.Context, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, c.binPath, args...)
	cmd.Env = c.Env()

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return stdout.String(), fmt.Errorf("ziti %s: %w\nstderr: %s",
			strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return stdout.String(), nil
}

// Command returns an exec.Cmd for a long-running ziti invocation (e.g. a controller
// or router process), with the same isolated environment as Run. The caller owns
// the process lifecycle.
func (c *Cli) Command(ctx context.Context, args ...string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, c.binPath, args...)
	cmd.Env = c.Env()
	return cmd
}
