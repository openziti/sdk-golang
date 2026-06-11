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

package harness

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/openziti/sdk-golang/acceptance/internal/ziticli"
)

const routerReadyTimeout = 60 * time.Second

// Router is a running edge-router child process, with lifecycle control for
// failover tests.
type Router struct {
	name       string
	configPath string
	port       int
	logPath    string
	cli        *ziticli.Cli // env preconfigured for this router's config paths
	cmd        *exec.Cmd
}

// Name returns the router's unique name on the controller.
func (r *Router) Name() string {
	return r.name
}

// AddRouter creates, enrolls, and runs an additional edge router as its own child
// process, uniquely named per the isolation contract, registering stop and
// best-effort entity deletion with t.
func (h *Harness) AddRouter(t testing.TB, base string) *Router {
	t.Helper()
	name := uniqueName(t, base)
	r, err := h.addRouter(name)
	if err != nil {
		t.Fatalf("adding router %s: %v", name, err)
	}
	t.Cleanup(func() {
		r.stopProcess()
		_, _ = h.cli.Run(context.Background(), "edge", "delete", "edge-router", name)
	})
	return r
}

// addRouter creates, enrolls, and runs an edge router as its own child process,
// per the separate-process contract. It follows the version-stable CLI sequence
// (create edge-router -> create config router edge -> router enroll -> router
// run), with each step executed by the version under test so the config stays
// version-correct. The router carries a role attribute equal to its name for
// targeted policies, and is gated on both TCP-listening and controller-reported
// online before returning. The caller owns the router's lifecycle.
func (h *Harness) addRouter(name string) (*Router, error) {
	routerDir := filepath.Join(h.home, "routers", name)
	if err := os.MkdirAll(routerDir, 0o700); err != nil {
		return nil, fmt.Errorf("creating router dir: %w", err)
	}
	jwtPath := filepath.Join(routerDir, name+".jwt")
	configPath := filepath.Join(routerDir, name+".yaml")

	ctx := context.Background()
	if _, err := h.cli.Run(ctx, "edge", "create", "edge-router", name,
		"--jwt-output-file", jwtPath,
		"--tunneler-enabled",
		"--role-attributes", name); err != nil {
		return nil, err
	}

	port, err := freePort()
	if err != nil {
		return nil, err
	}

	// the config generators read these; ZITI_HOME keeps the router's identity
	// files under its own directory
	rcli := h.cli.WithEnv(
		"ZITI_HOME="+routerDir,
		"ZITI_CTRL_ADVERTISED_ADDRESS=127.0.0.1",
		"ZITI_CTRL_ADVERTISED_PORT="+strconv.Itoa(h.ctrl.port),
		"ZITI_ROUTER_ADVERTISED_ADDRESS=127.0.0.1",
		"ZITI_ROUTER_PORT="+strconv.Itoa(port),
		"ZITI_ROUTER_LISTENER_BIND_PORT="+strconv.Itoa(port),
	)

	if _, err := rcli.Run(ctx, "create", "config", "router", "edge",
		"--routerName", name, "--output", configPath); err != nil {
		return nil, fmt.Errorf("generating router config: %w", err)
	}
	if _, err := rcli.Run(ctx, "router", "enroll", configPath, "--jwt", jwtPath); err != nil {
		return nil, fmt.Errorf("enrolling router: %w", err)
	}

	r := &Router{
		name:       name,
		configPath: configPath,
		port:       port,
		logPath:    filepath.Join(routerDir, name+".log"),
		cli:        rcli,
	}
	if err := r.start(); err != nil {
		r.stopProcess()
		return nil, err
	}
	return r, nil
}

// Start relaunches the router process and waits for it to be ready again, e.g.
// after a Stop in a failover test.
func (r *Router) Start(t testing.TB) {
	t.Helper()
	if err := r.start(); err != nil {
		t.Fatalf("router %s: %v", r.name, err)
	}
}

// start launches the router process and waits for it to be both TCP-listening and
// reported online by the controller. Config and enrollment persist across
// restarts, so Stop/start cycles need no re-enrollment.
func (r *Router) start() error {
	logFile, err := os.OpenFile(r.logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return fmt.Errorf("opening router log: %w", err)
	}
	cmd := r.cli.Command(context.Background(), "router", "run", r.configPath)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	if err := cmd.Start(); err != nil {
		_ = logFile.Close()
		return fmt.Errorf("starting router process: %w", err)
	}
	_ = logFile.Close()
	r.cmd = cmd

	return r.awaitReady()
}

// Stop kills the router process, e.g. to exercise SDK reconnect/failover.
func (r *Router) Stop(t testing.TB) {
	t.Helper()
	r.stopProcess()
}

func (r *Router) stopProcess() {
	stopProcess(r.cmd)
	r.cmd = nil
}

// awaitReady waits for the router's edge listener to accept TCP and for the
// controller to report the router online; the latter is the stronger gate, since
// a TCP-listening router may not yet be usable for dials.
func (r *Router) awaitReady() error {
	deadline := time.Now().Add(routerReadyTimeout)
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(r.port))

	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, time.Second)
		if err == nil {
			_ = conn.Close()
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	var lastState string
	for time.Now().Before(deadline) {
		online, state, err := r.isOnline()
		if err == nil && online {
			return nil
		}
		lastState = state
		if err != nil {
			lastState = err.Error()
		}
		time.Sleep(250 * time.Millisecond)
	}
	return fmt.Errorf("not online after %s (last state: %s)", routerReadyTimeout, lastState)
}

// isOnline asks the controller whether this router is online, via the versioned
// CLI's JSON output.
func (r *Router) isOnline() (bool, string, error) {
	out, err := r.cli.Run(context.Background(), "edge", "list", "edge-routers",
		fmt.Sprintf(`name = "%s"`, r.name), "-j")
	if err != nil {
		return false, "", err
	}
	var listing struct {
		Data []struct {
			Name     string `json:"name"`
			IsOnline bool   `json:"isOnline"`
		} `json:"data"`
	}
	if err := json.Unmarshal([]byte(out), &listing); err != nil {
		return false, "", fmt.Errorf("parsing edge-router listing: %w", err)
	}
	for _, er := range listing.Data {
		if er.Name == r.name {
			return er.IsOnline, fmt.Sprintf("listed, isOnline=%v", er.IsOnline), nil
		}
	}
	return false, "router not in listing", nil
}
