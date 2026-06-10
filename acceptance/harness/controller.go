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
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/openziti/sdk-golang/acceptance/internal/ziticli"
)

const (
	adminUsername = "admin"
	adminPassword = "admin"

	controllerReadyTimeout = 90 * time.Second
	processStopGrace       = 10 * time.Second
)

// controller is the running controller-only quickstart child process.
type controller struct {
	cmd      *exec.Cmd
	hostPort string
	logPath  string
}

// startController launches `ziti edge quickstart --no-router` as a long-lived child
// process: a pure controller, per the separate-process bootstrap contract. The
// returned controller is listening but not yet verified admin-usable; see
// awaitAdminUsable.
func startController(cli *ziticli.Cli, home string) (*controller, error) {
	port, err := freePort()
	if err != nil {
		return nil, err
	}

	logPath := filepath.Join(home, "quickstart.log")
	logFile, err := os.Create(logPath)
	if err != nil {
		return nil, fmt.Errorf("creating controller log: %w", err)
	}

	// context.Background: the process is owned by the harness and stopped in
	// teardown, not tied to any per-test context
	cmd := cli.Command(context.Background(),
		"edge", "quickstart",
		"--no-router",
		"--home", home,
		"--ctrl-address", "127.0.0.1",
		"--ctrl-port", strconv.Itoa(port),
	)
	cmd.Stdout = logFile
	cmd.Stderr = logFile

	if err := cmd.Start(); err != nil {
		_ = logFile.Close()
		return nil, fmt.Errorf("starting controller: %w", err)
	}
	// the child holds the file open via its stdout/stderr fds; close our handle
	_ = logFile.Close()

	return &controller{
		cmd:      cmd,
		hostPort: net.JoinHostPort("127.0.0.1", strconv.Itoa(port)),
		logPath:  logPath,
	}, nil
}

// awaitAdminUsable gates readiness on the bootstrap contract: HTTPS 200 is not
// enough (the listener is up whether or not routerless init ran), so readiness is
// HTTPS 200 *and* a successful admin login *and* one harmless admin operation. A
// failure after the HTTP gate is precisely the "routerless quickstart did not
// perform admin init on this line" signal, reported as such.
func (c *controller) awaitAdminUsable(ctx context.Context, cli *ziticli.Cli, version Version) error {
	deadline := time.Now().Add(controllerReadyTimeout)

	if err := c.awaitHTTPS(ctx, deadline); err != nil {
		return fmt.Errorf("controller (version %s) never became reachable: %w\n%s", version, err, c.logTail())
	}

	loginErr := c.retryCliUntil(ctx, deadline, func() error {
		_, err := cli.Run(ctx, "edge", "login", c.hostPort,
			"--username", adminUsername, "--password", adminPassword, "--yes")
		return err
	})
	if loginErr != nil {
		return fmt.Errorf("bootstrap contract violation for version %s: controller answers HTTPS but admin login failed, "+
			"so quickstart --no-router did not yield an admin-usable controller on this line: %w\n%s",
			version, loginErr, c.logTail())
	}

	if _, err := cli.Run(ctx, "edge", "list", "identities"); err != nil {
		return fmt.Errorf("bootstrap contract violation for version %s: admin login succeeded but a harmless admin "+
			"operation failed: %w\n%s", version, err, c.logTail())
	}
	return nil
}

// awaitHTTPS polls the edge client API until it returns 200.
func (c *controller) awaitHTTPS(ctx context.Context, deadline time.Time) error {
	client := &http.Client{
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
		Timeout:   2 * time.Second,
	}
	url := fmt.Sprintf("https://%s/edge/client/v1/version", c.hostPort)

	var lastErr error
	for time.Now().Before(deadline) {
		if err := ctx.Err(); err != nil {
			return err
		}
		resp, err := client.Get(url)
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
			lastErr = fmt.Errorf("status %s", resp.Status)
		} else {
			lastErr = err
		}
		time.Sleep(250 * time.Millisecond)
	}
	return fmt.Errorf("timed out after %s: %w", controllerReadyTimeout, lastErr)
}

// retryCliUntil retries op until it succeeds or the deadline passes, returning the
// last error. Admin init runs asynchronously after the HTTPS listener is up, so the
// first login attempts may race it.
func (c *controller) retryCliUntil(ctx context.Context, deadline time.Time, op func() error) error {
	var lastErr error
	for time.Now().Before(deadline) {
		if err := ctx.Err(); err != nil {
			return err
		}
		if lastErr = op(); lastErr == nil {
			return nil
		}
		time.Sleep(time.Second)
	}
	return lastErr
}

// stop terminates the controller process: SIGTERM, then SIGKILL after a grace
// period.
func (c *controller) stop() {
	if c.cmd.Process == nil {
		return
	}
	_ = c.cmd.Process.Signal(os.Interrupt)

	done := make(chan struct{})
	go func() {
		_, _ = c.cmd.Process.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(processStopGrace):
		_ = c.cmd.Process.Kill()
		<-done
	}
}

// logTail returns the end of the controller log for inclusion in directed errors.
func (c *controller) logTail() string {
	data, err := os.ReadFile(c.logPath)
	if err != nil {
		return fmt.Sprintf("(no controller log: %v)", err)
	}
	const tailBytes = 4096
	if len(data) > tailBytes {
		data = data[len(data)-tailBytes:]
	}
	return "--- controller log tail ---\n" + strings.TrimSpace(string(data))
}

// freePort reserves an ephemeral TCP port and releases it for the child process to
// bind, so multiple harnesses can coexist without a fixed port map.
func freePort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, fmt.Errorf("allocating port: %w", err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	_ = l.Close()
	return port, nil
}
