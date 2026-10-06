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

// e2ee-tls-fips hosts and dials an echo service with the tls end-to-end encryption method, and
// reports whether Go's FIPS 140-3 module is on. Build it with GOFIPS140=v1.0.0 and run it with
// GODEBUG=fips140=only to have non-approved crypto fail.
//
//	e2ee-tls-fips fips
//	e2ee-tls-fips host -identity host.json -service echo
//	e2ee-tls-fips dial -identity dialer.json -service echo -size 100000
//	e2ee-tls-fips both -identity id.json -service echo
package main

import (
	"bytes"
	"crypto/ecdh"
	"crypto/fips140"
	"crypto/rand"
	"crypto/sha256"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime/debug"
	"strings"
	"time"

	"github.com/openziti/sdk-golang/v2/ziti"
	"github.com/openziti/sdk-golang/v2/ziti/edge"
	"github.com/sirupsen/logrus"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	mode := os.Args[1]

	flags := flag.NewFlagSet(mode, flag.ExitOnError)
	identityFile := flags.String("identity", "", "identity file")
	service := flags.String("service", "", "service to host or dial")
	size := flags.Int("size", 64*1024+1, "bytes the dialer sends and expects echoed back")
	count := flags.Int("count", 3, "dials the dialer makes")
	method := flags.String("method", "tls", "e2ee method: tls or libsodium")
	forceV1 := flags.Bool("v1", false, "dial with Connect V1 instead of ConnectV2")
	sdkFlowControl := flags.Bool("sdk-flow-control", false, "with -v1, ask for sdk flow control (xgress) instead of legacy")
	_ = flags.Parse(os.Args[2:])

	reportFips()

	switch mode {
	case "fips":
		if !checkEnforcement() {
			os.Exit(1)
		}
		return
	case "host", "dial", "both":
		if *identityFile == "" || *service == "" {
			usage()
		}
	default:
		usage()
	}

	ctx := newContext(*identityFile, *method)
	defer ctx.Close()

	switch mode {
	case "host":
		host(ctx, *service, nil)
	case "dial":
		dial(ctx, *service, *size, *count, *forceV1, *sdkFlowControl)
	case "both":
		ready := make(chan struct{})
		go host(ctx, *service, ready)
		<-ready
		dial(ctx, *service, *size, *count, *forceV1, *sdkFlowControl)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: e2ee-tls-fips fips|host|dial|both [-identity file] [-service name] [-size n] [-count n]")
	os.Exit(2)
}

// reportFips logs what the binary was built with and whether the FIPS module is on right now.
func reportFips() {
	var gofips, godebug string
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, s := range info.Settings {
			switch s.Key {
			case "GOFIPS140":
				gofips = s.Value
			case "DefaultGODEBUG":
				godebug = s.Value
			}
		}
	}
	logrus.Infof("build GOFIPS140=%q DefaultGODEBUG=%q", gofips, godebug)
	logrus.Infof("runtime GODEBUG=%q", os.Getenv("GODEBUG"))
	logrus.Infof("crypto/fips140.Enabled()=%v", fips140.Enabled())
}

// checkEnforcement makes one approved and one non-approved call. Under GODEBUG=fips140=only the
// non-approved one must fail.
func checkEnforcement() bool {
	sum := sha256.Sum256([]byte("approved"))
	logrus.Infof("approved: sha256 ok (%x...)", sum[:4])

	err := func() (err error) {
		defer func() {
			if r := recover(); r != nil {
				err = fmt.Errorf("panic: %v", r)
			}
		}()
		_, err = ecdh.X25519().GenerateKey(rand.Reader)
		return err
	}()

	only := strings.Contains(os.Getenv("GODEBUG"), "fips140=only")
	switch {
	case err != nil && only:
		logrus.Infof("enforcement: non-approved X25519 key generation failed as required: %v", err)
		return true
	case err != nil:
		logrus.Errorf("non-approved X25519 key generation failed without fips140=only: %v", err)
		return false
	case only:
		logrus.Error("enforcement: non-approved X25519 key generation succeeded under fips140=only")
		return false
	default:
		logrus.Info("non-approved X25519 key generation succeeded (fips140=only not set)")
		return true
	}
}

func newContext(identityFile, method string) ziti.Context {
	cfg, err := ziti.NewConfigFromFile(identityFile)
	if err != nil {
		logrus.WithError(err).Fatal("unable to load identity")
	}
	opts := *ziti.DefaultOptions
	if method == "tls" {
		opts.E2EEMethod = edge.CryptoMethodTLS
	}
	logrus.Infof("e2ee method %s", opts.E2EEMethod)
	ctx, err := ziti.NewContextWithOpts(cfg, &opts)
	if err != nil {
		logrus.WithError(err).Fatal("unable to create context")
	}
	if err = ctx.Authenticate(); err != nil {
		logrus.WithError(err).Fatal("unable to authenticate")
	}
	return ctx
}

func host(ctx ziti.Context, service string, ready chan struct{}) {
	listenOpts := ziti.DefaultListenOptions()
	listenOpts.WaitForNEstablishedListeners = 1
	listener, err := ctx.ListenWithOptions(service, listenOpts)
	if err != nil {
		logrus.WithError(err).Fatal("unable to host service")
	}
	logrus.Infof("hosting %s", service)
	if ready != nil {
		close(ready)
	}

	for {
		conn, err := listener.AcceptEdge()
		if err != nil {
			logrus.WithError(err).Error("accept failed")
			return
		}
		go func() {
			defer func() { _ = conn.Close() }()
			n, err := io.Copy(conn, conn)
			logrus.WithError(err).Infof("host: echoed %d bytes, state %s", n, conn.GetState())
		}()
	}
}

func dial(ctx ziti.Context, service string, size, count int, forceV1, sdkFlowControl bool) {
	failed := false
	for i := 0; i < count; i++ {
		if err := dialOnce(ctx, service, size, forceV1, sdkFlowControl); err != nil {
			logrus.WithError(err).Errorf("dial %d failed", i+1)
			failed = true
		}
	}
	if failed {
		os.Exit(1)
	}
	logrus.Infof("PASS: %d dials echoed %d bytes each", count, size)
}

func dialOnce(ctx ziti.Context, service string, size int, forceV1, sdkFlowControl bool) error {
	conn, err := ctx.DialWithOptions(service, &ziti.DialOptions{
		ConnectTimeout: 10 * time.Second,
		ForceConnectV1: &forceV1,
		SdkFlowControl: &sdkFlowControl,
	})
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()

	payload := make([]byte, size)
	if _, err = rand.Read(payload); err != nil {
		return err
	}

	errC := make(chan error, 1)
	go func() {
		_, err := conn.Write(payload)
		if err == nil {
			err = conn.CloseWrite()
		}
		errC <- err
	}()

	got := make([]byte, 0, size)
	buf := make([]byte, 32*1024)
	for len(got) < size {
		_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
		n, err := conn.Read(buf)
		got = append(got, buf[:n]...)
		if err != nil {
			return fmt.Errorf("read after %d of %d bytes: %w", len(got), size, err)
		}
	}
	if err = <-errC; err != nil {
		return err
	}
	if !bytes.Equal(payload, got) {
		return fmt.Errorf("echo mismatch")
	}
	logrus.Infof("dial: echoed %d bytes, state %s", size, conn.GetState())
	return nil
}
