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

//go:build acceptance

// Package tests holds the acceptance test suite. The whole package shares one
// environment (a controller and the default edge router), brought up once in
// TestMain, per the design's Layer 5 model. Tests follow the isolation contract:
// uniquely named resources, policies targeting only their own entities, serial
// execution. Tests that stop, kill, or restart components must use their own
// environment via harness.Start, never the shared one.
package tests

import (
	"fmt"
	"os"
	"testing"

	"github.com/openziti/sdk-golang/acceptance/harness"
)

// shared is the package-wide environment, valid between TestMain's setup and
// teardown.
var shared *harness.Harness

func TestMain(m *testing.M) {
	h, teardown, err := harness.StartShared()
	if err != nil {
		fmt.Fprintf(os.Stderr, "starting shared acceptance environment: %v\n", err)
		os.Exit(1)
	}
	shared = h

	code := m.Run()
	teardown()
	os.Exit(code)
}
