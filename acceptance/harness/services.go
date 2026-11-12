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
	"strings"
	"testing"
)

// Service is a created service.
type Service struct {
	name string
}

// Name returns the service's unique name on the controller.
func (s *Service) Name() string {
	return s.name
}

// CreateService creates a service via the versioned CLI, uniquely named per the
// isolation contract, with best-effort cleanup.
func (h *Harness) CreateService(tb testing.TB, base string) *Service {
	tb.Helper()
	return h.CreateServiceWithConfigs(tb, base)
}

// CreateServiceWithConfigs creates a service associated with the given config
// names (e.g. an intercept.v1 config for intercept-style dialing), uniquely
// named with best-effort cleanup.
func (h *Harness) CreateServiceWithConfigs(tb testing.TB, base string, configs ...string) *Service {
	tb.Helper()
	name := uniqueName(tb, base)
	args := []string{"edge", "create", "service", name}
	if len(configs) > 0 {
		args = append(args, "--configs", strings.Join(configs, ","))
	}
	h.Cli(tb, args...)
	tb.Cleanup(func() {
		_, _ = h.cli.Run(context.Background(), "edge", "delete", "service", name)
	})
	return &Service{name: name}
}

// Policy is a created policy. Beyond its automatic best-effort cleanup it can be
// deleted mid-test, e.g. to revoke access and observe the SDK react.
type Policy struct {
	h    *Harness
	kind string
	name string
}

// Name returns the policy's unique name on the controller.
func (p *Policy) Name() string { return p.name }

// Delete removes the policy now (in addition to the automatic cleanup), failing
// the test on error. Used to revoke access during a test.
func (p *Policy) Delete(tb testing.TB) {
	tb.Helper()
	p.h.Cli(tb, "edge", "delete", p.kind, p.name)
}

// CreateConfig creates a config of the given type with the given JSON value,
// uniquely named with best-effort cleanup, and returns its name. The config
// types it references (e.g. intercept.v1) are created by the controller
// quickstart bootstrap.
func (h *Harness) CreateConfig(tb testing.TB, base, configType, jsonValue string) string {
	tb.Helper()
	name := uniqueName(tb, base)
	h.Cli(tb, "edge", "create", "config", name, configType, jsonValue)
	tb.Cleanup(func() {
		_, _ = h.cli.Run(context.Background(), "edge", "delete", "config", name)
	})
	return name
}

// GrantDial creates a Dial service policy granting the identities access to svc
// and returns a handle for revoking it. Per the isolation contract the policy
// targets the named entities explicitly, never #all or shared attributes.
func (h *Harness) GrantDial(tb testing.TB, svc *Service, ids ...NamedEntity) *Policy {
	tb.Helper()
	return h.createServicePolicy(tb, "Dial", svc, ids)
}

// GrantBind creates a Bind service policy granting the identities hosting access
// to svc, targeting the named entities explicitly, and returns a handle for
// revoking it.
func (h *Harness) GrantBind(tb testing.TB, svc *Service, ids ...NamedEntity) *Policy {
	tb.Helper()
	return h.createServicePolicy(tb, "Bind", svc, ids)
}

func (h *Harness) createServicePolicy(tb testing.TB, polType string, svc *Service, ids []NamedEntity) *Policy {
	tb.Helper()
	name := uniqueName(tb, strings.ToLower(polType))
	h.Cli(tb, "edge", "create", "service-policy", name, polType,
		"--service-roles", "@"+svc.Name(),
		"--identity-roles", identityRoles(ids))
	tb.Cleanup(func() {
		_, _ = h.cli.Run(context.Background(), "edge", "delete", "service-policy", name)
	})
	return &Policy{h: h, kind: "service-policy", name: name}
}

// GrantRouterAccess creates an edge-router policy letting the identities use the
// router, targeting both sides by name.
func (h *Harness) GrantRouterAccess(tb testing.TB, r *Router, ids ...NamedEntity) {
	tb.Helper()
	name := uniqueName(tb, "erp")
	h.Cli(tb, "edge", "create", "edge-router-policy", name,
		"--edge-router-roles", "@"+r.Name(),
		"--identity-roles", identityRoles(ids))
	tb.Cleanup(func() {
		_, _ = h.cli.Run(context.Background(), "edge", "delete", "edge-router-policy", name)
	})
}

// GrantServiceRouterAccess creates a service-edge-router policy letting svc's
// traffic transit the router, targeting both sides by name.
func (h *Harness) GrantServiceRouterAccess(tb testing.TB, svc *Service, r *Router) {
	tb.Helper()
	name := uniqueName(tb, "serp")
	h.Cli(tb, "edge", "create", "service-edge-router-policy", name,
		"--service-roles", "@"+svc.Name(),
		"--edge-router-roles", "@"+r.Name())
	tb.Cleanup(func() {
		_, _ = h.cli.Run(context.Background(), "edge", "delete", "service-edge-router-policy", name)
	})
}

func identityRoles(ids []NamedEntity) string {
	roles := make([]string, len(ids))
	for i, id := range ids {
		roles[i] = "@" + id.Name()
	}
	return strings.Join(roles, ",")
}
