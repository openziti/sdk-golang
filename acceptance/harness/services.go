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
func (h *Harness) CreateService(t testing.TB, base string) *Service {
	t.Helper()
	name := uniqueName(t, base)
	h.Cli(t, "edge", "create", "service", name)
	t.Cleanup(func() {
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
func (p *Policy) Delete(t testing.TB) {
	t.Helper()
	p.h.Cli(t, "edge", "delete", p.kind, p.name)
}

// GrantDial creates a Dial service policy granting the identities access to svc
// and returns a handle for revoking it. Per the isolation contract the policy
// targets the named entities explicitly, never #all or shared attributes.
func (h *Harness) GrantDial(t testing.TB, svc *Service, ids ...*Identity) *Policy {
	t.Helper()
	return h.createServicePolicy(t, "Dial", svc, ids)
}

// GrantBind creates a Bind service policy granting the identities hosting access
// to svc, targeting the named entities explicitly, and returns a handle for
// revoking it.
func (h *Harness) GrantBind(t testing.TB, svc *Service, ids ...*Identity) *Policy {
	t.Helper()
	return h.createServicePolicy(t, "Bind", svc, ids)
}

func (h *Harness) createServicePolicy(t testing.TB, polType string, svc *Service, ids []*Identity) *Policy {
	t.Helper()
	name := uniqueName(t, strings.ToLower(polType))
	h.Cli(t, "edge", "create", "service-policy", name, polType,
		"--service-roles", "@"+svc.Name(),
		"--identity-roles", identityRoles(ids))
	t.Cleanup(func() {
		_, _ = h.cli.Run(context.Background(), "edge", "delete", "service-policy", name)
	})
	return &Policy{h: h, kind: "service-policy", name: name}
}

// GrantRouterAccess creates an edge-router policy letting the identities use the
// router, targeting both sides by name.
func (h *Harness) GrantRouterAccess(t testing.TB, r *Router, ids ...*Identity) {
	t.Helper()
	name := uniqueName(t, "erp")
	h.Cli(t, "edge", "create", "edge-router-policy", name,
		"--edge-router-roles", "@"+r.Name(),
		"--identity-roles", identityRoles(ids))
	t.Cleanup(func() {
		_, _ = h.cli.Run(context.Background(), "edge", "delete", "edge-router-policy", name)
	})
}

// GrantServiceRouterAccess creates a service-edge-router policy letting svc's
// traffic transit the router, targeting both sides by name.
func (h *Harness) GrantServiceRouterAccess(t testing.TB, svc *Service, r *Router) {
	t.Helper()
	name := uniqueName(t, "serp")
	h.Cli(t, "edge", "create", "service-edge-router-policy", name,
		"--service-roles", "@"+svc.Name(),
		"--edge-router-roles", "@"+r.Name())
	t.Cleanup(func() {
		_, _ = h.cli.Run(context.Background(), "edge", "delete", "service-edge-router-policy", name)
	})
}

func identityRoles(ids []*Identity) string {
	roles := make([]string, len(ids))
	for i, id := range ids {
		roles[i] = "@" + id.Name()
	}
	return strings.Join(roles, ",")
}
