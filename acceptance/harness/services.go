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
	return h.CreateServiceWithConfigs(t, base)
}

// CreateServiceWithConfigs creates a service associated with the given config
// names (e.g. an intercept.v1 config for intercept-style dialing), uniquely
// named with best-effort cleanup.
func (h *Harness) CreateServiceWithConfigs(t testing.TB, base string, configs ...string) *Service {
	t.Helper()
	name := uniqueName(t, base)
	args := []string{"edge", "create", "service", name}
	if len(configs) > 0 {
		args = append(args, "--configs", strings.Join(configs, ","))
	}
	h.Cli(t, args...)
	t.Cleanup(func() {
		_, _ = h.cli.Run(context.Background(), "edge", "delete", "service", name)
	})
	return &Service{name: name}
}

// CreateConfig creates a config of the given type with the given JSON value,
// uniquely named with best-effort cleanup, and returns its name. The config
// types it references (e.g. intercept.v1) are created by the controller
// quickstart bootstrap.
func (h *Harness) CreateConfig(t testing.TB, base, configType, jsonValue string) string {
	t.Helper()
	name := uniqueName(t, base)
	h.Cli(t, "edge", "create", "config", name, configType, jsonValue)
	t.Cleanup(func() {
		_, _ = h.cli.Run(context.Background(), "edge", "delete", "config", name)
	})
	return name
}

// GrantDial creates a Dial service policy granting the identities access to svc.
// Per the isolation contract the policy targets the named entities explicitly,
// never #all or shared attributes.
func (h *Harness) GrantDial(t testing.TB, svc *Service, ids ...*Identity) {
	t.Helper()
	h.createServicePolicy(t, "Dial", svc, ids)
}

// GrantBind creates a Bind service policy granting the identities hosting access
// to svc, targeting the named entities explicitly.
func (h *Harness) GrantBind(t testing.TB, svc *Service, ids ...*Identity) {
	t.Helper()
	h.createServicePolicy(t, "Bind", svc, ids)
}

func (h *Harness) createServicePolicy(t testing.TB, polType string, svc *Service, ids []*Identity) {
	t.Helper()
	name := uniqueName(t, strings.ToLower(polType))
	h.Cli(t, "edge", "create", "service-policy", name, polType,
		"--service-roles", "@"+svc.Name(),
		"--identity-roles", identityRoles(ids))
	t.Cleanup(func() {
		_, _ = h.cli.Run(context.Background(), "edge", "delete", "service-policy", name)
	})
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
