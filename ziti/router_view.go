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

package ziti

import (
	"encoding/json"
	"sort"
	"time"

	"github.com/michaelquigley/pfxlog"
	"github.com/openziti/sdk-golang/v2/pb/edge_client_pb"
	"github.com/openziti/sdk-golang/v2/ziti/edge"
)

// RouterView permission values.
const (
	RouterViewPermissionDial = "Dial"
	RouterViewPermissionBind = "Bind"
)

// RouterView is the context's live view of one edge router: connection facts plus, when the
// router is push-subscribed, the services it can satisfy for the identity and its posture
// pass/fail state. Views are independent per router — each router evaluates and pushes its own
// state. Obtain current views with Context.GetRouterViews; EventRouterViewChanged signals
// changes.
type RouterView struct {
	// Id is the edge router's identity id, from the router's certificate identity on the
	// established channel.
	Id string `json:"id"`

	// Name is the edge router's name.
	Name string `json:"name"`

	// Address is the router connection's address. It matches the addr reported by
	// EventRouterConnected / EventRouterDisconnected.
	Address string `json:"address"`

	// Connected is true while the router connection is live. GetRouterViews only returns
	// connected routers; a view delivered by EventRouterViewChanged reports Connected false when
	// the router's view went away with its connection.
	Connected bool `json:"connected"`

	// SupportsPush is true when the router advertised the ServiceSubscriptions capability on the
	// live connection.
	SupportsPush bool `json:"supportsPush"`

	// Subscribed is true while this connection holds an active push subscription.
	Subscribed bool `json:"subscribed"`

	// IsAppView is true for the router whose pushed view backs the context's service cache
	// (the subscribed router at the highest StructuralIndex).
	IsAppView bool `json:"isAppView"`

	// StructuralIndex is the index of the router's last applied service change set; -1 until the
	// router's first snapshot has applied (or when the router is not subscribed).
	StructuralIndex int64 `json:"structuralIndex"`

	// LastActivity is when a dial or bind last used this router.
	LastActivity time.Time `json:"lastActivity"`

	// Services are the services this router can satisfy for the identity, rendered from its
	// pushed state. Nil for a router with no applied snapshot — its per-service view is unknown,
	// as opposed to an empty slice, which means the router pushed an empty set.
	Services []RouterServiceView `json:"services"`
}

// RouterServiceView is one service as a specific edge router can satisfy it, including every
// granting policy and the router's posture pass/fail state for their checks.
type RouterServiceView struct {
	// Id is the service's id.
	Id string `json:"id"`

	// Name is the service's name.
	Name string `json:"name"`

	// EncryptionRequired reports whether the service requires end-to-end encryption.
	EncryptionRequired bool `json:"encryptionRequired"`

	// Permissions holds RouterViewPermissionDial and/or RouterViewPermissionBind, derived from
	// the granting policies' types.
	Permissions []string `json:"permissions"`

	// Configs are the ids of the configs in scope for the identity on this service.
	Configs []string `json:"configs,omitempty"`

	// Config holds the identity-resolved config bodies pushed by the router, keyed by config
	// type name.
	Config map[string]map[string]interface{} `json:"config,omitempty"`

	// Policies are the service policies granting the identity access to this service on this
	// router, each with its posture checks and pass/fail state. Every granting policy is listed,
	// with or without posture checks.
	Policies []RouterPolicyView `json:"policies"`
}

// RouterPolicyView is one service policy granting access, with the router's posture evaluation
// for it.
type RouterPolicyView struct {
	// Id is the service policy's id.
	Id string `json:"id"`

	// Type is the policy's type: RouterViewPermissionDial or RouterViewPermissionBind.
	Type string `json:"type"`

	// IsPassing is the router's pushed pass/fail for the policy; nil until the router has pushed
	// posture state. A policy with no posture checks passes trivially once state arrives.
	IsPassing *bool `json:"isPassing"`

	// PostureChecks are the policy's posture checks with their definitions and pass/fail state.
	// Empty for a policy without posture checks.
	PostureChecks []RouterPostureCheckView `json:"postureChecks"`
}

// RouterPostureCheckView is one posture check's definition vitals and the router's pass/fail
// state for it.
type RouterPostureCheckView struct {
	// Id is the posture check's id.
	Id string `json:"id"`

	// Type is the posture check's type (e.g. MAC, OS, DOMAIN, MFA, PROCESS_MULTI).
	Type string `json:"type"`

	// IsPassing is the router's pushed pass/fail for the check; nil until the router has pushed
	// posture state.
	IsPassing *bool `json:"isPassing"`

	// TimeoutSeconds is the MFA timeout, when the check is an MFA check with a timeout.
	TimeoutSeconds int64 `json:"timeoutSeconds,omitempty"`

	// PromptOnWake and PromptOnUnlock report the MFA re-prompt configuration.
	PromptOnWake   bool `json:"promptOnWake,omitempty"`
	PromptOnUnlock bool `json:"promptOnUnlock,omitempty"`

	// PromptGracePeriodSeconds is the grace period allowed for an MFA re-prompt.
	PromptGracePeriodSeconds int32 `json:"promptGracePeriodSeconds,omitempty"`

	// Semantic is the process-check semantic (e.g. AllOf, AnyOf) for PROCESS_MULTI checks.
	Semantic string `json:"semantic,omitempty"`

	// Processes are the processes a PROCESS_MULTI check requires.
	Processes []RouterPostureCheckProcess `json:"processes,omitempty"`
}

// RouterPostureCheckProcess is one required process of a PROCESS_MULTI posture check.
type RouterPostureCheckProcess struct {
	OsType string `json:"osType"`
	Path   string `json:"path"`
}

// GetRouterViews returns the context's live view of every connected edge router. Absence from
// the result means not connected. Results are ordered by Address. EventRouterViewChanged signals
// changes to any router's view.
func (context *ContextImpl) GetRouterViews() []RouterView {
	result := make([]RouterView, 0, context.routerConnections.Count())
	for tpl := range context.routerConnections.IterBuffered() {
		if tpl.Val.IsClosed() {
			continue
		}
		result = append(result, context.renderRouterView(tpl.Val))
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].Address < result[j].Address
	})
	return result
}

// renderRouterView builds conn's current RouterView from connection facts and the coordinator's
// per-router state. Safe to call with no locks held.
func (context *ContextImpl) renderRouterView(conn edge.RouterConn) RouterView {
	addr := conn.GetRouterAddr()
	view := RouterView{
		Id:              conn.GetRouterId(),
		Name:            conn.GetRouterName(),
		Address:         addr,
		Connected:       !conn.IsClosed(),
		SupportsPush:    conn.IsRouterCapable(edge.RouterCapabilityServiceSubscriptions),
		Subscribed:      context.isRouterSubscribed(addr),
		StructuralIndex: -1,
	}
	if coordinator := context.getSubscriptionCoordinator(); coordinator != nil {
		coordinator.fillRouterView(conn, &view)
	}
	return view
}

// isRouterSubscribed reports whether addr holds a committed push subscription.
func (context *ContextImpl) isRouterSubscribed(addr string) bool {
	context.subscriptionLock.Lock()
	defer context.subscriptionLock.Unlock()
	_, ok := context.subscribedRouters[addr]
	return ok
}

// AddRouterViewChangedListener adds an event listener for the EventRouterViewChanged event and
// returns a function to remove the listener. It is emitted whenever an edge router's view changes
// in any way: its push subscription activates or ends, a pushed service change set applies, or
// its posture pass/fail state updates. The RouterView is the router's complete view after the
// change; replace any previously held copy rather than tracking deltas.
func (context *ContextImpl) AddRouterViewChangedListener(handler func(Context, RouterView)) func() {
	listener := func(args ...interface{}) {
		view, ok := args[0].(RouterView)

		if !ok {
			pfxlog.Logger().Fatalf("could not convert args[0] to %T was %T", view, args[0])
		}

		handler(context, view)
	}

	context.AddListener(EventRouterViewChanged, listener)

	return func() {
		context.RemoveListener(EventRouterViewChanged, listener)
	}
}

// fillRouterView copies the coordinator's per-router state into view: structural index, activity,
// app-view status, and the rendered services with posture pass/fail.
func (c *subscriptionCoordinator) fillRouterView(conn edge.RouterConn, view *RouterView) {
	c.mu.Lock()
	defer c.mu.Unlock()

	sub, ok := c.routers[conn]
	if !ok {
		return
	}
	view.StructuralIndex = sub.structuralIndex
	view.LastActivity = sub.lastActivity
	view.IsAppView = sub == c.appViewRouterLocked()
	if sub.structuralIndex >= 0 {
		view.Services = renderRouterServices(sub)
	}
}

// renderRouterServices builds the router's service views from its pushed structural cache with
// the router's posture pass/fail state, ordered by service name. Caller must hold the
// coordinator lock.
func renderRouterServices(sub *routerSubscription) []RouterServiceView {
	result := make([]RouterServiceView, 0, len(sub.servicesById))
	for _, def := range sub.servicesById {
		result = append(result, renderRouterServiceView(sub, def))
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].Name < result[j].Name
	})
	return result
}

// renderRouterServiceView builds one service's view: identity-resolved configs, every granting
// policy (with or without posture checks), the policies' check definitions, and the router's
// pass/fail overlaid at the policy and check level (nil where no state has been pushed yet).
func renderRouterServiceView(sub *routerSubscription, def *edge_client_pb.ServiceDef) RouterServiceView {
	view := RouterServiceView{
		Id:                 def.Id,
		Name:               def.Name,
		EncryptionRequired: def.EncryptionRequired,
		Configs:            def.Configs,
		Policies:           make([]RouterPolicyView, 0, len(def.PolicyIds)),
	}

	if len(def.ConfigData) > 0 {
		view.Config = map[string]map[string]interface{}{}
		for _, cd := range def.ConfigData {
			var data map[string]interface{}
			if err := json.Unmarshal([]byte(cd.DataJson), &data); err != nil {
				pfxlog.Logger().WithError(err).Errorf("failed to parse config data for service %s type %s", def.Name, cd.TypeName)
				continue
			}
			view.Config[cd.TypeName] = data
		}
	}

	dialAllowed, bindAllowed := false, false
	for _, policyId := range def.PolicyIds {
		policy, ok := sub.policiesById[policyId]
		if !ok {
			continue
		}

		policyView := RouterPolicyView{
			Id:            policyId,
			Type:          RouterViewPermissionDial,
			PostureChecks: make([]RouterPostureCheckView, 0, len(policy.PostureCheckIds)),
		}
		if policy.Type == edge_client_pb.PolicyType_Bind {
			policyView.Type = RouterViewPermissionBind
			bindAllowed = true
		} else {
			dialAllowed = true
		}
		if passing, ok := sub.policyStates[policyId]; ok {
			p := passing
			policyView.IsPassing = &p
		}

		for _, checkId := range policy.PostureCheckIds {
			policyView.PostureChecks = append(policyView.PostureChecks, renderRouterPostureCheckView(sub, checkId))
		}
		sort.Slice(policyView.PostureChecks, func(i, j int) bool {
			return policyView.PostureChecks[i].Id < policyView.PostureChecks[j].Id
		})

		view.Policies = append(view.Policies, policyView)
	}
	sort.Slice(view.Policies, func(i, j int) bool {
		return view.Policies[i].Id < view.Policies[j].Id
	})

	if dialAllowed {
		view.Permissions = append(view.Permissions, RouterViewPermissionDial)
	}
	if bindAllowed {
		view.Permissions = append(view.Permissions, RouterViewPermissionBind)
	}

	return view
}

// renderRouterPostureCheckView builds one posture check's view from its pushed definition and the
// router's pass/fail state. A check id with no cached definition (should not occur — envelopes
// carry reference closure) renders id-only.
func renderRouterPostureCheckView(sub *routerSubscription, checkId string) RouterPostureCheckView {
	view := RouterPostureCheckView{
		Id: checkId,
	}
	if passing, ok := sub.checkStates[checkId]; ok {
		p := passing
		view.IsPassing = &p
	}

	check, ok := sub.postureChecksById[checkId]
	if !ok {
		return view
	}

	view.Type = check.Type
	view.TimeoutSeconds = check.TimeoutSeconds
	view.PromptOnWake = check.PromptOnWake
	view.PromptOnUnlock = check.PromptOnUnlock
	view.PromptGracePeriodSeconds = check.PromptGracePeriodSeconds
	view.Semantic = check.Semantic
	for _, p := range check.Processes {
		view.Processes = append(view.Processes, RouterPostureCheckProcess{
			OsType: p.OsType,
			Path:   p.Path,
		})
	}
	return view
}

// requestViewChange schedules an EventRouterViewChanged emission for conn on the view worker.
// Callers may hold coordinator or subscription locks; the render and emit run with none of them
// held, because listeners may re-enter the SDK (dial, subscribe, evaluate posture).
func (c *subscriptionCoordinator) requestViewChange(conn edge.RouterConn) {
	if c.ctx == nil || c.ctx.EventEmmiter == nil {
		return
	}
	c.viewChangeMu.Lock()
	c.viewChangePending[conn] = struct{}{}
	c.viewChangeMu.Unlock()

	select {
	case c.viewChangeSignal <- struct{}{}:
	default: // a wake-up is already pending and will observe this change
	}
}

// viewChangeLoop drains view-change requests until the owning context closes, rendering each
// pending router's view fresh at emit time. Coalescing intermediate states is correct: the
// payload is a full replacement.
func (c *subscriptionCoordinator) viewChangeLoop(closeNotify <-chan struct{}) {
	for {
		select {
		case <-c.viewChangeSignal:
			c.viewChangeMu.Lock()
			pending := c.viewChangePending
			c.viewChangePending = map[edge.RouterConn]struct{}{}
			c.viewChangeMu.Unlock()

			for conn := range pending {
				c.ctx.Emit(EventRouterViewChanged, c.ctx.renderRouterView(conn))
			}
		case <-closeNotify:
			return
		}
	}
}
