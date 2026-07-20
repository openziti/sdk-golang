/*
	Copyright 2019 NetFoundry Inc.

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

package posture

import (
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/go-openapi/runtime"
	"github.com/michaelquigley/pfxlog"
	"github.com/openziti/edge-api/rest_model"
	"github.com/openziti/foundation/v2/stringz"
	"github.com/openziti/sdk-golang/v2/edge-apis"
	"github.com/openziti/sdk-golang/v2/ziti/edge"
	cmap "github.com/orcaman/concurrent-map/v2"
)

const (
	// TotpAttemptDelta defines how far in advance of expiration the cache proactively requests
	// new TOTP tokens, ensuring tokens remain valid during authentication flows.
	TotpAttemptDelta = 5 * time.Minute

	// TotpPostureCheckNoTimeout indicates that a TOTP posture check does not expire and
	// does not require periodic token refresh.
	TotpPostureCheckNoTimeout = int64(-1)
)

// CacheData holds the current snapshot of device posture information including running processes,
// network configuration, operating system details, and authentication state.
type CacheData struct {
	Processes    cmap.ConcurrentMap[string, ProcessInfo] // map[processPath]ProcessInfo
	MacAddresses []string
	Os           OsInfo
	Domain       string
	TotpToken    edge_apis.TotpTokenResult
	OnWake       WakeEvent
	OnUnlock     UnlockEvent
	Index        uint64
	Responses    []rest_model.PostureResponseCreate
}

// NewCacheData creates an empty posture cache snapshot with initialized collections.
func NewCacheData() *CacheData {
	return &CacheData{
		Processes:    cmap.New[ProcessInfo](),
		MacAddresses: []string{},
		Os: OsInfo{
			Type:    "",
			Version: "",
		},
		Domain: "",
		Index:  0,
	}
}

// ActiveServiceProvider supplies information about services currently in use by the client,
// enabling the cache to determine which posture checks are relevant.
type ActiveServiceProvider interface {
	GetActiveDialServices() []*rest_model.ServiceDetail
	GetActiveBindServices() []*rest_model.ServiceDetail
}

// ActiveServiceProviderFunc is a function adapter that implements ActiveServiceProvider
// for both dial and bind service queries.
type ActiveServiceProviderFunc func() []*rest_model.ServiceDetail

func (f ActiveServiceProviderFunc) GetActiveDialServices() []*rest_model.ServiceDetail {
	return f()
}

// Cache manages device posture data collection, tracking changes over time and coordinating
// submission of posture responses when device state changes or policies require updates.
type Cache struct {
	currentData  *CacheData
	previousData *CacheData

	watchedProcesses cmap.ConcurrentMap[string, string] //map[processPath]queryId

	serviceProvider ActiveServiceProvider

	lastSent  cmap.ConcurrentMap[string, time.Time] //map[type|processQueryId]time.Time
	submitter Submitter

	// Per-router submission wiring (see EnablePerRouterSubmission). All nil/empty when the cache
	// runs in the legacy broadcast mode.
	apiSessionProvider      ApiSessionProvider
	routerConnProvider      RouterConnectionProvider
	routerQueryInfoProvider RouterQueryInfoProvider
	controllerSubmitter     Submitter

	// connBaselines records, per router connection, the posture data that connection was last
	// successfully sent, restricted to the fields its requirements covered. Guarded by lock.
	connBaselines map[edge.RouterConn]*CacheData

	startOnce           sync.Once
	doSingleSubmissions bool
	closeNotify         <-chan struct{}

	DomainProvider    DomainProvider
	MacProvider       MacProvider
	OsProvider        OsProvider
	ProcessProvider   ProcessProvider
	TotpTokenProvider edge_apis.TotpTokenProvider

	lock        sync.Mutex
	totpTimeout int64
	eventState  EventState
}

// NewCache creates a posture cache that monitors device state and coordinates posture response
// submission. The cache uses the provided service provider to determine which posture checks
// are active, the submitter to send responses, and the token provider for TOTP authentication.
func NewCache(activeServiceProvider ActiveServiceProvider, submitter Submitter, totpTokenProvider edge_apis.TotpTokenProvider, closeNotify <-chan struct{}) *Cache {
	cache := &Cache{
		currentData:      NewCacheData(),
		previousData:     NewCacheData(),
		watchedProcesses: cmap.New[string](),
		serviceProvider:  activeServiceProvider,
		lastSent:         cmap.New[time.Time](),
		submitter:        submitter,
		connBaselines:    map[edge.RouterConn]*CacheData{},
		startOnce:        sync.Once{},
		closeNotify:      closeNotify,
		totpTimeout:      TotpPostureCheckNoTimeout,

		TotpTokenProvider: totpTokenProvider,
		DomainProvider:    NewDomainProvider(),
		MacProvider:       NewMacProvider(),
		OsProvider:        NewOsProvider(),
		ProcessProvider:   NewProcessProvider(),

		eventState: NewEventState(),
	}

	cache.currentData.Index = 1

	cache.start()

	return cache
}

// EnablePerRouterSubmission switches the cache from broadcast submission (every posture-capable
// router receives every response through the submitter) to per-router submission: each
// posture-capable router connection receives only the responses its own required checks cover
// (per the RouterQueryInfoProvider, falling back to the globally-derived requirements), diffed
// against what that connection was last successfully sent. Legacy API sessions are unaffected and
// keep the broadcast path. controller is the destination for responses that must fall back to the
// controller because a posture-capable-less connection exists.
//
// Call once at construction time, before the cache is shared across goroutines.
func (cache *Cache) EnablePerRouterSubmission(apiSessions ApiSessionProvider, conns RouterConnectionProvider, requirements RouterQueryInfoProvider, controller Submitter) {
	cache.apiSessionProvider = apiSessions
	cache.routerConnProvider = conns
	cache.routerQueryInfoProvider = requirements
	cache.controllerSubmitter = controller
}

// postureDestination is one router connection to submit to and, when the SDK holds per-router
// state for it, the posture requirements derived from that router's pushed state. A nil info means
// "use the globally-derived requirements".
type postureDestination struct {
	conn edge.RouterConn
	info *QueryInfo
}

// destinationSet is the resolved submission plan for one evaluation pass.
type destinationSet struct {
	conns []postureDestination
	// anyIncapable is true when at least one open router connection cannot accept posture data,
	// requiring the controller fallback for the globally-changed responses.
	anyIncapable bool
}

// gatherDestinations resolves this pass's per-router submission plan, or nil when the legacy
// broadcast path applies (per-router mode not enabled, no API session yet, or a legacy session).
//
// It MUST run before cache.lock is taken: the router query-info provider acquires the subscription
// coordinator's lock, and a goroutine already holding that lock can re-enter posture evaluation
// through service-change event listeners — so the provider is never called under cache.lock.
func (cache *Cache) gatherDestinations() *destinationSet {
	if cache.apiSessionProvider == nil || cache.routerConnProvider == nil {
		return nil
	}

	apiSession := cache.apiSessionProvider.GetCurrentApiSession()
	if apiSession == nil || apiSession.GetType() == edge_apis.ApiSessionTypeLegacy {
		return nil
	}

	set := &destinationSet{}
	for _, conn := range cache.routerConnProvider.GetRouterConnections() {
		if conn.IsClosed() {
			continue
		}
		if !conn.IsRouterCapable(edge.RouterCapabilityPostureChecks) && !conn.GetBoolHeader(edge.SupportsPostureChecksHeader) {
			set.anyIncapable = true
			continue
		}
		var info *QueryInfo
		if cache.routerQueryInfoProvider != nil {
			if routerInfo, ok := cache.routerQueryInfoProvider.GetRouterPostureQueryInfo(conn); ok {
				info = routerInfo
			}
		}
		set.conns = append(set.conns, postureDestination{conn: conn, info: info})
	}
	return set
}

// Evaluate refreshes all posture data and determines if new posture responses should be sent out
func (cache *Cache) Evaluate() {
	destinations := cache.gatherDestinations()

	cache.lock.Lock()
	defer cache.lock.Unlock()

	activeDialServices := cache.serviceProvider.GetActiveDialServices()
	activeBindServices := cache.serviceProvider.GetActiveBindServices()
	globalInfo := GetQueryInfo(activeDialServices, activeBindServices)

	// Collection covers the union of every destination's requirements, so per-router data (e.g. a
	// process watched only by one router's checks) is gathered even when the global view lacks it.
	unionInfo := globalInfo
	if destinations != nil {
		unionInfo = globalInfo.clone()
		for _, dest := range destinations.conns {
			if dest.info != nil {
				unionInfo.merge(dest.info)
			}
		}
	}

	cache.setTotpTimeout(unionInfo.TotpTimeout)

	candidateData := cache.collectCandidate(unionInfo)
	if candidateData == nil {
		return
	}

	// The wake/unlock one-shots live on currentData (set by event listeners), never on a candidate
	// or per-connection baseline; compute them once for every destination this pass.
	wakeChanged := !cache.currentData.OnWake.At.Equal(candidateData.OnWake.At)
	unlockChanged := !cache.currentData.OnUnlock.At.Equal(candidateData.OnUnlock.At)

	globalChanged := getChangedResponses(cache.currentData, candidateData, globalInfo, wakeChanged, unlockChanged)

	if destinations == nil {
		if len(globalChanged) > 0 {
			cache.previousData = cache.currentData
			cache.currentData = candidateData
			cache.currentData.Responses = globalChanged

			if err := cache.SendResponses(globalChanged); err != nil {
				pfxlog.Logger().Error(err)
			}
		}
		return
	}

	anySent := cache.submitPerRouter(destinations, candidateData, globalInfo, wakeChanged, unlockChanged)

	if destinations.anyIncapable && len(globalChanged) > 0 {
		legacyResponses := filterToLegacyPostureResponses(globalChanged)
		if len(legacyResponses) > 0 {
			for _, err := range cache.sendResponsesVia(cache.controllerSubmitter, legacyResponses) {
				pfxlog.Logger().Error(err)
			}
		}
	}

	// currentData remains the baseline for the global diff and the TOTP bookkeeping. Commit on the
	// global change as before, and additionally when any per-router delta was sent or a fresh TOTP
	// token was fetched: a wake/unlock one-shot or token relevant only to a router's per-connection
	// requirements must not be re-sent (or re-fetched) on every pass because the global view alone
	// never commits it.
	if len(globalChanged) > 0 || anySent || cache.currentData.TotpToken.Token != candidateData.TotpToken.Token {
		cache.previousData = cache.currentData
		cache.currentData = candidateData
		cache.currentData.Responses = globalChanged
	}
}

// submitPerRouter sends each destination the responses its requirements cover, diffed against
// that connection's baseline, returning whether any send succeeded. A connection with no baseline
// (newly connected or newly relevant) receives its full relevant current state. Baselines commit
// only on a successful send, so a failed send retries on the next pass. Caller holds cache.lock.
func (cache *Cache) submitPerRouter(destinations *destinationSet, candidateData *CacheData, globalInfo *QueryInfo, wakeChanged, unlockChanged bool) bool {
	anySent := false
	seen := map[edge.RouterConn]struct{}{}
	for _, dest := range destinations.conns {
		seen[dest.conn] = struct{}{}

		info := dest.info
		if info == nil {
			info = globalInfo
		}

		baseline := cache.connBaselines[dest.conn]
		if baseline == nil {
			baseline = NewCacheData()
		}

		responses := getChangedResponses(baseline, candidateData, info, wakeChanged, unlockChanged)
		if len(responses) == 0 {
			continue
		}

		if err := dest.conn.SendPosture(responses); err != nil {
			pfxlog.Logger().WithError(err).Errorf("failed to send posture responses to router [%s]", dest.conn.GetRouterName())
			continue
		}

		anySent = true
		cache.commitConnBaseline(dest.conn, baseline, candidateData, info)
	}

	for conn := range cache.connBaselines {
		if _, stillPresent := seen[conn]; !stillPresent || conn.IsClosed() {
			delete(cache.connBaselines, conn)
		}
	}

	return anySent
}

// commitConnBaseline records what conn has now been told, copying only the fields covered by info,
// so data that becomes relevant to this connection later still diffs against its zero value and is
// sent then. Caller holds cache.lock.
func (cache *Cache) commitConnBaseline(conn edge.RouterConn, baseline, candidateData *CacheData, info *QueryInfo) {
	if _, ok := info.QueryTypes[string(rest_model.PostureCheckTypeMFA)]; ok {
		baseline.TotpToken = candidateData.TotpToken
	}
	if _, ok := info.QueryTypes[string(rest_model.PostureCheckTypeDOMAIN)]; ok {
		baseline.Domain = candidateData.Domain
	}
	if _, ok := info.QueryTypes[string(rest_model.PostureCheckTypeMAC)]; ok {
		baseline.MacAddresses = candidateData.MacAddresses
	}
	if _, ok := info.QueryTypes[string(rest_model.PostureCheckTypeOS)]; ok {
		baseline.Os = candidateData.Os
	}
	for path := range info.Processes {
		if processInfo, ok := candidateData.Processes.Get(path); ok {
			baseline.Processes.Set(path, processInfo)
		}
	}
	cache.connBaselines[conn] = baseline
}

// collectCandidate gathers current device posture data for the given requirements: OS, domain,
// MAC addresses, the watched processes, and — when the MFA timeout window has been entered — a
// fresh TOTP token. Returns nil if the cache is closed while waiting on a TOTP token. Caller holds
// cache.lock.
func (cache *Cache) collectCandidate(info *QueryInfo) *CacheData {
	candidateData := NewCacheData()
	candidateData.Index = cache.currentData.Index + 1

	candidateData.Os = cache.OsProvider.GetOsInfo()
	candidateData.Domain = cache.DomainProvider.GetDomain()
	candidateData.MacAddresses = sanitizeMacAddresses(cache.MacProvider.GetMacAddresses())

	for processPath, queryId := range info.Processes {
		processInfo := cache.ProcessProvider.GetProcessInfo(processPath)
		processInfo.QueryId = queryId
		candidateData.Processes.Set(processPath, processInfo)
	}

	candidateData.TotpToken = cache.previousData.TotpToken

	if cache.TotpTokenProvider != nil && cache.totpTimeoutWindowEntered() {
		totpTokenResultCh := cache.TotpTokenProvider.Request()

		if totpTokenResultCh != nil {
			select {
			case totpTokenResult := <-totpTokenResultCh:
				if totpTokenResult.Err != nil {
					pfxlog.Logger().Errorf("error requesting totp token: %v", totpTokenResult.Err)
				} else {
					candidateData.TotpToken = totpTokenResult
				}
			case <-cache.closeNotify:
				return nil
			}
		}
	}

	return candidateData
}

func getActiveQueryInfo(dialServices []*rest_model.ServiceDetail, bindServices []*rest_model.ServiceDetail) (map[string]string, map[string]string, int64) {
	activeQueryTypes := map[string]string{} // map[queryType]->queryId'
	activeProcesses := map[string]string{}  // map[processPath]->queryId'

	lowestTotpTimeout := TotpPostureCheckNoTimeout
	for _, service := range dialServices {
		for _, postureQueryState := range service.PostureQueries {
			if postureQueryState.PolicyType == rest_model.DialBindDial {
				addQueryInfoToMaps(activeQueryTypes, activeProcesses, postureQueryState)
				lowestTotpTimeout = getLowestTotpTimeout(postureQueryState, lowestTotpTimeout)
			}
		}
	}

	for _, service := range bindServices {
		for _, postureQueryState := range service.PostureQueries {
			if postureQueryState.PolicyType == rest_model.DialBindBind {
				addQueryInfoToMaps(activeQueryTypes, activeProcesses, postureQueryState)
				lowestTotpTimeout = getLowestTotpTimeout(postureQueryState, lowestTotpTimeout)
			}
		}
	}

	return activeQueryTypes, activeProcesses, lowestTotpTimeout
}

func getLowestTotpTimeout(postureQueryState *rest_model.PostureQueries, curTimeout int64) int64 {
	for _, query := range postureQueryState.PostureQueries {

		if *query.QueryType == rest_model.PostureCheckTypeMFA {
			if curTimeout == TotpPostureCheckNoTimeout && query.Timeout != nil && *query.Timeout != TotpPostureCheckNoTimeout {
				curTimeout = *query.Timeout
			} else if query.Timeout != nil && *query.Timeout < curTimeout {
				curTimeout = *query.Timeout
			}
		}
	}

	return curTimeout
}

func addQueryInfoToMaps(activeQueryTypes map[string]string, activeProcesses map[string]string, postureQueryState *rest_model.PostureQueries) {
	for _, query := range postureQueryState.PostureQueries {
		activeQueryTypes[string(*query.QueryType)] = *query.ID

		switch *query.QueryType {
		case rest_model.PostureCheckTypePROCESS:
			activeQueryTypes[string(rest_model.PostureCheckTypeOS)] = *query.ID
			activeProcesses[query.Process.Path] = *query.ID
		case rest_model.PostureCheckTypePROCESSMULTI:
			activeQueryTypes[string(rest_model.PostureCheckTypeOS)] = *query.ID

			for _, process := range query.Processes {
				activeProcesses[process.Path] = *query.ID
			}
		}
	}
}

// GetChangedResponses determines if posture responses should be sent out.
func (cache *Cache) GetChangedResponses(currentData, candidateData *CacheData, activeQueryTypes map[string]string) []rest_model.PostureResponseCreate {
	processes := map[string]string{}
	candidateData.Processes.IterCb(func(processPath string, processInfo ProcessInfo) {
		processes[processPath] = processInfo.QueryId
	})

	wakeChanged := !currentData.OnWake.At.Equal(candidateData.OnWake.At)
	unlockChanged := !currentData.OnUnlock.At.Equal(candidateData.OnUnlock.At)

	info := &QueryInfo{QueryTypes: activeQueryTypes, Processes: processes}
	return getChangedResponses(currentData, candidateData, info, wakeChanged, unlockChanged)
}

// getChangedResponses builds the posture responses a destination needs given what it last saw
// (baseline) and freshly collected candidate data, restricted to the query types and process paths
// in info. wakeChanged/unlockChanged are the pass-wide endpoint-state one-shots — they are
// computed once against the cache's current data because the wake/unlock signal never lives on a
// candidate or per-destination baseline.
func getChangedResponses(baseline, candidateData *CacheData, info *QueryInfo, wakeChanged, unlockChanged bool) []rest_model.PostureResponseCreate {
	if info.isEmpty() {
		return nil
	}

	activeQueryTypes := info.QueryTypes

	var responses []rest_model.PostureResponseCreate

	if wakeChanged || unlockChanged {
		// TOTP MFA checks are the only checks that care about wake/unlock
		if queryId, ok := activeQueryTypes[string(rest_model.PostureCheckTypeMFA)]; ok {
			endpointState := &rest_model.PostureResponseEndpointStateCreate{
				Unlocked: unlockChanged,
				Woken:    wakeChanged,
			}
			endpointState.SetID(&queryId)
			responses = append(responses, endpointState)
		}
	}

	if baseline.Domain != candidateData.Domain {
		if queryId, ok := activeQueryTypes[string(rest_model.PostureCheckTypeDOMAIN)]; ok {
			domainResponse := &rest_model.PostureResponseDomainCreate{
				Domain: &candidateData.Domain,
			}
			domainResponse.SetID(&queryId)
			domainResponse.SetTypeID(rest_model.PostureCheckTypeDOMAIN)

			responses = append(responses, domainResponse)
		}
	}

	if baseline.TotpToken.Token != candidateData.TotpToken.Token {
		if queryId, ok := activeQueryTypes[string(rest_model.PostureCheckTypeMFA)]; ok {
			totpMfaResponse := &edge.PostureResponseTotp{
				TotpToken: candidateData.TotpToken.Token,
			}
			totpMfaResponse.SetID(&queryId)
			totpMfaResponse.SetTypeID(rest_model.PostureCheckTypeMFA)

			responses = append(responses, totpMfaResponse)
		}
	}

	if !stringz.EqualSlices(baseline.MacAddresses, candidateData.MacAddresses) {
		if queryId, ok := activeQueryTypes[string(rest_model.PostureCheckTypeMAC)]; ok {
			macResponse := &rest_model.PostureResponseMacAddressCreate{
				MacAddresses: candidateData.MacAddresses,
			}
			macResponse.SetID(&queryId)
			macResponse.SetTypeID(rest_model.PostureCheckTypeMAC)

			responses = append(responses, macResponse)
		}
	}

	if candidateData.Os.Version != baseline.Os.Version || candidateData.Os.Type != baseline.Os.Type {
		if queryId, ok := activeQueryTypes[string(rest_model.PostureCheckTypeOS)]; ok {
			osResponse := &rest_model.PostureResponseOperatingSystemCreate{
				Type:    &candidateData.Os.Type,
				Version: &candidateData.Os.Version,
				Build:   "",
			}
			osResponse.SetID(&queryId)
			osResponse.SetTypeID(rest_model.PostureCheckTypeOS)

			responses = append(responses, osResponse)
		}
	}

	candidateData.Processes.IterCb(func(processPath string, candidateProcessInfo ProcessInfo) {
		// The candidate carries the union of every destination's watched processes; only this
		// destination's paths belong in its responses.
		if _, relevant := info.Processes[processPath]; !relevant {
			return
		}

		curProcessInfo, ok := baseline.Processes.Get(processPath)

		sendResponse := false
		if !ok {
			//no prev state send
			sendResponse = true
		} else {
			sendResponse = curProcessInfo.IsRunning != candidateProcessInfo.IsRunning || curProcessInfo.Hash != candidateProcessInfo.Hash || !stringz.EqualSlices(curProcessInfo.SignerFingerprints, candidateProcessInfo.SignerFingerprints)
		}

		if sendResponse {
			processResponse := &rest_model.PostureResponseProcessCreate{
				Path:               processPath,
				Hash:               candidateProcessInfo.Hash,
				SignerFingerprints: candidateProcessInfo.SignerFingerprints,
				IsRunning:          candidateProcessInfo.IsRunning,
			}

			processResponse.SetID(&candidateProcessInfo.QueryId)
			processResponse.SetTypeID(rest_model.PostureCheckTypePROCESS)
			responses = append(responses, processResponse)
		}
	})

	return responses
}

func (cache *Cache) totpTimeoutWindowEntered() bool {
	if cache.totpTimeout == TotpPostureCheckNoTimeout {
		return false
	}

	if cache.previousData.TotpToken.IssuedAt.IsZero() {
		return true
	}

	if cache.previousData.TotpToken.Token == "" {
		return true
	}

	effectiveTimeout := time.Duration(cache.totpTimeout)*time.Second - TotpAttemptDelta
	return cache.previousData.TotpToken.IssuedAt.Add(effectiveTimeout).Before(time.Now())
}

func (cache *Cache) start() {
	cache.startOnce.Do(func() {
		stopWake, err := cache.eventState.ListenForWake(cache.onWake)
		if err != nil {
			pfxlog.Logger().WithError(err).Error("error starting wake listener for posture")
		}

		stopUnlock, err := cache.eventState.ListenForUnlock(cache.OnUnlock)
		if err != nil {
			pfxlog.Logger().WithError(err).Error("error starting unlock listener for posture")
		}

		ticker := time.NewTicker(10 * time.Second)
		go func() {
			defer func() {
				if r := recover(); r != nil {
					pfxlog.Logger().Errorf("error during posture response streaming: %v", r)
				}
			}()

			for {
				select {
				case <-ticker.C:

					cache.Evaluate()
				case <-cache.closeNotify:
					if stopWake != nil {
						stopWake()
					}

					if stopUnlock != nil {
						stopUnlock()
					}
					return
				}
			}
		}()
	})
}

func (cache *Cache) SendResponses(responses []rest_model.PostureResponseCreate) []error {
	return cache.sendResponsesVia(cache.submitter, responses)
}

// sendResponsesVia submits responses through the given submitter, falling back from bulk to
// single submissions when the destination does not support the bulk endpoint (HTTP 404).
func (cache *Cache) sendResponsesVia(submitter Submitter, responses []rest_model.PostureResponseCreate) []error {
	if cache.doSingleSubmissions {
		var allErrors []error
		for _, response := range responses {
			err := submitter.SendPostureResponse(response)

			if err != nil {
				allErrors = append(allErrors, err)
			}
		}

		return allErrors

	} else {
		err := submitter.SendPostureResponseBulk(responses)

		if err != nil {
			if apiErr, ok := err.(*runtime.APIError); ok && apiErr.Code == http.StatusNotFound {
				cache.doSingleSubmissions = true
				return cache.sendResponsesVia(submitter, responses)
			}
			return []error{err}
		}
		return nil
	}
}

// InitializePostureOnEdgeRouter pushes posture state to a newly connected edge router. In
// per-router mode the new connection simply has no baseline yet, so a full evaluation pass sends
// it its full relevant state (and deltas, if any, to every other destination). In the legacy
// broadcast mode the previous behavior is preserved: re-send the most recent response batch
// through the submitter.
func (cache *Cache) InitializePostureOnEdgeRouter(edge.RouterConn) error {
	if cache.apiSessionProvider != nil && cache.routerConnProvider != nil {
		cache.Evaluate()
		return nil
	}

	allResponses := cache.GetAllResponses()
	return cache.submitter.SendPostureResponseBulk(allResponses)
}

func (cache *Cache) GetAllResponses() []rest_model.PostureResponseCreate {
	cache.lock.Lock()
	defer cache.lock.Unlock()

	var allResponses []rest_model.PostureResponseCreate

	allResponses = append(allResponses, cache.currentData.Responses...)

	return allResponses
}

func (cache *Cache) setTotpTimeout(timeout int64) {
	cache.totpTimeout = timeout
}

func (cache *Cache) onWake(event WakeEvent) {
	cache.currentData.OnWake = event
}

func (cache *Cache) OnUnlock(event UnlockEvent) {
	cache.currentData.OnUnlock = event
}

func (cache *Cache) SimulateWake() {
	cache.onWake(WakeEvent{At: time.Now().UTC()})
}

func (cache *Cache) SimulateUnlock() {
	cache.OnUnlock(UnlockEvent{At: time.Now().UTC()})
}

func (cache *Cache) SetTotpToken(token *rest_model.TotpToken) {
	cache.currentData.TotpToken = edge_apis.TotpTokenResult{
		Token:    *token.Token,
		IssuedAt: time.Time(*token.IssuedAt),
	}
}

func (cache *Cache) SetTotpProviderFunc(f func() <-chan edge_apis.TotpTokenResult) {
	p := edge_apis.TotpTokenProviderFunc(f)
	cache.TotpTokenProvider = &p
}

func (cache *Cache) SetDomainProviderFunc(f func() string) {
	p := DomainProviderFunc(f)
	cache.DomainProvider = &p
}

func (cache *Cache) SetMacProviderFunc(f func() []string) {
	p := MacProviderFunc(f)
	cache.MacProvider = &p
}

func (cache *Cache) SetOsProviderFunc(f func() OsInfo) {
	p := OsProviderFunc(f)
	cache.OsProvider = &p
}

func (cache *Cache) SetProcessProviderFunc(f func(string) ProcessInfo) {
	p := ProcessInfoFunc(f)
	cache.ProcessProvider = &p
}

func sanitizeMacAddresses(addresses []string) []string {
	result := make([]string, 0, len(addresses))

	for _, address := range addresses {
		address = strings.TrimSpace(address)
		address = strings.ToLower(address)
		address = strings.ReplaceAll(address, ":", "")
		result = append(result, address)
	}

	return result
}
