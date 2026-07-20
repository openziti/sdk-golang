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

package posture

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/openziti/edge-api/rest_model"
	edge_apis "github.com/openziti/sdk-golang/v2/edge-apis"
	"github.com/openziti/sdk-golang/v2/ziti/edge"
	"github.com/stretchr/testify/require"
)

// stubPostureConn records posture submissions; all other RouterConn methods come from the embedded
// (nil) interface and panic if unexpectedly invoked, which keeps the stub honest.
type stubPostureConn struct {
	edge.RouterConn
	name    string
	closed  bool
	capable bool

	mu   sync.Mutex
	sent [][]rest_model.PostureResponseCreate
}

func (s *stubPostureConn) GetRouterName() string    { return s.name }
func (s *stubPostureConn) GetRouterAddr() string    { return s.name }
func (s *stubPostureConn) IsClosed() bool           { return s.closed }
func (s *stubPostureConn) IsRouterCapable(int) bool { return s.capable }
func (s *stubPostureConn) GetBoolHeader(int32) bool { return false }

func (s *stubPostureConn) SendPosture(creates []rest_model.PostureResponseCreate) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sent = append(s.sent, creates)
	return nil
}

func (s *stubPostureConn) sentBatches() [][]rest_model.PostureResponseCreate {
	s.mu.Lock()
	defer s.mu.Unlock()
	result := make([][]rest_model.PostureResponseCreate, len(s.sent))
	copy(result, s.sent)
	return result
}

// stubApiSession overrides only GetType; everything else panics via the embedded (nil) interface.
type stubApiSession struct {
	edge_apis.ApiSession
	sessionType edge_apis.ApiSessionType
}

func (s *stubApiSession) GetType() edge_apis.ApiSessionType { return s.sessionType }

// stubDestinations plays all three destination-provider roles for the cache under test.
type stubDestinations struct {
	sessionType edge_apis.ApiSessionType

	mu    sync.Mutex
	conns []edge.RouterConn
	infos map[edge.RouterConn]*QueryInfo
}

func (s *stubDestinations) GetCurrentApiSession() edge_apis.ApiSession {
	return &stubApiSession{sessionType: s.sessionType}
}

func (s *stubDestinations) GetRouterConnections() []edge.RouterConn {
	s.mu.Lock()
	defer s.mu.Unlock()
	result := make([]edge.RouterConn, len(s.conns))
	copy(result, s.conns)
	return result
}

func (s *stubDestinations) GetRouterPostureQueryInfo(conn edge.RouterConn) (*QueryInfo, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	info, ok := s.infos[conn]
	return info, ok
}

func (s *stubDestinations) setConns(conns ...edge.RouterConn) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.conns = conns
}

func (s *stubDestinations) setInfo(conn edge.RouterConn, info *QueryInfo) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.infos[conn] = info
}

// recordingSubmitter records controller-bound bulk submissions.
type recordingSubmitter struct {
	mu    sync.Mutex
	bulks [][]rest_model.PostureResponseCreate
}

func (r *recordingSubmitter) SendPostureResponse(response rest_model.PostureResponseCreate) error {
	return r.SendPostureResponseBulk([]rest_model.PostureResponseCreate{response})
}

func (r *recordingSubmitter) SendPostureResponseBulk(responses []rest_model.PostureResponseCreate) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.bulks = append(r.bulks, responses)
	return nil
}

func (r *recordingSubmitter) bulkCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.bulks)
}

// stubServices supplies fixed active dial/bind service sets.
type stubServices struct {
	dials []*rest_model.ServiceDetail
	binds []*rest_model.ServiceDetail
}

func (s stubServices) GetActiveDialServices() []*rest_model.ServiceDetail { return s.dials }
func (s stubServices) GetActiveBindServices() []*rest_model.ServiceDetail { return s.binds }

func macOnlyInfo(queryId string) *QueryInfo {
	return &QueryInfo{
		QueryTypes:  map[string]string{string(rest_model.PostureCheckTypeMAC): queryId},
		Processes:   map[string]string{},
		TotpTimeout: TotpPostureCheckNoTimeout,
	}
}

func domainOnlyInfo(queryId string) *QueryInfo {
	return &QueryInfo{
		QueryTypes:  map[string]string{string(rest_model.PostureCheckTypeDOMAIN): queryId},
		Processes:   map[string]string{},
		TotpTimeout: TotpPostureCheckNoTimeout,
	}
}

// newPerRouterTestCache builds a cache in per-router submission mode with deterministic device
// data providers, returning the cache, the controller-bound submitter, and a cleanup func.
func newPerRouterTestCache(t *testing.T, dest *stubDestinations) (*Cache, *recordingSubmitter) {
	closeNotify := make(chan struct{})
	t.Cleanup(func() { close(closeNotify) })

	controller := &recordingSubmitter{}
	cache := NewCache(stubServices{}, controller, nil, closeNotify)
	cache.EnablePerRouterSubmission(dest, dest, dest, controller)

	cache.SetMacProviderFunc(func() []string { return []string{"aa:bb:cc:dd:ee:ff"} })
	cache.SetDomainProviderFunc(func() string { return "corp.example" })
	cache.SetOsProviderFunc(func() OsInfo { return OsInfo{Type: "Linux", Version: "6.1"} })
	cache.SetProcessProviderFunc(func(path string) ProcessInfo {
		return ProcessInfo{IsRunning: true, Hash: "hash-" + path}
	})

	return cache, controller
}

// TestPerRouterSubmissionFiltersByRouterRequirements locks in that each posture-capable router
// connection receives only the posture responses its own required checks cover, rather than the
// broadcast of everything to everyone.
func TestPerRouterSubmissionFiltersByRouterRequirements(t *testing.T) {
	connA := &stubPostureConn{name: "mac-router", capable: true}
	connB := &stubPostureConn{name: "domain-router", capable: true}
	dest := &stubDestinations{
		sessionType: edge_apis.ApiSessionTypeOidc,
		conns:       []edge.RouterConn{connA, connB},
		infos: map[edge.RouterConn]*QueryInfo{
			connA: macOnlyInfo("mac-check"),
			connB: domainOnlyInfo("domain-check"),
		},
	}
	cache, controller := newPerRouterTestCache(t, dest)

	cache.Evaluate()

	batchesA := connA.sentBatches()
	require.Len(t, batchesA, 1, "the MAC router should receive exactly one batch")
	require.Len(t, batchesA[0], 1, "the MAC router's batch should carry only its own check's response")
	macResponse, ok := batchesA[0][0].(*rest_model.PostureResponseMacAddressCreate)
	require.True(t, ok, "expected a MAC response, got %T", batchesA[0][0])
	require.Equal(t, []string{"aabbccddeeff"}, macResponse.MacAddresses)

	batchesB := connB.sentBatches()
	require.Len(t, batchesB, 1, "the domain router should receive exactly one batch")
	require.Len(t, batchesB[0], 1, "the domain router's batch should carry only its own check's response")
	domainResponse, ok := batchesB[0][0].(*rest_model.PostureResponseDomainCreate)
	require.True(t, ok, "expected a domain response, got %T", batchesB[0][0])
	require.Equal(t, "corp.example", *domainResponse.Domain)

	require.Equal(t, 0, controller.bulkCount(), "all conns capable: nothing goes to the controller")
}

// TestNewRouterConnReceivesFullRelevantState locks in that a router connection appearing after
// prior evaluations receives its full relevant current state (empty baseline), while already
// current connections receive nothing when no data changed.
func TestNewRouterConnReceivesFullRelevantState(t *testing.T) {
	connA := &stubPostureConn{name: "existing-router", capable: true}
	dest := &stubDestinations{
		sessionType: edge_apis.ApiSessionTypeOidc,
		conns:       []edge.RouterConn{connA},
		infos: map[edge.RouterConn]*QueryInfo{
			connA: macOnlyInfo("mac-check"),
		},
	}
	cache, _ := newPerRouterTestCache(t, dest)

	cache.Evaluate()
	require.Len(t, connA.sentBatches(), 1, "first pass sends the existing router its state")

	connB := &stubPostureConn{name: "new-router", capable: true}
	dest.setConns(connA, connB)
	dest.setInfo(connB, macOnlyInfo("mac-check"))

	cache.Evaluate()

	require.Len(t, connA.sentBatches(), 1, "nothing changed: the existing router receives no new batch")
	batchesB := connB.sentBatches()
	require.Len(t, batchesB, 1, "the new router must receive its full relevant state despite no data change")
	require.Len(t, batchesB[0], 1)
	_, ok := batchesB[0][0].(*rest_model.PostureResponseMacAddressCreate)
	require.True(t, ok, "expected a MAC response, got %T", batchesB[0][0])
}

// TestRelevanceExpansionSendsCurrentData locks in that when a check type becomes relevant to a
// router later (e.g. its pushed state gains a domain check), the router receives the current data
// for that type even though the device data itself did not change.
func TestRelevanceExpansionSendsCurrentData(t *testing.T) {
	conn := &stubPostureConn{name: "router", capable: true}
	dest := &stubDestinations{
		sessionType: edge_apis.ApiSessionTypeOidc,
		conns:       []edge.RouterConn{conn},
		infos: map[edge.RouterConn]*QueryInfo{
			conn: macOnlyInfo("mac-check"),
		},
	}
	cache, _ := newPerRouterTestCache(t, dest)

	cache.Evaluate()
	require.Len(t, conn.sentBatches(), 1, "first pass sends the MAC state")

	expanded := macOnlyInfo("mac-check")
	expanded.QueryTypes[string(rest_model.PostureCheckTypeDOMAIN)] = "domain-check"
	dest.setInfo(conn, expanded)

	cache.Evaluate()

	batches := conn.sentBatches()
	require.Len(t, batches, 2, "the newly relevant domain check should produce a second batch")
	require.Len(t, batches[1], 1, "only the newly relevant type is sent, not a full re-send")
	domainResponse, ok := batches[1][0].(*rest_model.PostureResponseDomainCreate)
	require.True(t, ok, "expected a domain response, got %T", batches[1][0])
	require.Equal(t, "corp.example", *domainResponse.Domain)
}

// TestLegacySessionKeepsBroadcastPath locks in that legacy API sessions are untouched by
// per-router submission: responses go through the configured submitter (the controller route) and
// no router connection is contacted directly by the cache.
func TestLegacySessionKeepsBroadcastPath(t *testing.T) {
	conn := &stubPostureConn{name: "router", capable: true}
	dest := &stubDestinations{
		sessionType: edge_apis.ApiSessionTypeLegacy,
		conns:       []edge.RouterConn{conn},
		infos: map[edge.RouterConn]*QueryInfo{
			conn: macOnlyInfo("mac-check"),
		},
	}
	cache, controller := newPerRouterTestCache(t, dest)

	// The global view must require posture data for the legacy path to send anything.
	macQueryId := "mac-check"
	macQueryType := rest_model.PostureCheckTypeMAC
	cache.serviceProvider = stubServices{
		dials: []*rest_model.ServiceDetail{{
			PostureQueries: []*rest_model.PostureQueries{{
				PolicyType: rest_model.DialBindDial,
				PostureQueries: []*rest_model.PostureQuery{{
					BaseEntity: rest_model.BaseEntity{ID: &macQueryId},
					QueryType:  &macQueryType,
				}},
			}},
		}},
	}

	cache.Evaluate()

	require.Empty(t, conn.sentBatches(), "legacy sessions never submit posture directly to routers")
	require.Equal(t, 1, controller.bulkCount(), "legacy sessions submit through the configured submitter")
}

// TestPerRouterSubmissionConcurrency hammers concurrent evaluation passes, router initialization,
// and destination churn. Run under -race it locks in that the per-connection baselines and the
// evaluation state are guarded by the cache lock; removing that guard makes this test report a
// data race.
func TestPerRouterSubmissionConcurrency(t *testing.T) {
	connA := &stubPostureConn{name: "steady", capable: true}
	connB := &stubPostureConn{name: "churning", capable: true}
	dest := &stubDestinations{
		sessionType: edge_apis.ApiSessionTypeOidc,
		conns:       []edge.RouterConn{connA},
		infos: map[edge.RouterConn]*QueryInfo{
			connA: macOnlyInfo("mac-check"),
			connB: macOnlyInfo("mac-check"),
		},
	}
	cache, _ := newPerRouterTestCache(t, dest)

	// Vary the device data so evaluation passes keep producing deltas and baseline writes.
	var counter atomic.Uint64
	cache.SetMacProviderFunc(func() []string {
		return []string{fmt.Sprintf("aa:bb:cc:dd:ee:%02d", counter.Add(1)%50)}
	})

	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				cache.Evaluate()
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for j := 0; j < 50; j++ {
			_ = cache.InitializePostureOnEdgeRouter(connB)
		}
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		for j := 0; j < 50; j++ {
			if j%2 == 0 {
				dest.setConns(connA, connB)
			} else {
				dest.setConns(connA)
			}
		}
	}()
	wg.Wait()

	require.NotEmpty(t, connA.sentBatches(), "the steady router should have received posture data")
}

// TestIncapableConnFallsBackToController locks in that when an open connection cannot accept
// posture data, the globally-changed responses fall back to the controller.
func TestIncapableConnFallsBackToController(t *testing.T) {
	capable := &stubPostureConn{name: "capable", capable: true}
	incapable := &stubPostureConn{name: "incapable", capable: false}
	dest := &stubDestinations{
		sessionType: edge_apis.ApiSessionTypeOidc,
		conns:       []edge.RouterConn{capable, incapable},
		infos: map[edge.RouterConn]*QueryInfo{
			capable: macOnlyInfo("mac-check"),
		},
	}
	cache, controller := newPerRouterTestCache(t, dest)

	// The controller fallback carries the globally-derived changes, so the global view must
	// require the MAC data too.
	macQueryId := "mac-check"
	macQueryType := rest_model.PostureCheckTypeMAC
	cache.serviceProvider = stubServices{
		dials: []*rest_model.ServiceDetail{{
			PostureQueries: []*rest_model.PostureQueries{{
				PolicyType: rest_model.DialBindDial,
				PostureQueries: []*rest_model.PostureQuery{{
					BaseEntity: rest_model.BaseEntity{ID: &macQueryId},
					QueryType:  &macQueryType,
				}},
			}},
		}},
	}

	cache.Evaluate()

	require.Len(t, capable.sentBatches(), 1, "the capable router still receives its responses directly")
	require.Empty(t, incapable.sentBatches(), "an incapable router is never sent posture directly")
	require.Equal(t, 1, controller.bulkCount(), "the incapable router's presence routes global changes to the controller")
}
