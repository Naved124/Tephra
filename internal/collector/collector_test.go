// SPDX-License-Identifier: Apache-2.0

package collector_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"

	tephrav1 "github.com/Naved124/tephra/api/tephra/v1"
	"github.com/Naved124/tephra/internal/collector"
	"github.com/Naved124/tephra/internal/export"
)

// fakeLoki keeps what is pushed, dropping exact duplicates as Loki does.
type fakeLoki struct {
	t   *testing.T
	srv *httptest.Server

	mu sync.Mutex
	// lines is keyed by label set, timestamp and content.
	lines  map[string]map[string]string
	pushes int
	// status, when not 0, is returned instead of storing.
	status atomic.Int32
}

func newFakeLoki(t *testing.T) *fakeLoki {
	f := &fakeLoki{t: t, lines: map[string]map[string]string{}}
	f.srv = httptest.NewServer(http.HandlerFunc(f.handle))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeLoki) handle(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/loki/api/v1/push" || r.Header.Get("Content-Type") != "application/json" {
		http.Error(w, "bad request", http.StatusNotFound)
		return
	}
	if s := f.status.Load(); s != 0 {
		http.Error(w, "injected", int(s))
		return
	}
	var body struct {
		Streams []struct {
			Stream map[string]string `json:"stream"`
			Values [][2]string       `json:"values"`
		} `json:"streams"`
	}
	raw, _ := io.ReadAll(r.Body)
	if err := json.Unmarshal(raw, &body); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.pushes++
	for _, s := range body.Streams {
		labels, _ := json.Marshal(s.Stream) // map keys are sorted
		for _, v := range s.Values {
			f.lines[v[0]+"\x00"+v[1]+"\x00"+string(labels)] = s.Stream
		}
	}
	w.WriteHeader(http.StatusNoContent)
}

func (f *fakeLoki) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.lines)
}

// byLabel counts stored lines per value of one label.
func (f *fakeLoki) byLabel(name string) map[string]int {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := map[string]int{}
	for _, labels := range f.lines {
		out[labels[name]]++
	}
	return out
}

type server struct {
	c    *collector.Collector
	grpc *grpc.Server
	stop context.CancelFunc
	addr string
}

// startCollector serves on addr, or on a free port when addr is empty.
func startCollector(t *testing.T, loki *fakeLoki, addr string, opts collector.Options) *server {
	t.Helper()
	if addr == "" {
		addr = "127.0.0.1:0"
	}
	var ln net.Listener
	var err error
	// The port of a server that just stopped can take a moment to free.
	for i := 0; i < 50; i++ {
		if ln, err = net.Listen("tcp", addr); err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		t.Fatal(err)
	}
	if opts.FlushInterval == 0 {
		opts.FlushInterval = 20 * time.Millisecond
	}
	if opts.PushBackoff == 0 {
		opts.PushBackoff = 5 * time.Millisecond
	}
	opts.Cluster = "kind"
	if opts.HealthInterval == 0 {
		opts.HealthInterval = -1
	}
	ctx, cancel := context.WithCancel(context.Background())
	s := &server{
		c:    collector.New(collector.NewLoki(loki.srv.URL, ""), opts, slog.New(slog.NewTextHandler(io.Discard, nil))),
		grpc: grpc.NewServer(),
		stop: cancel,
		addr: ln.Addr().String(),
	}
	tephrav1.RegisterExporterServer(s.grpc, s.c)
	go s.c.Run(ctx)
	go func() { _ = s.grpc.Serve(ln) }()
	t.Cleanup(s.kill)
	return s
}

// kill stops the server at once, as a deleted pod would.
func (s *server) kill() {
	s.grpc.Stop()
	s.stop()
}

func startExporter(t *testing.T, addr string, capacity int) *export.GRPC {
	t.Helper()
	g, err := export.NewGRPC(addr, capacity)
	if err != nil {
		t.Fatal(err)
	}
	g.Backoff = func(int) time.Duration { return 10 * time.Millisecond }
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { g.Run(ctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	return g
}

func event(i int) *export.Record {
	return &export.Record{
		TS:   time.Date(2026, 11, 11, 9, 0, 0, i*1000, time.UTC).Format("2006-01-02T15:04:05.000000Z"),
		Type: "exec", Node: "tephra-worker",
		Process: export.Process{PID: uint32(1000 + i), Image: "/bin/true", CommandLine: fmt.Sprintf("true <%d> & more", i), Exec: &export.Exec{}},
		K8s:     export.K8s{Namespace: "shop", Pod: "web"},
	}
}

func alert(i int, level string) *export.Record {
	r := event(i)
	r.Rule = &export.Rule{ID: "R001", Title: "t", Level: level, Tags: []string{"attack.execution"}}
	return r
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestEventsAndAlertsReachLoki(t *testing.T) {
	loki := newFakeLoki(t)
	srv := startCollector(t, loki, "", collector.Options{})
	g := startExporter(t, srv.addr, 8192)

	const n = 1500 // several streams
	for i := 0; i < n; i++ {
		g.Offer(event(i))
	}
	g.Offer(alert(n, "high"))
	g.Offer(alert(n+1, "critical"))
	host := event(n + 2)
	host.K8s = export.K8s{Namespace: "host"}
	host.Type = "connect"
	host.Process.Exec = nil
	g.Offer(host)

	waitFor(t, "all records in Loki", func() bool { return loki.count() == n+3 })
	// Stored first, acknowledged a moment later.
	waitFor(t, "every record acknowledged", func() bool { return g.Stats().Acked == n+3 })
	if st := g.Stats(); st.Acked != n+3 || st.DroppedEvents != 0 || st.DroppedAlerts != 0 || st.Rejected != 0 {
		t.Errorf("exporter stats %+v", st)
	}
	waitFor(t, "empty queue", func() bool { return g.Stats().Queued == 0 })
	if st := srv.c.Stats(); st.Received != n+3 || st.Pushed != n+3 || st.QueuedBytes != 0 {
		t.Errorf("collector stats %+v", st)
	}

	// The label set of section 7, and nothing with high cardinality.
	for label, want := range map[string]map[string]int{
		"cluster":   {"kind": n + 3},
		"node":      {"tephra-worker": n + 3},
		"namespace": {"shop": n + 2, "host": 1},
		"stream":    {"event": n + 1, "alert": 2},
		"type":      {"exec": n + 2, "connect": 1},
		"level":     {"": n + 1, "high": 1, "critical": 1},
	} {
		got := loki.byLabel(label)
		if fmt.Sprint(got) != fmt.Sprint(want) {
			t.Errorf("label %s: %v, want %v", label, got, want)
		}
	}
	if got := loki.byLabel("pod"); len(got) != 1 || got[""] != n+3 {
		t.Errorf("pod must not be a label: %v", got)
	}

	// The stored line is the same JSON the agent prints.
	want, _ := export.MarshalLine(alert(n, "high"))
	found := false
	loki.mu.Lock()
	for k := range loki.lines {
		if len(k) > len(want) && k[20:20+len(want)] == string(want) {
			found = true
		}
	}
	loki.mu.Unlock()
	if !found {
		t.Errorf("alert line not stored verbatim: %s", want)
	}
}

// Killing the collector while agents are sending loses nothing: batches
// that were not acknowledged are sent again to the new one.
func TestCollectorRestartLosesNothing(t *testing.T) {
	loki := newFakeLoki(t)
	srv := startCollector(t, loki, "", collector.Options{})
	g := startExporter(t, srv.addr, 8192)

	const n = 3000
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < n; i++ {
			g.Offer(event(i))
			if i%10 == 0 {
				time.Sleep(time.Millisecond)
			}
		}
	}()
	waitFor(t, "first records", func() bool { return loki.count() > 200 })
	srv.kill()
	time.Sleep(100 * time.Millisecond)
	startCollector(t, loki, srv.addr, collector.Options{})
	wg.Wait()

	waitFor(t, "every record after the restart", func() bool { return loki.count() == n })
	st := g.Stats()
	if st.DroppedEvents != 0 || st.DroppedAlerts != 0 {
		t.Errorf("records dropped with room in the queue: %+v", st)
	}
	if st.Retries == 0 {
		t.Error("no stream was retried; the restart was not exercised")
	}
}

// While the collector is away the queue fills, and what does not fit is
// counted: stored + dropped == offered.
func TestOverflowIsCounted(t *testing.T) {
	loki := newFakeLoki(t)
	srv := startCollector(t, loki, "", collector.Options{})
	srv.kill()
	g := startExporter(t, srv.addr, 100)

	const n = 1000
	for i := 0; i < n; i++ {
		g.Offer(event(i))
	}
	startCollector(t, loki, srv.addr, collector.Options{})
	waitFor(t, "queue drained", func() bool { return g.Stats().Queued == 0 })
	st := g.Stats()
	if st.DroppedEvents == 0 || uint64(loki.count())+st.DroppedEvents != n {
		t.Errorf("stored %d + dropped %d != offered %d", loki.count(), st.DroppedEvents, n)
	}
}

// When Loki is failing the collector does not acknowledge, and the agent
// keeps the records until it recovers.
func TestLokiOutage(t *testing.T) {
	loki := newFakeLoki(t)
	loki.status.Store(http.StatusServiceUnavailable)
	srv := startCollector(t, loki, "", collector.Options{PushAttempts: 2})
	g := startExporter(t, srv.addr, 8192)
	for i := 0; i < 50; i++ {
		g.Offer(event(i))
	}
	waitFor(t, "a failed stream", func() bool { return g.Stats().Retries > 0 && srv.c.Stats().PushErrors >= 2 })
	if loki.count() != 0 || g.Stats().Acked != 0 {
		t.Fatalf("records acknowledged during the outage: %+v", g.Stats())
	}
	loki.status.Store(0)
	waitFor(t, "records after recovery", func() bool { return loki.count() == 50 })
}

// A batch Loki refuses for good is counted and not sent again.
func TestLokiRejection(t *testing.T) {
	loki := newFakeLoki(t)
	loki.status.Store(http.StatusBadRequest)
	srv := startCollector(t, loki, "", collector.Options{})
	g := startExporter(t, srv.addr, 8192)
	for i := 0; i < 5; i++ {
		g.Offer(event(i))
	}
	waitFor(t, "rejection", func() bool { return g.Stats().Rejected == 5 })
	if st := g.Stats(); st.Retries != 0 || st.Queued != 0 {
		t.Errorf("rejected batch retried: %+v", st)
	}
	if st := srv.c.Stats(); st.Rejected != 5 || st.Pushed != 0 {
		t.Errorf("collector stats %+v", st)
	}
}

func TestInvalidRecordsAreCounted(t *testing.T) {
	loki := newFakeLoki(t)
	srv := startCollector(t, loki, "", collector.Options{})
	g := startExporter(t, srv.addr, 8192)

	badTS := event(1)
	badTS.TS = "yesterday"
	badType := event(2)
	badType.Type = "nonsense"
	noNode := event(3)
	noNode.Node = ""
	noLevel := alert(4, "")
	for _, r := range []*export.Record{event(0), badTS, badType, noNode, noLevel} {
		g.Offer(r)
	}
	waitFor(t, "the valid record", func() bool { return loki.count() == 1 && g.Stats().Rejected == 4 })
	if st := srv.c.Stats(); st.Invalid != 4 || st.Pushed != 1 {
		t.Errorf("collector stats %+v", st)
	}
}

// Over its memory bound the collector refuses streams instead of growing.
func TestRefusesWhenFull(t *testing.T) {
	loki := newFakeLoki(t)
	srv := startCollector(t, loki, "", collector.Options{MaxBytes: 64})
	g := startExporter(t, srv.addr, 8192)
	for i := 0; i < 10; i++ {
		g.Offer(event(i))
	}
	waitFor(t, "a refused stream", func() bool { return srv.c.Stats().Refused > 0 })
	if loki.count() != 0 {
		t.Errorf("%d records stored past the bound", loki.count())
	}
}

// Agents and the collector itself report their counters as health records,
// stored under their own stream so they never mix with events.
func TestHealthRecords(t *testing.T) {
	loki := newFakeLoki(t)
	srv := startCollector(t, loki, "", collector.Options{HealthInterval: 30 * time.Millisecond, Namespace: "tephra"})
	g := startExporter(t, srv.addr, 8192)
	g.Offer(&export.Record{
		TS: "2026-11-11T09:00:00.000000Z", Type: export.TypeHealth, Node: "tephra-worker",
		K8s: export.K8s{Namespace: "tephra"}, Health: map[string]uint64{"ringbuf_dropped": 7},
	})
	g.Offer(&export.Record{TS: "2026-11-11T09:00:00.000000Z", Type: export.TypeHealth, Node: "tephra-worker"})

	waitFor(t, "health from the agent and the collector", func() bool {
		nodes := loki.byLabel("node")
		return nodes["tephra-worker"] == 1 && nodes["collector"] >= 2
	})
	if got := loki.byLabel("stream"); len(got) != 1 || got["health"] == 0 {
		t.Errorf("streams %v, want only health", got)
	}
	if got := loki.byLabel("namespace"); len(got) != 1 || got["tephra"] == 0 {
		t.Errorf("namespaces %v, want only tephra", got)
	}
	want := `{"ts":"2026-11-11T09:00:00.000000Z","type":"health","node":"tephra-worker","health":{"ringbuf_dropped":7}}`
	found := false
	loki.mu.Lock()
	for k := range loki.lines {
		if strings.Contains(k, want) {
			found = true
		}
	}
	loki.mu.Unlock()
	if !found {
		t.Errorf("agent health line not stored as %s", want)
	}
	// A health record without counters is refused; the acknowledgement
	// that says so arrives after the batch is stored.
	waitFor(t, "the rejection to be acknowledged", func() bool { return g.Stats().Rejected == 1 })
}
