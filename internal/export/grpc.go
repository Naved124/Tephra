// SPDX-License-Identifier: Apache-2.0

package export

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	tephrav1 "github.com/Naved124/tephra/api/tephra/v1"
)

// Tuning of the collector stream.
const (
	// maxBatch is the most records sent in one stream.
	maxBatch = 512
	// linger is how long a batch of raw events waits for more. A batch
	// holding an alert does not wait.
	linger = 200 * time.Millisecond
	// sendTimeout bounds one stream, including the collector's write to
	// the store.
	sendTimeout = 20 * time.Second
	minBackoff  = time.Second
	maxBackoff  = 30 * time.Second
)

// GRPCStats are the exporter's counters.
type GRPCStats struct {
	// Queued is the number of records waiting or being sent.
	Queued int
	// Acked records were confirmed stored by the collector; Rejected ones
	// were refused for good.
	Acked    uint64
	Rejected uint64
	// DroppedEvents and DroppedAlerts were discarded because the queue
	// was full.
	DroppedEvents uint64
	DroppedAlerts uint64
	// Retries counts streams that failed and were sent again.
	Retries uint64
}

// GRPC streams records to the collector. A bounded queue sits in front of
// the stream. When it is full, raw events are dropped before alerts, and
// every drop is counted.
//
// A record leaves the queue only when the collector has acknowledged the
// stream that carried it, so a collector restart loses nothing that was
// queued: the batch is sent again. The other side of that is duplicates,
// when a stream was stored but its acknowledgement was lost; the store drops
// an entry that is identical to one it already has.
type GRPC struct {
	conn   *grpc.ClientConn
	client tephrav1.ExporterClient
	cap    int

	mu     sync.Mutex
	events []*Record
	alerts []*Record
	// inflight is the batch being sent; it still occupies queue space.
	inflight int
	wake     chan struct{}

	acked, rejected, droppedEvents, droppedAlerts, retries atomic.Uint64

	// Backoff is the wait before the given retry (0 for the first). The
	// default doubles from 1 to 30 seconds. Set before Run.
	Backoff func(attempt int) time.Duration
}

// NewGRPC prepares a client for the collector at addr (host:port). Nothing
// is sent until Run is called. The connection is not encrypted: the
// collector is a cluster-internal service, and mutual TLS is out of scope
// for this version.
func NewGRPC(addr string, capacity int) (*GRPC, error) {
	if capacity <= 0 {
		return nil, fmt.Errorf("export queue capacity must be positive")
	}
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, fmt.Errorf("collector address %q: %w", addr, err)
	}
	return &GRPC{
		conn:    conn,
		client:  tephrav1.NewExporterClient(conn),
		cap:     capacity,
		wake:    make(chan struct{}, 1),
		Backoff: expBackoff,
	}, nil
}

func expBackoff(attempt int) time.Duration {
	d := minBackoff << min(attempt, 5)
	return min(d, maxBackoff)
}

// Offer queues a record without blocking. It reports whether the record was
// taken.
func (g *GRPC) Offer(r *Record) bool {
	g.mu.Lock()
	full := len(g.events)+len(g.alerts)+g.inflight >= g.cap
	switch {
	case !full:
	case !r.IsAlert():
		g.mu.Unlock()
		g.droppedEvents.Add(1)
		return false
	case len(g.events) > 0:
		// Make room for the alert at the cost of the oldest raw event.
		g.events = g.events[1:]
		g.droppedEvents.Add(1)
	default:
		g.mu.Unlock()
		g.droppedAlerts.Add(1)
		return false
	}
	if r.IsAlert() {
		g.alerts = append(g.alerts, r)
	} else {
		g.events = append(g.events, r)
	}
	g.mu.Unlock()
	select {
	case g.wake <- struct{}{}:
	default:
	}
	return true
}

// take removes up to maxBatch records, alerts first, and marks them in
// flight.
func (g *GRPC) take() (batch []*Record, hasAlert bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	n := min(len(g.alerts), maxBatch)
	batch = append(batch, g.alerts[:n]...)
	g.alerts = g.alerts[n:]
	hasAlert = n > 0
	n = min(len(g.events), maxBatch-len(batch))
	batch = append(batch, g.events[:n]...)
	g.events = g.events[n:]
	g.inflight = len(batch)
	return batch, hasAlert
}

func (g *GRPC) pending() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return len(g.events) + len(g.alerts)
}

// Run sends until ctx is cancelled, then makes one last attempt to deliver
// what is queued.
func (g *GRPC) Run(ctx context.Context) {
	defer func() { _ = g.conn.Close() }()
	for {
		select {
		case <-ctx.Done():
			g.drain()
			return
		case <-g.wake:
		}
		for g.pending() > 0 && ctx.Err() == nil {
			// Let a batch of raw events fill up; an alert goes at
			// once.
			g.mu.Lock()
			wait := len(g.alerts) == 0 && len(g.events) < maxBatch
			g.mu.Unlock()
			if wait {
				select {
				case <-ctx.Done():
				case <-time.After(linger):
				}
			}
			batch, _ := g.take()
			g.deliver(ctx, batch)
		}
	}
}

// deliver sends one batch until it is acknowledged or ctx ends. The batch
// keeps its place in the queue's accounting meanwhile, so a collector that
// stays down fills the queue and the overflow is counted.
func (g *GRPC) deliver(ctx context.Context, batch []*Record) {
	for attempt := 0; ; attempt++ {
		ack, err := g.send(ctx, batch)
		if err == nil {
			g.acked.Add(ack.GetAccepted())
			g.rejected.Add(ack.GetRejected())
			break
		}
		g.retries.Add(1)
		select {
		case <-ctx.Done():
			// Shutting down: put the batch back for the final
			// attempt.
			g.mu.Lock()
			for _, r := range batch {
				if r.IsAlert() {
					g.alerts = append(g.alerts, r)
				} else {
					g.events = append(g.events, r)
				}
			}
			g.inflight = 0
			g.mu.Unlock()
			return
		case <-time.After(g.Backoff(attempt)):
		}
	}
	g.mu.Lock()
	g.inflight = 0
	g.mu.Unlock()
}

func (g *GRPC) send(ctx context.Context, batch []*Record) (*tephrav1.Ack, error) {
	ctx, cancel := context.WithTimeout(ctx, sendTimeout)
	defer cancel()
	stream, err := g.client.Export(ctx)
	if err != nil {
		return nil, err
	}
	for _, r := range batch {
		if err := stream.Send(ToProto(r)); err != nil {
			// The real error is on the receive side.
			_, rerr := stream.CloseAndRecv()
			if rerr != nil {
				return nil, rerr
			}
			return nil, err
		}
	}
	ack, err := stream.CloseAndRecv()
	if err != nil {
		return nil, err
	}
	if got := ack.GetAccepted() + ack.GetRejected(); got != uint64(len(batch)) {
		return nil, fmt.Errorf("collector answered for %d records, sent %d", got, len(batch))
	}
	return ack, nil
}

// drain makes one attempt per batch to deliver what is left at shutdown.
func (g *GRPC) drain() {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	for g.pending() > 0 {
		batch, _ := g.take()
		ack, err := g.send(ctx, batch)
		if err != nil {
			return
		}
		g.acked.Add(ack.GetAccepted())
		g.rejected.Add(ack.GetRejected())
		g.mu.Lock()
		g.inflight = 0
		g.mu.Unlock()
	}
}

// Stats returns the counters.
func (g *GRPC) Stats() GRPCStats {
	g.mu.Lock()
	queued := len(g.events) + len(g.alerts) + g.inflight
	g.mu.Unlock()
	return GRPCStats{
		Queued:        queued,
		Acked:         g.acked.Load(),
		Rejected:      g.rejected.Load(),
		DroppedEvents: g.droppedEvents.Load(),
		DroppedAlerts: g.droppedAlerts.Load(),
		Retries:       g.retries.Load(),
	}
}
