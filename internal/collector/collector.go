// SPDX-License-Identifier: Apache-2.0

// Package collector receives record streams from the agents, batches them
// by Loki label set and pushes them to Loki. It keeps no state: a stream is
// acknowledged only after Loki has taken its records, so whatever the
// collector holds when it dies is still held by the agent that sent it.
package collector

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	tephrav1 "github.com/Naved124/tephra/api/tephra/v1"
	"github.com/Naved124/tephra/internal/events"
	"github.com/Naved124/tephra/internal/export"
)

// Pusher stores a batch; *Loki implements it.
type Pusher interface {
	Push(ctx context.Context, entries []Entry) error
}

// Options configure a Collector. Zero values select the defaults.
type Options struct {
	// Cluster is the value of the cluster label.
	Cluster string
	// Namespace labels the collector's own health records.
	Namespace string
	// HealthInterval is how often the collector stores its own counters;
	// negative disables it.
	HealthInterval time.Duration
	// FlushBytes and FlushInterval bound a batch: it is pushed when it
	// reaches the size or the age, whichever comes first.
	FlushBytes    int
	FlushInterval time.Duration
	// MaxBytes bounds the records held in memory. A stream that would
	// exceed it is refused, and the agent sends it again later.
	MaxBytes int
	// MaxStream is the most records taken from one stream.
	MaxStream int
	// PushAttempts is how often a failing push is tried before the
	// streams in the batch are failed back to their agents.
	PushAttempts int
	PushBackoff  time.Duration
}

func (o *Options) defaults() {
	if o.Cluster == "" {
		o.Cluster = "default"
	}
	if o.Namespace == "" {
		o.Namespace = "host"
	}
	if o.HealthInterval == 0 {
		o.HealthInterval = 15 * time.Second
	}
	if o.FlushBytes <= 0 {
		o.FlushBytes = 1 << 20
	}
	if o.FlushInterval <= 0 {
		o.FlushInterval = time.Second
	}
	if o.MaxBytes <= 0 {
		o.MaxBytes = 64 << 20
	}
	if o.MaxStream <= 0 {
		o.MaxStream = 4096
	}
	if o.PushAttempts <= 0 {
		o.PushAttempts = 3
	}
	if o.PushBackoff <= 0 {
		o.PushBackoff = 500 * time.Millisecond
	}
}

// Stats are the collector's counters.
type Stats struct {
	// Received counts records read from streams; Invalid those that
	// failed validation.
	Received uint64
	Invalid  uint64
	// Pushed records reached Loki; Rejected ones Loki refused for good.
	Pushed   uint64
	Rejected uint64
	// PushErrors counts failed push attempts; Refused counts streams
	// turned away because the memory bound was reached.
	PushErrors uint64
	Refused    uint64
	// QueuedBytes is what is held in memory now.
	QueuedBytes int64
}

// result is what happened to one stream's records.
type result struct {
	rejected bool
	err      error
}

// group is the records of one stream, waiting for their batch.
type group struct {
	entries []Entry
	bytes   int
	done    chan result
}

// Collector implements the Exporter service.
type Collector struct {
	tephrav1.UnimplementedExporterServer
	opts Options
	push Pusher
	log  *slog.Logger

	mu      sync.Mutex
	pending []*group
	bytes   int
	first   time.Time
	kick    chan struct{}

	received, invalid, pushed, rejected, pushErrors, refused atomic.Uint64
	queued                                                   atomic.Int64
}

// New returns a Collector. Run must be started for streams to complete.
func New(push Pusher, opts Options, log *slog.Logger) *Collector {
	opts.defaults()
	return &Collector{opts: opts, push: push, log: log, kick: make(chan struct{}, 1)}
}

// Stats returns the counters.
func (c *Collector) Stats() Stats {
	return Stats{
		Received: c.received.Load(), Invalid: c.invalid.Load(),
		Pushed: c.pushed.Load(), Rejected: c.rejected.Load(),
		PushErrors: c.pushErrors.Load(), Refused: c.refused.Load(),
		QueuedBytes: c.queued.Load(),
	}
}

// Export reads one stream, queues its records and answers once they are in
// Loki.
func (c *Collector) Export(stream tephrav1.Exporter_ExportServer) error {
	g := &group{done: make(chan result, 1)}
	var invalid uint64
	for {
		rec, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}
		c.received.Add(1)
		if len(g.entries)+int(invalid) >= c.opts.MaxStream {
			return status.Errorf(codes.InvalidArgument, "more than %d records in one stream", c.opts.MaxStream)
		}
		e, err := c.entry(rec)
		if err != nil {
			invalid++
			if c.invalid.Add(1) <= 10 {
				c.log.Warn("invalid record", "error", err.Error())
			}
			continue
		}
		g.entries = append(g.entries, e)
		g.bytes += len(e.Line)
	}
	if len(g.entries) == 0 {
		return stream.SendAndClose(&tephrav1.Ack{Rejected: invalid})
	}

	if !c.enqueue(g) {
		c.refused.Add(1)
		return status.Error(codes.ResourceExhausted, "collector queue is full")
	}
	select {
	case res := <-g.done:
		switch {
		case res.err != nil:
			return status.Errorf(codes.Unavailable, "store: %v", res.err)
		case res.rejected:
			return stream.SendAndClose(&tephrav1.Ack{Rejected: invalid + uint64(len(g.entries))})
		}
		return stream.SendAndClose(&tephrav1.Ack{Accepted: uint64(len(g.entries)), Rejected: invalid})
	case <-stream.Context().Done():
		// The agent gave up; it will send the batch again. What is
		// already queued here is still pushed, and Loki drops the
		// duplicates.
		return status.FromContextError(stream.Context().Err()).Err()
	}
}

// entry validates a record and turns it into a log line with its labels.
func (c *Collector) entry(p *tephrav1.Record) (Entry, error) {
	rec := export.FromProto(p)
	ts, err := time.Parse(time.RFC3339Nano, rec.TS)
	if err != nil {
		return Entry{}, fmt.Errorf("timestamp %q: %w", rec.TS, err)
	}
	if rec.Type == export.TypeHealth {
		if rec.Node == "" || len(rec.Health) == 0 {
			return Entry{}, fmt.Errorf("health record without node or counters")
		}
		return healthEntry(c.opts.Cluster, rec.K8s.Namespace, rec.Node, ts, rec.Health)
	}
	if _, ok := events.ParseType(rec.Type); !ok {
		return Entry{}, fmt.Errorf("unknown event type %q", rec.Type)
	}
	if rec.Node == "" || rec.K8s.Namespace == "" {
		return Entry{}, fmt.Errorf("record without node or namespace")
	}
	l := Labels{Cluster: c.opts.Cluster, Node: rec.Node, Namespace: rec.K8s.Namespace, Stream: "event", Type: rec.Type}
	if rec.IsAlert() {
		if rec.Rule.ID == "" || rec.Rule.Level == "" {
			return Entry{}, fmt.Errorf("alert without rule id or level")
		}
		l.Stream = "alert"
		l.Level = rec.Rule.Level
	}
	line, err := export.MarshalLine(rec)
	if err != nil {
		return Entry{}, err
	}
	return Entry{Labels: l, TS: ts.UnixNano(), Line: string(line)}, nil
}

// healthEntry builds the log line of a health record: time, sender and
// counters, without the event fields.
func healthEntry(cluster, namespace, node string, ts time.Time, counters map[string]uint64) (Entry, error) {
	if namespace == "" {
		namespace = "host"
	}
	line, err := json.Marshal(struct {
		TS     string            `json:"ts"`
		Type   string            `json:"type"`
		Node   string            `json:"node"`
		Health map[string]uint64 `json:"health"`
	}{ts.UTC().Format("2006-01-02T15:04:05.000000Z"), export.TypeHealth, node, counters})
	if err != nil {
		return Entry{}, err
	}
	return Entry{
		Labels: Labels{Cluster: cluster, Node: node, Namespace: namespace, Stream: export.TypeHealth, Type: export.TypeHealth},
		TS:     ts.UnixNano(),
		Line:   string(line),
	}, nil
}

// selfHealth queues the collector's own counters, under the node name
// "collector".
func (c *Collector) selfHealth(now time.Time) {
	st := c.Stats()
	e, err := healthEntry(c.opts.Cluster, c.opts.Namespace, "collector", now, map[string]uint64{
		"records_received": st.Received,
		"records_invalid":  st.Invalid,
		"records_pushed":   st.Pushed,
		"records_rejected": st.Rejected,
		"push_errors":      st.PushErrors,
		"streams_refused":  st.Refused,
		"queue_bytes":      uint64(st.QueuedBytes),
	})
	if err != nil {
		return
	}
	c.enqueue(&group{entries: []Entry{e}, bytes: len(e.Line), done: make(chan result, 1)})
}

func (c *Collector) enqueue(g *group) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if int(c.queued.Load())+g.bytes > c.opts.MaxBytes {
		return false
	}
	if len(c.pending) == 0 {
		c.first = time.Now()
	}
	c.pending = append(c.pending, g)
	c.bytes += g.bytes
	c.queued.Add(int64(g.bytes))
	if c.bytes >= c.opts.FlushBytes {
		select {
		case c.kick <- struct{}{}:
		default:
		}
	}
	return true
}

// Run flushes batches until ctx is cancelled, then flushes what is left.
func (c *Collector) Run(ctx context.Context) {
	tick := time.NewTicker(c.opts.FlushInterval / 4)
	defer tick.Stop()
	var health <-chan time.Time
	if c.opts.HealthInterval > 0 {
		t := time.NewTicker(c.opts.HealthInterval)
		defer t.Stop()
		health = t.C
	}
	for {
		select {
		case now := <-health:
			c.selfHealth(now)
		case <-ctx.Done():
			c.flush(context.Background())
			return
		case <-c.kick:
			c.flush(ctx)
		case <-tick.C:
			c.mu.Lock()
			due := len(c.pending) > 0 && time.Since(c.first) >= c.opts.FlushInterval
			c.mu.Unlock()
			if due {
				c.flush(ctx)
			}
		}
	}
}

// flush pushes everything pending as one batch and tells each stream how it
// went.
func (c *Collector) flush(ctx context.Context) {
	c.mu.Lock()
	groups := c.pending
	c.pending, c.bytes = nil, 0
	c.mu.Unlock()
	if len(groups) == 0 {
		return
	}
	var entries []Entry
	total := 0
	for _, g := range groups {
		entries = append(entries, g.entries...)
		total += g.bytes
	}

	var res result
	for attempt := 1; ; attempt++ {
		err := c.push.Push(ctx, entries)
		if err == nil {
			c.pushed.Add(uint64(len(entries)))
			break
		}
		c.pushErrors.Add(1)
		if errors.Is(err, errRejected) {
			c.rejected.Add(uint64(len(entries)))
			c.log.Error("batch rejected by Loki", "records", len(entries), "error", err.Error())
			res.rejected = true
			break
		}
		if attempt >= c.opts.PushAttempts || ctx.Err() != nil {
			c.log.Error("push to Loki failed; the agents will send again", "records", len(entries), "attempts", attempt, "error", err.Error())
			res.err = err
			break
		}
		select {
		case <-ctx.Done():
		case <-time.After(c.opts.PushBackoff << (attempt - 1)):
		}
	}
	c.queued.Add(-int64(total))
	for _, g := range groups {
		g.done <- res
	}
}
