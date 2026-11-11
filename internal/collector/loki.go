// SPDX-License-Identifier: Apache-2.0

package collector

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Labels is the Loki label set of a record. Labels are indexed, so they stay
// low-cardinality: pod name, pid and rule ID are in the JSON body and are
// filtered at query time.
type Labels struct {
	Cluster   string
	Node      string
	Namespace string
	// Stream is "event" or "alert", so the two can be retained for
	// different lengths of time.
	Stream string
	Type   string
	// Level is the alert level; empty on raw events.
	Level string
}

func (l Labels) toMap() map[string]string {
	m := map[string]string{
		"cluster":   l.Cluster,
		"node":      l.Node,
		"namespace": l.Namespace,
		"stream":    l.Stream,
		"type":      l.Type,
	}
	if l.Level != "" {
		m["level"] = l.Level
	}
	return m
}

// Entry is one log line bound for Loki.
type Entry struct {
	Labels Labels
	// TS is the event's own time, in nanoseconds since the epoch. Loki
	// drops an entry identical in stream, time and content to one it
	// has, which is what makes a resent batch harmless.
	TS   int64
	Line string
}

// errRejected marks a push Loki refused for good: sending it again would
// fail the same way.
var errRejected = errors.New("rejected by Loki")

// Loki pushes entries to /loki/api/v1/push.
type Loki struct {
	url    string
	tenant string
	client *http.Client
}

// NewLoki returns a client for the Loki at base (for example
// http://loki:3100). tenant, if set, is sent as X-Scope-OrgID.
func NewLoki(base, tenant string) *Loki {
	return &Loki{
		url:    strings.TrimRight(base, "/") + "/loki/api/v1/push",
		tenant: tenant,
		client: &http.Client{Timeout: 10 * time.Second},
	}
}

type pushStream struct {
	Stream map[string]string `json:"stream"`
	Values [][2]string       `json:"values"`
}

// encode groups entries by label set, oldest first within each.
func encode(entries []Entry) ([]byte, error) {
	byLabels := map[Labels][]Entry{}
	var order []Labels
	for _, e := range entries {
		if _, ok := byLabels[e.Labels]; !ok {
			order = append(order, e.Labels)
		}
		byLabels[e.Labels] = append(byLabels[e.Labels], e)
	}
	streams := make([]pushStream, 0, len(order))
	for _, l := range order {
		es := byLabels[l]
		sort.SliceStable(es, func(i, j int) bool { return es[i].TS < es[j].TS })
		s := pushStream{Stream: l.toMap(), Values: make([][2]string, len(es))}
		for i, e := range es {
			s.Values[i] = [2]string{strconv.FormatInt(e.TS, 10), e.Line}
		}
		streams = append(streams, s)
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(map[string]any{"streams": streams}); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// Push sends one batch. It returns errRejected (wrapped) when Loki refuses
// the content, and any other error when the push may work if tried again.
func (l *Loki) Push(ctx context.Context, entries []Entry) error {
	body, err := encode(entries)
	if err != nil {
		return fmt.Errorf("%w: %w", errRejected, err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, l.url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if l.tenant != "" {
		req.Header.Set("X-Scope-OrgID", l.tenant)
	}
	resp, err := l.client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	switch {
	case resp.StatusCode/100 == 2:
		return nil
	case resp.StatusCode == http.StatusTooManyRequests, resp.StatusCode/100 == 5:
		return fmt.Errorf("loki answered %s: %s", resp.Status, bytes.TrimSpace(msg))
	default:
		// 4xx: a bad label, an entry too old. Loki will say the same
		// next time.
		return fmt.Errorf("%w: %s: %s", errRejected, resp.Status, bytes.TrimSpace(msg))
	}
}
