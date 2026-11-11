// SPDX-License-Identifier: Apache-2.0

package export

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// The protobuf form must carry every field of the JSON form. Each exported
// field of the record is set to a distinct non-zero value by reflection, so
// a field added to one form and forgotten in the other fails here.
func TestProtoRoundTripEveryField(t *testing.T) {
	r := &Record{}
	n := 0
	fill(reflect.ValueOf(r).Elem(), &n)
	if n < 50 {
		t.Fatalf("only %d fields filled; the walker is broken", n)
	}
	back := FromProto(ToProto(r))
	if !reflect.DeepEqual(r, back) {
		a, _ := json.Marshal(r)
		b, _ := json.Marshal(back)
		t.Errorf("round trip changed the record\nbefore %s\nafter  %s", a, b)
	}
}

func fill(v reflect.Value, n *int) {
	switch v.Kind() {
	case reflect.Pointer:
		v.Set(reflect.New(v.Type().Elem()))
		fill(v.Elem(), n)
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			fill(v.Field(i), n)
		}
	case reflect.String:
		*n++
		v.SetString("s" + string(rune('A'+*n%26)) + string(rune('a'+*n/26)))
	case reflect.Bool:
		*n++
		v.SetBool(true)
	case reflect.Uint16, reflect.Uint32, reflect.Uint64:
		*n++
		v.SetUint(uint64(*n + 1))
	case reflect.Slice:
		*n++
		v.Set(reflect.ValueOf([]string{"x", "y"}))
	case reflect.Map:
		*n++
		if v.Type().Elem().Kind() == reflect.Uint64 {
			v.Set(reflect.ValueOf(map[string]uint64{"k": uint64(*n)}))
		} else {
			v.Set(reflect.ValueOf(map[string]string{"k": "v"}))
		}
	default:
		panic("unhandled kind " + v.Kind().String())
	}
}

// The recorded events of every shipped rule survive the round trip as the
// same JSON line.
func TestProtoRoundTripRecordedEvents(t *testing.T) {
	files, err := filepath.Glob("../../rules/testdata/*.jsonl")
	if err != nil || len(files) == 0 {
		t.Fatalf("no recorded events: %v", err)
	}
	for _, path := range files {
		f, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		sc := bufio.NewScanner(f)
		sc.Buffer(nil, 1<<20)
		for sc.Scan() {
			var rec Record
			if err := json.Unmarshal(sc.Bytes(), &rec); err != nil {
				t.Fatalf("%s: %v", path, err)
			}
			before, _ := MarshalLine(&rec)
			after, _ := MarshalLine(FromProto(ToProto(&rec)))
			if string(before) != string(after) {
				t.Errorf("%s:\nbefore %s\nafter  %s", path, before, after)
			}
		}
		_ = f.Close()
	}
}

func queued(g *GRPC) (events, alerts int) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return len(g.events), len(g.alerts)
}

// When the queue is full, raw events go before alerts, and every drop is
// counted.
func TestQueueDropsEventsBeforeAlerts(t *testing.T) {
	g, err := NewGRPC("127.0.0.1:1", 4)
	if err != nil {
		t.Fatal(err)
	}
	ev := func() *Record { return &Record{Type: "exec"} }
	al := func() *Record { return &Record{Type: "exec", Rule: &Rule{ID: "R001", Level: "high"}} }

	for i := 0; i < 4; i++ {
		if !g.Offer(ev()) {
			t.Fatal("event refused with room in the queue")
		}
	}
	if g.Offer(ev()) {
		t.Error("event accepted by a full queue")
	}
	// An alert displaces the oldest raw event.
	for i := 0; i < 4; i++ {
		if !g.Offer(al()) {
			t.Errorf("alert %d refused while raw events were queued", i)
		}
	}
	if e, a := queued(g); e != 0 || a != 4 {
		t.Errorf("queue holds %d events and %d alerts, want 0 and 4", e, a)
	}
	// Nothing left to displace.
	if g.Offer(al()) {
		t.Error("alert accepted by a queue full of alerts")
	}
	st := g.Stats()
	if st.DroppedEvents != 5 || st.DroppedAlerts != 1 || st.Queued != 4 {
		t.Errorf("stats %+v, want 5 events and 1 alert dropped, 4 queued", st)
	}

	// A batch being sent still takes up queue space.
	batch, hasAlert := g.take()
	if len(batch) != 4 || !hasAlert || g.Stats().Queued != 4 || g.Offer(ev()) {
		t.Errorf("in-flight batch of %d not counted against the queue", len(batch))
	}
}

func TestNewGRPCRejectsBadCapacity(t *testing.T) {
	if _, err := NewGRPC("127.0.0.1:1", 0); err == nil {
		t.Error("zero capacity accepted")
	}
}
