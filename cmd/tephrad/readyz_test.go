// SPDX-License-Identifier: Apache-2.0

package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// The readiness probe passes only while the agent reads events: not before
// its programs and readers are up, and not once it is stopping.
func TestReadyz(t *testing.T) {
	a := &agent{c: &counters{}}
	h := metricsHandler(a, nil)
	code := func() int {
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/readyz", nil))
		return rr.Code
	}
	if got := code(); got != http.StatusServiceUnavailable {
		t.Errorf("before reading: %d, want 503", got)
	}
	a.c.ready.Store(true)
	if got := code(); got != http.StatusOK {
		t.Errorf("while reading: %d, want 200", got)
	}
	a.c.ready.Store(false)
	if got := code(); got != http.StatusServiceUnavailable {
		t.Errorf("stopping: %d, want 503", got)
	}
}
