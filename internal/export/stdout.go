// SPDX-License-Identifier: Apache-2.0

package export

import (
	"bufio"
	"encoding/json"
	"io"
)

// JSONLines writes one JSON object per line. It is not safe for concurrent
// use; the pipeline has a single export stage.
type JSONLines struct {
	w   *bufio.Writer
	enc *json.Encoder
}

// NewJSONLines wraps w, normally os.Stdout so that kubectl logs works with no
// backend.
func NewJSONLines(w io.Writer) *JSONLines {
	bw := bufio.NewWriterSize(w, 64<<10)
	return &JSONLines{w: bw, enc: newEncoder(bw)}
}

func newEncoder(w io.Writer) *json.Encoder {
	enc := json.NewEncoder(w)
	// Command lines are full of <, > and &; keep them readable.
	enc.SetEscapeHTML(false)
	return enc
}

// lineBuffer collects one encoded record.
type lineBuffer struct{ b []byte }

func (l *lineBuffer) Write(p []byte) (int, error) {
	l.b = append(l.b, p...)
	return len(p), nil
}

// trimmed returns the bytes without the newline the encoder appends.
func (l *lineBuffer) trimmed() []byte {
	if n := len(l.b); n > 0 && l.b[n-1] == '\n' {
		return l.b[:n-1]
	}
	return l.b
}

// Write buffers one record.
func (j *JSONLines) Write(r *Record) error {
	return j.enc.Encode(r)
}

// Flush pushes buffered records out. The pipeline calls it whenever it runs
// out of pending events, so a quiet node still delivers promptly.
func (j *JSONLines) Flush() error {
	return j.w.Flush()
}
