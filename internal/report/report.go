// Package report renders guardian command output in two forms: a stable,
// versioned JSON envelope for agents/CI, and clean human-readable text for the
// terminal. It depends only on internal/model; callers pass it the data to
// render.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"time"
)

// SchemaVersion is the version of the JSON envelope contract. Bump only on a
// breaking change to the envelope shape; additive changes keep the version.
const SchemaVersion = 1

// Envelope is the stable JSON wrapper emitted by every command under --json.
type Envelope struct {
	SchemaVersion int       `json:"schema_version"`
	Command       string    `json:"command"`
	GeneratedAt   time.Time `json:"generated_at"`
	Data          any       `json:"data"`
}

// now is overridable in tests for deterministic timestamps.
var now = time.Now

// WriteJSON marshals data inside the versioned envelope and writes it to w,
// terminated by a newline. The output is indented for readability; agents
// parse it structurally, so indentation is cosmetic.
func WriteJSON(w io.Writer, command string, data any) error {
	env := Envelope{
		SchemaVersion: SchemaVersion,
		Command:       command,
		GeneratedAt:   now().UTC(),
		Data:          data,
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(env); err != nil {
		return fmt.Errorf("report: encode %s envelope: %w", command, err)
	}
	return nil
}
