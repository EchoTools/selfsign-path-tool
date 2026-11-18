package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"time"
)

// auditFileName is the JSON-lines audit log, kept beside the certificates so it survives runs.
const auditFileName = "audit.log"

// auditRecord is one structured line per signing, status or clear operation.
type auditRecord struct {
	Time       string   `json:"time"`
	User       string   `json:"user"`
	PID        int      `json:"pid"`
	Argv       []string `json:"argv"`
	Op         string   `json:"op"`
	File       string   `json:"file"`
	Mode       string   `json:"mode,omitempty"`
	Cert       string   `json:"cert,omitempty"`
	Outcome    string   `json:"outcome"`
	Error      string   `json:"error,omitempty"`
	DurationMS int64    `json:"duration_ms"`
}

// startAudit begins a record for one operation on one file.
func startAudit(op, filename string) *auditRecord {
	abs, err := filepath.Abs(filename)
	if err != nil {
		abs = filename
	}
	name := "unknown"
	if u, err := user.Current(); err == nil {
		name = u.Username
	}
	return &auditRecord{
		Time: time.Now().UTC().Format(time.RFC3339Nano),
		User: name,
		PID:  os.Getpid(),
		Argv: os.Args[1:],
		Op:   op,
		File: abs,
	}
}

// finish records the outcome and writes the record. A write failure is printed to
// stderr so it cannot be lost silently.
func (r *auditRecord) finish(opErr error, start time.Time) {
	r.DurationMS = time.Since(start).Milliseconds()
	if opErr != nil {
		r.Outcome = "error"
		r.Error = opErr.Error()
	} else {
		r.Outcome = "ok"
	}
	writeAuditRecord(r)
}

// auditLogPath returns the location of the audit log.
func auditLogPath() string {
	return filepath.Join(getCertificateDirectory(), auditFileName)
}

// writeAuditRecord appends one JSON line to the audit log.
func writeAuditRecord(r *auditRecord) {
	path := auditLogPath()
	line, err := json.Marshal(r)
	if err == nil {
		var f *os.File
		f, err = os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
		if err == nil {
			_, err = f.Write(append(line, '\n'))
			if closeErr := f.Close(); err == nil {
				err = closeErr
			}
		}
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: audit log write failed (%s): %v\n", path, err)
	}
}
