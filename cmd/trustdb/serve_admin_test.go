package main

import (
	"testing"

	"github.com/wowtrust/trustdb/v2/internal/securityaudit"
)

func TestAdminAuditRecorderKeepsDisabledWriterNil(t *testing.T) {
	t.Parallel()

	var writer *securityaudit.Writer
	if recorder := adminAuditRecorder(writer); recorder != nil {
		t.Fatalf("adminAuditRecorder(nil) = %T, want nil interface", recorder)
	}
}
