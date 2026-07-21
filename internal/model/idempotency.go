package model

// SchemaIdempotencyDecision identifies the durable projection that preserves
// an accepted ingest decision independently of WAL retention and replay.
const SchemaIdempotencyDecision = "trustdb.idempotency-decision.v1"

// IdempotencyIdentity is the full namespace of a client-provided idempotency
// key. None of its components may be omitted for a durable decision.
type IdempotencyIdentity struct {
	TenantID       string `cbor:"tenant_id" json:"tenant_id"`
	ClientID       string `cbor:"client_id" json:"client_id"`
	IdempotencyKey string `cbor:"idempotency_key" json:"idempotency_key"`
}

// IdempotencyDecision is the durable response returned for an identical
// retry. BatchID ties the projection to the committed batch that published it.
type IdempotencyDecision struct {
	SchemaVersion string              `cbor:"schema_version" json:"schema_version"`
	Identity      IdempotencyIdentity `cbor:"identity" json:"identity"`
	ClaimHash     []byte              `cbor:"claim_hash" json:"claim_hash"`
	Record        ServerRecord        `cbor:"server_record" json:"server_record"`
	Accepted      AcceptedReceipt     `cbor:"accepted_receipt" json:"accepted_receipt"`
	BatchID       string              `cbor:"batch_id" json:"batch_id"`
}
