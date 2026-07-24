export namespace anchor {
	
	export class OtsUpgradeResult {
	    url: string;
	    changed: boolean;
	    status_code?: number;
	    old_length?: number;
	    new_length?: number;
	    error?: string;
	    elapsed_ms?: number;
	
	    static createFrom(source: any = {}) {
	        return new OtsUpgradeResult(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.url = source["url"];
	        this.changed = source["changed"];
	        this.status_code = source["status_code"];
	        this.old_length = source["old_length"];
	        this.new_length = source["new_length"];
	        this.error = source["error"];
	        this.elapsed_ms = source["elapsed_ms"];
	    }
	}
	export class OtsUpgradeSummary {
	    tree_size: number;
	    digest: string;
	    changed: boolean;
	    calendars: OtsUpgradeResult[];
	    inspected_at_unix_nano: number;
	
	    static createFrom(source: any = {}) {
	        return new OtsUpgradeSummary(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.tree_size = source["tree_size"];
	        this.digest = source["digest"];
	        this.changed = source["changed"];
	        this.calendars = this.convertValues(source["calendars"], OtsUpgradeResult);
	        this.inspected_at_unix_nano = source["inspected_at_unix_nano"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}

}

export namespace main {
	
	export class LocalRecord {
	    record_id: string;
	    submitted_at: string;
	    submitted_at_unix_nano: number;
	    file_path: string;
	    file_name: string;
	    content_hash_hex: string;
	    content_length: number;
	    media_type: string;
	    event_type: string;
	    source: string;
	    idempotency_key: string;
	    tenant_id: string;
	    client_id: string;
	    key_id: string;
	    proof_level: string;
	    batch_id: string;
	    anchor_status: string;
	    anchor_sink?: string;
	    anchor_id?: string;
	    last_error?: string;
	    last_synced_at?: string;
	    last_synced_at_unix_nano?: number;
	    server_record?: model.ServerRecord;
	    accepted_receipt?: model.AcceptedReceipt;
	    committed_receipt?: model.CommittedReceipt;
	    global_proof?: model.GlobalLogProof;
	    anchor_result?: model.STHAnchorResult;
	
	    static createFrom(source: any = {}) {
	        return new LocalRecord(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.record_id = source["record_id"];
	        this.submitted_at = source["submitted_at"];
	        this.submitted_at_unix_nano = source["submitted_at_unix_nano"];
	        this.file_path = source["file_path"];
	        this.file_name = source["file_name"];
	        this.content_hash_hex = source["content_hash_hex"];
	        this.content_length = source["content_length"];
	        this.media_type = source["media_type"];
	        this.event_type = source["event_type"];
	        this.source = source["source"];
	        this.idempotency_key = source["idempotency_key"];
	        this.tenant_id = source["tenant_id"];
	        this.client_id = source["client_id"];
	        this.key_id = source["key_id"];
	        this.proof_level = source["proof_level"];
	        this.batch_id = source["batch_id"];
	        this.anchor_status = source["anchor_status"];
	        this.anchor_sink = source["anchor_sink"];
	        this.anchor_id = source["anchor_id"];
	        this.last_error = source["last_error"];
	        this.last_synced_at = source["last_synced_at"];
	        this.last_synced_at_unix_nano = source["last_synced_at_unix_nano"];
	        this.server_record = this.convertValues(source["server_record"], model.ServerRecord);
	        this.accepted_receipt = this.convertValues(source["accepted_receipt"], model.AcceptedReceipt);
	        this.committed_receipt = this.convertValues(source["committed_receipt"], model.CommittedReceipt);
	        this.global_proof = this.convertValues(source["global_proof"], model.GlobalLogProof);
	        this.anchor_result = this.convertValues(source["anchor_result"], model.STHAnchorResult);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class SubmitResult {
	    record: LocalRecord;
	    proof_level: string;
	    idempotent: boolean;
	    batch_queued: boolean;
	    batch_error?: string;
	
	    static createFrom(source: any = {}) {
	        return new SubmitResult(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.record = this.convertValues(source["record"], LocalRecord);
	        this.proof_level = source["proof_level"];
	        this.idempotent = source["idempotent"];
	        this.batch_queued = source["batch_queued"];
	        this.batch_error = source["batch_error"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class BatchItemResult {
	    path: string;
	    success: boolean;
	    error?: string;
	    result?: SubmitResult;
	
	    static createFrom(source: any = {}) {
	        return new BatchItemResult(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.path = source["path"];
	        this.success = source["success"];
	        this.error = source["error"];
	        this.result = this.convertValues(source["result"], SubmitResult);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class FileInfo {
	    path: string;
	    name: string;
	    size: number;
	    content_hash_hex: string;
	    media_type: string;
	
	    static createFrom(source: any = {}) {
	        return new FileInfo(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.path = source["path"];
	        this.name = source["name"];
	        this.size = source["size"];
	        this.content_hash_hex = source["content_hash_hex"];
	        this.media_type = source["media_type"];
	    }
	}
	export class HealthStatus {
	    ok: boolean;
	    server_url: string;
	    transport: string;
	    rtt_millis: number;
	    error?: string;
	    status_code?: number;
	    transport_security?: string;
	    tls_version?: string;
	    peer_authenticated?: boolean;
	    peer_subject?: string;
	
	    static createFrom(source: any = {}) {
	        return new HealthStatus(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.ok = source["ok"];
	        this.server_url = source["server_url"];
	        this.transport = source["transport"];
	        this.rtt_millis = source["rtt_millis"];
	        this.error = source["error"];
	        this.status_code = source["status_code"];
	        this.transport_security = source["transport_security"];
	        this.tls_version = source["tls_version"];
	        this.peer_authenticated = source["peer_authenticated"];
	        this.peer_subject = source["peer_subject"];
	    }
	}
	export class IdentityView {
	    tenant_id: string;
	    client_id: string;
	    key_id: string;
	    public_key_b64: string;
	    has_private: boolean;
	
	    static createFrom(source: any = {}) {
	        return new IdentityView(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.tenant_id = source["tenant_id"];
	        this.client_id = source["client_id"];
	        this.key_id = source["key_id"];
	        this.public_key_b64 = source["public_key_b64"];
	        this.has_private = source["has_private"];
	    }
	}
	
	export class Metric {
	    name: string;
	    type?: string;
	    help?: string;
	    labels?: Record<string, string>;
	    value: number;
	
	    static createFrom(source: any = {}) {
	        return new Metric(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.name = source["name"];
	        this.type = source["type"];
	        this.help = source["help"];
	        this.labels = source["labels"];
	        this.value = source["value"];
	    }
	}
	export class RecordPage {
	    items: LocalRecord[];
	    total: number;
	    limit: number;
	    offset: number;
	    has_more: boolean;
	    next_cursor?: string;
	    source?: string;
	    total_exact: boolean;
	    error?: string;
	
	    static createFrom(source: any = {}) {
	        return new RecordPage(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.items = this.convertValues(source["items"], LocalRecord);
	        this.total = source["total"];
	        this.limit = source["limit"];
	        this.offset = source["offset"];
	        this.has_more = source["has_more"];
	        this.next_cursor = source["next_cursor"];
	        this.source = source["source"];
	        this.total_exact = source["total_exact"];
	        this.error = source["error"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class RecordPageOptions {
	    limit: number;
	    offset: number;
	    cursor?: string;
	    direction?: string;
	    query?: string;
	    level?: string;
	    batch_id?: string;
	    tenant_id?: string;
	    client_id?: string;
	
	    static createFrom(source: any = {}) {
	        return new RecordPageOptions(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.limit = source["limit"];
	        this.offset = source["offset"];
	        this.cursor = source["cursor"];
	        this.direction = source["direction"];
	        this.query = source["query"];
	        this.level = source["level"];
	        this.batch_id = source["batch_id"];
	        this.tenant_id = source["tenant_id"];
	        this.client_id = source["client_id"];
	    }
	}
	export class Settings {
	    server_url: string;
	    server_transport: string;
	    server_ca_file: string;
	    server_name: string;
	    server_ca_pins_sha256: string;
	    client_tls_cert_file: string;
	    client_tls_key_file: string;
	    tls_reload_interval: string;
	    server_public_key_b64: string;
	    anchor_plugin_command: string;
	    anchor_plugin_args_text: string;
	    anchor_plugin_start_timeout: string;
	    anchor_plugin_rpc_timeout: string;
	    default_media_type: string;
	    default_event_type: string;
	    theme: string;
	
	    static createFrom(source: any = {}) {
	        return new Settings(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.server_url = source["server_url"];
	        this.server_transport = source["server_transport"];
	        this.server_ca_file = source["server_ca_file"];
	        this.server_name = source["server_name"];
	        this.server_ca_pins_sha256 = source["server_ca_pins_sha256"];
	        this.client_tls_cert_file = source["client_tls_cert_file"];
	        this.client_tls_key_file = source["client_tls_key_file"];
	        this.tls_reload_interval = source["tls_reload_interval"];
	        this.server_public_key_b64 = source["server_public_key_b64"];
	        this.anchor_plugin_command = source["anchor_plugin_command"];
	        this.anchor_plugin_args_text = source["anchor_plugin_args_text"];
	        this.anchor_plugin_start_timeout = source["anchor_plugin_start_timeout"];
	        this.anchor_plugin_rpc_timeout = source["anchor_plugin_rpc_timeout"];
	        this.default_media_type = source["default_media_type"];
	        this.default_event_type = source["default_event_type"];
	        this.theme = source["theme"];
	    }
	}
	export class SubmitRequest {
	    path: string;
	    media_type?: string;
	    event_type?: string;
	    source?: string;
	
	    static createFrom(source: any = {}) {
	        return new SubmitRequest(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.path = source["path"];
	        this.media_type = source["media_type"];
	        this.event_type = source["event_type"];
	        this.source = source["source"];
	    }
	}
	
	export class VerifyRequest {
	    mode: string;
	    file_path: string;
	    single_proof_path?: string;
	    proof_path?: string;
	    global_proof_path?: string;
	    anchor_path?: string;
	    server_url?: string;
	    record_id?: string;
	    skip_anchor?: boolean;
	    client_public_key_b64?: string;
	    server_public_key_b64?: string;
	
	    static createFrom(source: any = {}) {
	        return new VerifyRequest(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.mode = source["mode"];
	        this.file_path = source["file_path"];
	        this.single_proof_path = source["single_proof_path"];
	        this.proof_path = source["proof_path"];
	        this.global_proof_path = source["global_proof_path"];
	        this.anchor_path = source["anchor_path"];
	        this.server_url = source["server_url"];
	        this.record_id = source["record_id"];
	        this.skip_anchor = source["skip_anchor"];
	        this.client_public_key_b64 = source["client_public_key_b64"];
	        this.server_public_key_b64 = source["server_public_key_b64"];
	    }
	}
	export class VerifyResponse {
	    valid: boolean;
	    level: string;
	    record_id: string;
	    anchor_sink?: string;
	    anchor_id?: string;
	    bundle?: model.ProofBundle;
	    global_proof?: model.GlobalLogProof;
	    anchor?: model.STHAnchorResult;
	    content_bytes?: number;
	    error?: string;
	
	    static createFrom(source: any = {}) {
	        return new VerifyResponse(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.valid = source["valid"];
	        this.level = source["level"];
	        this.record_id = source["record_id"];
	        this.anchor_sink = source["anchor_sink"];
	        this.anchor_id = source["anchor_id"];
	        this.bundle = this.convertValues(source["bundle"], model.ProofBundle);
	        this.global_proof = this.convertValues(source["global_proof"], model.GlobalLogProof);
	        this.anchor = this.convertValues(source["anchor"], model.STHAnchorResult);
	        this.content_bytes = source["content_bytes"];
	        this.error = source["error"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}

}

export namespace model {
	
	export class Signature {
	    alg: string;
	    key_id: string;
	    signature: number[];
	
	    static createFrom(source: any = {}) {
	        return new Signature(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.alg = source["alg"];
	        this.key_id = source["key_id"];
	        this.signature = source["signature"];
	    }
	}
	export class WALPosition {
	    segment_id: number;
	    offset: number;
	    sequence: number;
	
	    static createFrom(source: any = {}) {
	        return new WALPosition(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.segment_id = source["segment_id"];
	        this.offset = source["offset"];
	        this.sequence = source["sequence"];
	    }
	}
	export class AcceptedReceipt {
	    schema_version: string;
	    record_id: string;
	    status: string;
	    server_id: string;
	    server_received_at_unix_nano: number;
	    wal: WALPosition;
	    server_signature: Signature;
	
	    static createFrom(source: any = {}) {
	        return new AcceptedReceipt(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.schema_version = source["schema_version"];
	        this.record_id = source["record_id"];
	        this.status = source["status"];
	        this.server_id = source["server_id"];
	        this.server_received_at_unix_nano = source["server_received_at_unix_nano"];
	        this.wal = this.convertValues(source["wal"], WALPosition);
	        this.server_signature = this.convertValues(source["server_signature"], Signature);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class BatchProof {
	    tree_alg: string;
	    leaf_index: number;
	    tree_size: number;
	    audit_path: number[][];
	
	    static createFrom(source: any = {}) {
	        return new BatchProof(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.tree_alg = source["tree_alg"];
	        this.leaf_index = source["leaf_index"];
	        this.tree_size = source["tree_size"];
	        this.audit_path = source["audit_path"];
	    }
	}
	export class BatchRoot {
	    schema_version: string;
	    batch_id: string;
	    node_id?: string;
	    log_id?: string;
	    batch_root: number[];
	    tree_size: number;
	    closed_at_unix_nano: number;
	
	    static createFrom(source: any = {}) {
	        return new BatchRoot(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.schema_version = source["schema_version"];
	        this.batch_id = source["batch_id"];
	        this.node_id = source["node_id"];
	        this.log_id = source["log_id"];
	        this.batch_root = source["batch_root"];
	        this.tree_size = source["tree_size"];
	        this.closed_at_unix_nano = source["closed_at_unix_nano"];
	    }
	}
	export class TimeAttestation {
	    type: string;
	    token?: number[];
	
	    static createFrom(source: any = {}) {
	        return new TimeAttestation(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.type = source["type"];
	        this.token = source["token"];
	    }
	}
	export class Metadata {
	    event_type: string;
	    source?: string;
	    trace_id?: string;
	    parents?: string[];
	    custom?: Record<string, string>;
	
	    static createFrom(source: any = {}) {
	        return new Metadata(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.event_type = source["event_type"];
	        this.source = source["source"];
	        this.trace_id = source["trace_id"];
	        this.parents = source["parents"];
	        this.custom = source["custom"];
	    }
	}
	export class Content {
	    hash_alg: string;
	    content_hash: number[];
	    content_length: number;
	    media_type?: string;
	    storage_uri?: string;
	
	    static createFrom(source: any = {}) {
	        return new Content(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.hash_alg = source["hash_alg"];
	        this.content_hash = source["content_hash"];
	        this.content_length = source["content_length"];
	        this.media_type = source["media_type"];
	        this.storage_uri = source["storage_uri"];
	    }
	}
	export class ClientClaim {
	    schema_version: string;
	    tenant_id: string;
	    client_id: string;
	    key_id: string;
	    produced_at_unix_nano: number;
	    nonce: number[];
	    idempotency_key: string;
	    content: Content;
	    metadata: Metadata;
	    time_attestation?: TimeAttestation;
	
	    static createFrom(source: any = {}) {
	        return new ClientClaim(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.schema_version = source["schema_version"];
	        this.tenant_id = source["tenant_id"];
	        this.client_id = source["client_id"];
	        this.key_id = source["key_id"];
	        this.produced_at_unix_nano = source["produced_at_unix_nano"];
	        this.nonce = source["nonce"];
	        this.idempotency_key = source["idempotency_key"];
	        this.content = this.convertValues(source["content"], Content);
	        this.metadata = this.convertValues(source["metadata"], Metadata);
	        this.time_attestation = this.convertValues(source["time_attestation"], TimeAttestation);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class CommittedReceipt {
	    schema_version: string;
	    record_id: string;
	    status: string;
	    batch_id: string;
	    leaf_index: number;
	    leaf_hash: number[];
	    batch_root: number[];
	    batch_closed_at_unix_nano: number;
	    node_id?: string;
	    log_id?: string;
	    server_signature: Signature;
	
	    static createFrom(source: any = {}) {
	        return new CommittedReceipt(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.schema_version = source["schema_version"];
	        this.record_id = source["record_id"];
	        this.status = source["status"];
	        this.batch_id = source["batch_id"];
	        this.leaf_index = source["leaf_index"];
	        this.leaf_hash = source["leaf_hash"];
	        this.batch_root = source["batch_root"];
	        this.batch_closed_at_unix_nano = source["batch_closed_at_unix_nano"];
	        this.node_id = source["node_id"];
	        this.log_id = source["log_id"];
	        this.server_signature = this.convertValues(source["server_signature"], Signature);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	
	export class GlobalConsistencyProof {
	    from_tree_size: number;
	    to_tree_size: number;
	    audit_path: number[][];
	
	    static createFrom(source: any = {}) {
	        return new GlobalConsistencyProof(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.from_tree_size = source["from_tree_size"];
	        this.to_tree_size = source["to_tree_size"];
	        this.audit_path = source["audit_path"];
	    }
	}
	export class SignedTreeHead {
	    schema_version: string;
	    tree_alg: string;
	    tree_size: number;
	    root_hash: number[];
	    timestamp_unix_nano: number;
	    node_id?: string;
	    log_id?: string;
	    signature: Signature;
	
	    static createFrom(source: any = {}) {
	        return new SignedTreeHead(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.schema_version = source["schema_version"];
	        this.tree_alg = source["tree_alg"];
	        this.tree_size = source["tree_size"];
	        this.root_hash = source["root_hash"];
	        this.timestamp_unix_nano = source["timestamp_unix_nano"];
	        this.node_id = source["node_id"];
	        this.log_id = source["log_id"];
	        this.signature = this.convertValues(source["signature"], Signature);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class GlobalLogProof {
	    schema_version: string;
	    node_id?: string;
	    log_id?: string;
	    batch_id: string;
	    leaf_index: number;
	    leaf_hash: number[];
	    tree_size: number;
	    inclusion_path: number[][];
	    sth: SignedTreeHead;
	    consistency?: GlobalConsistencyProof;
	
	    static createFrom(source: any = {}) {
	        return new GlobalLogProof(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.schema_version = source["schema_version"];
	        this.node_id = source["node_id"];
	        this.log_id = source["log_id"];
	        this.batch_id = source["batch_id"];
	        this.leaf_index = source["leaf_index"];
	        this.leaf_hash = source["leaf_hash"];
	        this.tree_size = source["tree_size"];
	        this.inclusion_path = source["inclusion_path"];
	        this.sth = this.convertValues(source["sth"], SignedTreeHead);
	        this.consistency = this.convertValues(source["consistency"], GlobalConsistencyProof);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	
	export class Validation {
	    policy_version: string;
	    hash_alg_allowed: boolean;
	    signature_alg_allowed: boolean;
	    key_status: string;
	
	    static createFrom(source: any = {}) {
	        return new Validation(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.policy_version = source["policy_version"];
	        this.hash_alg_allowed = source["hash_alg_allowed"];
	        this.signature_alg_allowed = source["signature_alg_allowed"];
	        this.key_status = source["key_status"];
	    }
	}
	export class ServerRecord {
	    schema_version: string;
	    record_id: string;
	    tenant_id: string;
	    client_id: string;
	    key_id: string;
	    claim_hash: number[];
	    client_signature_hash: number[];
	    received_at_unix_nano: number;
	    wal: WALPosition;
	    validation: Validation;
	
	    static createFrom(source: any = {}) {
	        return new ServerRecord(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.schema_version = source["schema_version"];
	        this.record_id = source["record_id"];
	        this.tenant_id = source["tenant_id"];
	        this.client_id = source["client_id"];
	        this.key_id = source["key_id"];
	        this.claim_hash = source["claim_hash"];
	        this.client_signature_hash = source["client_signature_hash"];
	        this.received_at_unix_nano = source["received_at_unix_nano"];
	        this.wal = this.convertValues(source["wal"], WALPosition);
	        this.validation = this.convertValues(source["validation"], Validation);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class SignedClaim {
	    schema_version: string;
	    claim: ClientClaim;
	    signature: Signature;
	
	    static createFrom(source: any = {}) {
	        return new SignedClaim(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.schema_version = source["schema_version"];
	        this.claim = this.convertValues(source["claim"], ClientClaim);
	        this.signature = this.convertValues(source["signature"], Signature);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class ProofBundle {
	    schema_version: string;
	    record_id: string;
	    node_id?: string;
	    log_id?: string;
	    signed_claim: SignedClaim;
	    server_record: ServerRecord;
	    accepted_receipt: AcceptedReceipt;
	    committed_receipt: CommittedReceipt;
	    batch_proof: BatchProof;
	
	    static createFrom(source: any = {}) {
	        return new ProofBundle(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.schema_version = source["schema_version"];
	        this.record_id = source["record_id"];
	        this.node_id = source["node_id"];
	        this.log_id = source["log_id"];
	        this.signed_claim = this.convertValues(source["signed_claim"], SignedClaim);
	        this.server_record = this.convertValues(source["server_record"], ServerRecord);
	        this.accepted_receipt = this.convertValues(source["accepted_receipt"], AcceptedReceipt);
	        this.committed_receipt = this.convertValues(source["committed_receipt"], CommittedReceipt);
	        this.batch_proof = this.convertValues(source["batch_proof"], BatchProof);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class STHAnchorResult {
	    schema_version: string;
	    node_id?: string;
	    log_id?: string;
	    tree_size: number;
	    sink_name: string;
	    anchor_id: string;
	    root_hash: number[];
	    sth: SignedTreeHead;
	    proof?: number[];
	    published_at_unix_nano: number;
	
	    static createFrom(source: any = {}) {
	        return new STHAnchorResult(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.schema_version = source["schema_version"];
	        this.node_id = source["node_id"];
	        this.log_id = source["log_id"];
	        this.tree_size = source["tree_size"];
	        this.sink_name = source["sink_name"];
	        this.anchor_id = source["anchor_id"];
	        this.root_hash = source["root_hash"];
	        this.sth = this.convertValues(source["sth"], SignedTreeHead);
	        this.proof = source["proof"];
	        this.published_at_unix_nano = source["published_at_unix_nano"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	
	
	
	
	
	

}
