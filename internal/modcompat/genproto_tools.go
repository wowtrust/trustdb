//go:build tools

// Package modcompat pins dependency versions needed to keep legacy TiKV and
// etcd requirements compatible with the split genproto modules used by gRPC.
package modcompat

import _ "google.golang.org/genproto/googleapis/type/expr"
