// Package migrations embeds the numbered SQL schema migrations
// (NNNN_description.sql), applied in order at startup by internal/store.
package migrations

import "embed"

// FS holds every migration file.
//
//go:embed *.sql
var FS embed.FS
