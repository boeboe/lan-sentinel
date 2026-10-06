// Package oui embeds the IEEE MA-L, MA-M and MA-S registries as the
// precomputed table internal/identify searches in place (oui.bin; its format
// is internal/ouitable). `make oui` (data/oui/gen) downloads the registries,
// writes them readable as oui.tsv.gz and derives oui.bin from them; both are
// regenerated each release and kept in step by a test.
package oui

import _ "embed"

// Data is oui.bin.
//
//go:embed oui.bin
var Data []byte
