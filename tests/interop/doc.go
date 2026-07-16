// Package interop holds Docker-based interoperability tests that run the veepin
// client and server against strongSwan.
//
// The tests are guarded by the "interop" build tag and require Docker, so they
// are excluded from the default `go build ./...` / `go test ./...` and never
// affect the CGO-free, dependency-free core. Run them with:
//
//	make interop
//	# or: go test -tags interop ./tests/interop/...
//
// This file carries the package clause with no build tag so the package always
// has a buildable Go source file even when the interop tag is absent.
package interop
