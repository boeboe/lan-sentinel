// Package nettest holds the network integration tests (build tag nettest).
// They run in Docker on a test network with simulated hosts, as uid 65534
// with only CAP_NET_RAW, via `make test-net` (test/net/run.sh).
//
// LS_TEST_* environment variables describe the network. Tests that need a
// change outside the runner container (swap the host behind an IP, connect a
// second network) write <action>.request into LS_TEST_SYNC; run.sh performs
// the action and writes <action>.done.
package nettest
