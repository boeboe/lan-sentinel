// Package net holds the network integration tests (build tag nettest). They
// run in Docker on a test network with simulated hosts, as uid 65534 with
// only CAP_NET_RAW, via `make test-net` (test/net/run.sh). The environment
// variables LS_TEST_IFACE, LS_TEST_OPEN, LS_TEST_CLOSED, LS_TEST_ABSENT and
// LS_TEST_IPV6 describe the test network. The first tests arrive with the
// netlink backends in phase 1.
package net
