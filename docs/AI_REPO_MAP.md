# LAN Sentinel — Repository map

Where each concern lives, what to read before changing it, and which tests cover it. This lets an agent open the few files a task needs instead of searching the tree. The rules and task recipes are in [`AGENTS.md`](../AGENTS.md); this page only answers "where".

## Concerns

| Concern | Code | Read first | Tests |
| --- | --- | --- | --- |
| Host identity, bindings, conflicts, presence | `internal/correlate` (`rules.go`, `state.go`, `correlate.go`) | `DATA_MODEL.md` §3, §5.1–§5.3, §6 | `internal/correlate/correlate_test.go`; `test/golden` (`TestScenarios`, reconstruction) |
| Names and `preferred_name` | `internal/correlate/names.go` | `DATA_MODEL.md` §5.4 | `internal/correlate/names_test.go` |
| Proxy ARP and duplicate IP | `internal/correlate/proxyarp.go`, `rules.go` | `DATA_MODEL.md` §5.2; `REQUIREMENTS.md` §5 (Proxy ARP vs duplicate IP) | `proxyarp_test.go`; `test/golden` |
| Services, probe results, operator actions (kill switch, scans, descriptions) | `internal/correlate/probes.go` | `DATA_MODEL.md` §5.5, §5.8, §8 | `internal/correlate/probes_test.go`, `internal/daemon/*_test.go` |
| DHCP servers and leases | `decoders/dhcp.go`, `internal/correlate/dhcp.go`, `internal/config` (`InterfaceDHCP`) | `DATA_MODEL.md` §5.6; `REQUIREMENTS.md` FR-PA-3, FR-PA-7 | `correlate/dhcp_test.go`, `store/dhcp_test.go`, `test/golden/capture_test.go` |
| Identification (OUI, passive identifiers) | `internal/identify`, `internal/correlate/identify.go`, `internal/ouitable`, `data/oui` | `DATA_MODEL.md` §5.7 | `identify/*_test.go`, `correlate/identify_test.go` |
| Events and journald | `internal/events`; emitted from `internal/correlate` | `DATA_MODEL.md` §7; `ARCHITECTURE.md` §7 | `events_test.go` (`TestCatalogueMatchesSchema`) |
| Observation type, bus, operator messages | `internal/observation` | `DATA_MODEL.md` §2; `ARCHITECTURE.md` §3 (Observation bus) | `internal/observation/*_test.go` |
| Passive capture and BPF filter | `internal/collect/capture` (`capture.go`, `filter.go`, `decoder.go`) | `ARCHITECTURE.md` §3 (Passive capture) | `capture_test.go`; `test/net/capture_test.go` |
| Frame decoders | `internal/collect/capture/decoders` | `ARCHITECTURE.md` §3; `DATA_MODEL.md` §2 (meta keys) | `decoders_test.go`, `edge_test.go`, `fuzz_test.go` |
| Neighbour table | `internal/collect/neighbor`, `platform/netlink.go` | `ARCHITECTURE.md` §3 (Neighbour collector) | `neighbor` tests; `test/net/netlink_test.go` |
| Interfaces and contexts | `internal/iface`, `platform/netlink.go` | `ARCHITECTURE.md` §3 (Interface manager) | `iface` tests; `test/net/netlink_test.go` |
| Replay | `internal/collect/replay`, `internal/clock` | `ARCHITECTURE.md` §3 (Replay collector) | `replay` tests; `test/golden/capture_test.go` |
| Kernel access | `internal/platform` (`afpacket.go`, `netlink.go`, `transmit.go`); fakes in `platform/fake` | `ARCHITECTURE.md` §3 (Platform layer), §8 | `platform` tests; `test/net` |
| Active probe safety (budget, policy, kill switch, back-off, plan) | `internal/probe` | `ARCHITECTURE.md` §3 (Active probes), §5 | `budget_test.go`, `policy_test.go`, `plan_test.go`; `test/net/active_test.go` (`TestActiveDiscovery`) |
| Probe engines | `internal/probe/{arp,icmp,tcp,udp}` | `ARCHITECTURE.md` §3, §5 | per-engine tests on `platform/fake`; `test/net/active_test.go` |
| Scheduling and operator scans | `internal/probe/scheduler`, `internal/netrange` | `ARCHITECTURE.md` §3 (scheduler paragraph) | `scheduler_test.go`, `netrange` tests |
| Storage, writer, compaction, integrity | `internal/store` (`store.go`, `compact.go`, `integrity.go`, `migrate.go`) | `DATA_MODEL.md` §4, §9; `ARCHITECTURE.md` §3 (Store) | `store_test.go`, `compact_test.go`, `integrity_test.go`; `test/crash`; `make soak` |
| Read model (API and `--offline`) | `internal/store/reader.go`, `query.go`, `model.go` | `CLI.md` §1, §4; `DATA_MODEL.md` §4 (Point-in-time query) | `reader_test.go`; `test/golden/cli_test.go` |
| Schema | `migrations/NNNN_*.sql` | `DATA_MODEL.md` §4; `AGENTS.md` §10, §13 | `store_test.go` (migrations, constraints) |
| REST API | `internal/api` (`api.go` reads, `active.go` operator endpoints, `client.go`) | `API.md` | `api_test.go`, `active_test.go`, `fail_test.go` |
| CLI | `internal/cli` (`root.go`, `hosts.go`, `lists.go`, `describe.go`, `configcmd.go`, `status.go`, `output.go`, `backend.go`) | `CLI.md` | `cli_test.go`, `read_test.go`, `formats_test.go`, `describe_test.go`, `active_test.go` |
| Daemon lifecycle, reload | `internal/daemon` (`daemon.go`, `pipeline.go`, `server.go`, `active.go`) | `ARCHITECTURE.md` §6; `REQUIREMENTS.md` FR-CFG-3 | `daemon_test.go`; `test/systemd` |
| Configuration | `internal/config` (`types.go`, `defaults.go`, `validate.go`, `load.go`, `summary.go`) | `ARCHITECTURE.md` §6 | `config_test.go`, `fuzz_test.go`; `TestDeployConfigs` |
| Metrics | `internal/metrics`; values gathered in `internal/daemon` | `API.md` (Metrics); AGENTS.md rule 9 | `metrics_test.go` |
| systemd, sd_notify, journald | `internal/service`, `deploy/lan-sentinel.service` | `ARCHITECTURE.md` §8 | `service` tests; `test/systemd/run.sh` |
| Install, upgrade, rollout | `deploy/README.md` (its install block is run by `test/systemd/run.sh`) | `deploy/README.md` | `make test-systemd` |
| Board privilege audit | `tools/capcheck` (its README audit block is run by `test/systemd/run.sh`) | `tools/capcheck/README.md`; `ARCHITECTURE.md` §8 | `make test-net`, `make test-systemd` |
| Build, CI, release | `Makefile`, `build/*.sh`, `.github/workflows/{ci,release}.yml` | `ARCHITECTURE.md` §4 (Tooling); `README.md` (Releases) | CI itself |
| Hardware validation | `docs/TEST_PLAN.md` | `IMPLEMENTATION_PLAN.md` (Open hardware and field checks) | manual, on boards |

## Common tasks: files to touch

The steps are in `AGENTS.md` §10. These are the files each task usually touches.

| Task | Files |
| --- | --- |
| Passive decoder | `internal/collect/capture/decoders/<proto>.go`, `decoders.go`, `decoders_test.go`, `fuzz_test.go`; `capture/filter.go` if new frames are needed; `test/frames`; optionally `test/fixtures/fixtures.go` + `make fixtures` + `test/golden/capture_test.go`; `ARCHITECTURE.md` §3, `DATA_MODEL.md` §2 |
| Read-only CLI command | `internal/store/reader.go` (+ `query.go`, `model.go`), `internal/api/api.go`, `internal/api/client.go`, `internal/cli/backend.go`, a command file in `internal/cli`, `root.go`; tests in `store`, `api`, `cli`; `CLI.md`, `API.md` |
| Operator (write) command | the above, plus `internal/api/active.go` (`Control`), `internal/daemon/active.go`, `internal/observation/bus.go` (`Operator` kind), `internal/correlate/probes.go`; usually a migration and an event |
| Schema change | `migrations/NNNN_*.sql`, `internal/store` models and queries, `internal/correlate/db.go` if the correlator writes it; `DATA_MODEL.md` §4 |
| Event type | migration (events rebuild), `internal/events/events.go`, emitting code in `internal/correlate`; `DATA_MODEL.md` §7, `CLI.md` (Event type names) |
| Config key | `internal/config/{types,defaults,validate,summary}.go`, `testdata/architecture-example.yaml`, `deploy/config.yaml`; the consumer; `ARCHITECTURE.md` §6 |
| Metric | `internal/metrics` (label allow-list), gathering in `internal/daemon`; `API.md`, `ARCHITECTURE.md` §3 (Metrics) |
| Probe engine fix | `internal/probe/<engine>`, `internal/probe` (budget, plan), `internal/probe/scheduler`; `test/net/active_test.go`; `ARCHITECTURE.md` §3, §5 |
| Unit or install change | `deploy/lan-sentinel.service`, `deploy/README.md`, `tools/capcheck/README.md`, `test/systemd/run.sh`; `ARCHITECTURE.md` §8 |
