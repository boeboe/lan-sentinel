package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"net/netip"
	"slices"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"lan-sentinel/internal/config"
	"lan-sentinel/internal/probe"
	"lan-sentinel/internal/probe/idprobe"
	"lan-sentinel/internal/probe/scheduler"
	"lan-sentinel/internal/store"
)

func (a *app) activeCmd() *cobra.Command {
	c := &cobra.Command{Use: "active", Short: "Active-discovery kill switch"}
	var reason string
	disable := &cobra.Command{
		Use:     "disable",
		Short:   "Kill switch: stop all active probing now; persists across restarts",
		Example: "  sudo lan-sentinel active disable --reason maintenance",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if a.g.offline {
				return failf(ExitUsage, "%s needs the running daemon; it does not work with --offline", cmd.CommandPath())
			}
			st, err := a.client().DisableActive(cmd.Context(), reason)
			if err != nil {
				return a.failed(err)
			}
			if a.g.output == "json" {
				return writeJSON(a.output(), st)
			}
			fmt.Fprintln(a.output(), "Active discovery disabled (persists across restarts). Clear with: lan-sentinel active enable")
			return nil
		},
	}
	disable.Flags().StringVar(&reason, "reason", "", "why active discovery is stopped (required)")
	_ = disable.MarkFlagRequired("reason")

	var enableReason string
	enable := &cobra.Command{
		Use:     "enable",
		Short:   "Clear the kill switch",
		Example: "  sudo lan-sentinel active enable",
		Long: "Clears the kill switch. It fails (exit 2) while LAN_SENTINEL_ACTIVE_DISABLED=1\n" +
			"is set, and does not override per-interface active.enabled: false.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if a.g.offline {
				return failf(ExitUsage, "%s needs the running daemon; it does not work with --offline", cmd.CommandPath())
			}
			st, err := a.client().EnableActive(cmd.Context(), enableReason)
			if err != nil {
				return a.failed(err)
			}
			if a.g.output == "json" {
				return writeJSON(a.output(), st)
			}
			fmt.Fprintln(a.output(), "Active discovery enabled.")
			return nil
		},
	}
	enable.Flags().StringVar(&enableReason, "reason", "", "why active discovery is resumed")
	c.AddCommand(disable, enable)
	return c
}

type scanFlags struct {
	interfaces []string
	networks   []string
	profile    string
	arp, icmp  bool
	tcp        []int
	udp        []string
	allowWide  bool
}

func (f *scanFlags) add(cmd *cobra.Command) {
	fl := cmd.Flags()
	fl.StringSliceVar(&f.interfaces, "interface", nil, "interface to scan (repeatable; default every interface with active discovery)")
	fl.StringSliceVar(&f.networks, "network", nil, "network to scan, inside the interface's configured networks (repeatable)")
	fl.StringVar(&f.profile, "profile", "", "scan profile from the configuration")
	fl.BoolVar(&f.arp, "arp", false, "ARP sweep of the networks (the default when no probe is given)")
	fl.BoolVar(&f.icmp, "icmp", false, "ICMP echo to the known hosts")
	fl.IntSliceVar(&f.tcp, "tcp", nil, "TCP connect to this port on the known hosts (repeatable)")
	fl.StringSliceVar(&f.udp, "udp", nil, "UDP probe of the known hosts: "+strings.Join(config.UDPProbeNames, " or ")+" (repeatable)")
	fl.BoolVar(&f.allowWide, "allow-wide", false, fmt.Sprintf("allow a sweep of more than %d addresses (check scan plan first)", config.DefaultMaxSweepTargets))
}

func (f *scanFlags) request() (probe.Request, error) {
	req := probe.Request{Interfaces: f.interfaces, Profile: f.profile, ARP: f.arp, ICMP: f.icmp, TCP: f.tcp, UDP: f.udp, AllowWide: f.allowWide}
	for _, n := range f.networks {
		p, err := netip.ParsePrefix(n)
		if err != nil {
			return req, failf(ExitUsage, "--network %q: want a CIDR such as 192.168.1.0/24", n)
		}
		req.Networks = append(req.Networks, p)
	}
	return req, nil
}

func (a *app) scanCmd() *cobra.Command {
	c := &cobra.Command{Use: "scan", Short: "Operator scans, bound by the active-discovery safety controls"}
	var pf scanFlags
	plan := &cobra.Command{
		Use:     "plan",
		Short:   "Dry run: what a scan would do, sending nothing",
		Example: "  sudo lan-sentinel scan plan --interface eth0",
		Long: "Prints targets, probes, rates, the estimate and the verdict. Exit 0 if the\n" +
			"scan is allowed, 2 if refused. Online the daemon computes the plan; with\n" +
			"--offline it comes from the config file, the persisted kill switch and the\n" +
			"known hosts in the database (the interfaces' own addresses are unknown).",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := onlyFormats(a.g.output, "table", "json"); err != nil {
				return err
			}
			req, err := pf.request()
			if err != nil {
				return err
			}
			p, err := a.plan(cmd.Context(), req)
			if err != nil {
				return a.failed(err)
			}
			if err := a.printPlan(p); err != nil {
				return err
			}
			if !p.Allowed {
				return silent(ExitError)
			}
			return nil
		},
	}
	pf.add(plan)

	var rf scanFlags
	run := &cobra.Command{
		Use:     "run",
		Short:   "Operator-triggered scan, bound by the same safety controls",
		Example: "  sudo lan-sentinel scan run --interface eth0 --arp",
		Long: "Computes the same plan as scan plan, prints it and refuses (exit 2) if the\n" +
			"plan does. Otherwise the daemon runs it through its budgets: per interface\n" +
			"the ARP sweep first, then ICMP, TCP and UDP on the known hosts and the ARP\n" +
			"responders. Returns with a summary when the scan completes.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := onlyFormats(a.g.output, "table", "json"); err != nil {
				return err
			}
			if a.g.offline {
				return failf(ExitUsage, "%s needs the running daemon; it does not work with --offline", cmd.CommandPath())
			}
			req, err := rf.request()
			if err != nil {
				return err
			}
			cl := a.client()
			p, err := cl.PlanScan(cmd.Context(), req)
			if err != nil {
				return a.failed(err)
			}
			if a.g.output != "json" {
				if err := a.printPlan(p); err != nil {
					return err
				}
			}
			if !p.Allowed {
				if a.g.output == "json" {
					_ = writeJSON(a.output(), scheduler.ScanResult{Plan: p})
				}
				return silent(ExitError)
			}
			if a.g.output != "json" {
				fmt.Fprintf(a.output(), "Scanning (estimated typical duration %s) ...\n", approx(p.Estimate.TypicalSeconds))
			}
			res, err := cl.Scan(cmd.Context(), req)
			if errors.Is(err, scheduler.ErrScanRefused) {
				if a.g.output == "json" {
					_ = writeJSON(a.output(), res)
				} else {
					_ = a.printPlan(res.Plan)
				}
				return silent(ExitError)
			}
			if err != nil {
				return a.failed(err)
			}
			if a.g.output == "json" {
				if err := writeJSON(a.output(), res); err != nil {
					return err
				}
			} else {
				printScan(a.output(), res)
			}
			for _, r := range res.Interfaces {
				if r.Aborted != "" {
					return silent(ExitError)
				}
			}
			return nil
		},
	}
	rf.add(run)
	c.AddCommand(plan, run)
	return c
}

// plan asks the daemon, or computes the plan offline.
func (a *app) plan(ctx context.Context, req probe.Request) (probe.Plan, error) {
	if !a.g.offline {
		return a.client().PlanScan(ctx, req)
	}
	cfg, err := a.settings("db")
	if err != nil {
		return probe.Plan{}, err
	}
	r, err := store.OpenReadOnly(cfg.Storage.Path, store.ReadOptions{NameExpiry: cfg.Identity.NameExpiry.D(), Now: a.env.now})
	if err != nil {
		return probe.Plan{}, fail(ExitError, err)
	}
	defer r.Close() //nolint:errcheck // read-only
	st, err := r.ActiveState(ctx)
	if err != nil {
		return probe.Plan{}, err
	}
	if slices.Contains(a.env.Environ, config.EnvActiveDisabled+"=1") {
		st.Disabled, st.Forced = true, true
		if st.Reason == "" {
			st.Reason = config.EnvActiveDisabled + "=1"
		}
	}
	in := probe.PlanInput{Config: cfg, Active: st, Known: map[string][]netip.Addr{},
		IdentifyJobs: map[string]int{}, IdentifyPackets: map[string]int{}}
	since := a.env.now().Add(-cfg.Active.Identify.HostMaxAge.D())
	for _, ic := range cfg.Interfaces {
		known, err := r.KnownIPv4(ctx, ic.Name)
		if err != nil {
			return probe.Plan{}, err
		}
		for _, k := range known {
			in.Known[ic.Name] = append(in.Known[ic.Name], k.IP)
		}
		for _, e := range ic.Active.Identify {
			cands, err := r.IdentifyTargets(ctx, ic.Name, e.Name, since)
			if err != nil {
				return probe.Plan{}, err
			}
			for _, c := range cands {
				if c.Suppress != "" {
					continue
				}
				in.IdentifyJobs[ic.Name]++
				in.IdentifyPackets[ic.Name] += idprobe.BudgetCostOf(e.Name)
			}
		}
	}
	return probe.Compute(in, req), nil
}

func (a *app) printPlan(p probe.Plan) error {
	if a.g.output == "json" {
		return writeJSON(a.output(), p)
	}
	w := a.output()
	for _, ip := range p.Interfaces {
		head := fmt.Sprintf("Interface:  %s", ip.Interface)
		if p.Profile != "" {
			head += "    Profile: " + p.Profile
		}
		if len(ip.Networks) > 0 {
			head += "    Networks: " + joinPrefixes(ip.Networks)
		}
		fmt.Fprintln(w, head)
		if len(ip.Reasons) > 0 && len(ip.Networks) == 0 {
			continue
		}
		var targets []string
		if p.Probes.ARP {
			t := fmt.Sprintf("%d to sweep", ip.SweepTargets)
			if len(ip.Excluded) > 0 {
				t += " (excluded: " + strings.Join(ip.Excluded, ", ") + ")"
			}
			targets = append(targets, t)
		}
		if p.Probes.ICMP || len(p.Probes.TCP) > 0 || len(p.Probes.UDP) > 0 {
			targets = append(targets, fmt.Sprintf("%d known hosts", ip.KnownTargets))
		}
		fmt.Fprintf(w, "Targets:    %s\n", strings.Join(targets, ", "))
		if len(p.Interfaces) > 1 {
			fmt.Fprintf(w, "Estimate:   %s\n", estimateText(ip.Estimate))
			fmt.Fprintf(w, "Duration:   %s\n", durationText(ip.Estimate))
		}
	}
	fmt.Fprintf(w, "Probes:     %s\n", strings.ReplaceAll(scheduler.Kind(p.Probes), ",", "; "))
	fmt.Fprintf(w, "Rates:      %s\n", ratesText(p))
	fmt.Fprintf(w, "Estimate:   %s\n", estimateText(p.Estimate))
	if p.Estimate.Packets > 0 {
		fmt.Fprintf(w, "Duration:   %s\n", durationText(p.Estimate))
		for i, as := range p.Assumptions {
			label := "            "
			if i == 0 {
				label = "Assumes:    "
			}
			fmt.Fprintf(w, "%s%s\n", label, as)
		}
	}
	if p.Allowed {
		fmt.Fprintln(w, "Verdict:    ALLOWED")
		return nil
	}
	fmt.Fprintln(w, "Verdict:    REFUSED")
	for _, r := range p.Reasons {
		fmt.Fprintf(w, "  - %s\n", r)
	}
	return nil
}

func joinPrefixes(ps []netip.Prefix) string {
	s := make([]string, len(ps))
	for i, p := range ps {
		s[i] = p.String()
	}
	return strings.Join(s, ", ")
}

func ratesText(p probe.Plan) string {
	r := p.Rates
	var parts []string
	rate := func(proto probe.Protocol) string { return trimFloat(r.Protocols[proto]) }
	if p.Probes.ARP {
		parts = append(parts, "arp "+rate(probe.ARP)+" pps")
	}
	if p.Probes.ICMP {
		parts = append(parts, "icmp "+rate(probe.ICMP)+" pps")
	}
	if len(p.Probes.TCP) > 0 {
		parts = append(parts, fmt.Sprintf("tcp %s connects/s (≤%d per interface, ≤%d per host)", rate(probe.TCP), r.TCPPerInterface, r.TCPPerHost))
	}
	if len(p.Probes.UDP) > 0 {
		parts = append(parts, "udp "+rate(probe.UDP)+" pps")
	}
	return strings.Join(parts, ", ") + fmt.Sprintf("; global cap %s pps", trimFloat(r.GlobalPPS))
}

func trimFloat(f float64) string {
	return strings.TrimSuffix(strings.TrimRight(fmt.Sprintf("%.2f", f), "0"), ".")
}

func estimateText(e probe.Estimate) string {
	var parts []string
	if e.ARPRequests > 0 {
		parts = append(parts, fmt.Sprintf("%d ARP requests", e.ARPRequests))
	}
	if e.ICMPEchoes > 0 {
		parts = append(parts, fmt.Sprintf("%d ICMP echoes", e.ICMPEchoes))
	}
	if e.TCPConnects > 0 {
		parts = append(parts, fmt.Sprintf("%d TCP connects (at most %d packets each)", e.TCPConnects, probe.TCPTokens))
	}
	if e.UDPProbes > 0 {
		parts = append(parts, fmt.Sprintf("%d UDP probes", e.UDPProbes))
	}
	if len(parts) == 0 {
		return "nothing to send"
	}
	return strings.Join(parts, ", ") + fmt.Sprintf(", at most ~%d packets", e.Packets)
}

// durationText labels the two duration estimates (Plan.Assumptions say
// what they assume).
func durationText(e probe.Estimate) string {
	return fmt.Sprintf("estimated typical %s, estimated no-response %s", approx(e.TypicalSeconds), approx(e.NoResponseSeconds))
}

// approx prints a duration estimate: "~51 s", "~4 min", "~3.2 h".
func approx(seconds float64) string {
	switch {
	case seconds < 120:
		return fmt.Sprintf("~%d s", int(math.Ceil(seconds)))
	case seconds < 2*3600:
		return fmt.Sprintf("~%d min", int(math.Ceil(seconds/60)))
	}
	return fmt.Sprintf("~%.1f h", seconds/3600)
}

func printScan(w io.Writer, res scheduler.ScanResult) {
	for _, r := range res.Interfaces {
		line := fmt.Sprintf("%s: done in %.0f s", r.Interface, r.Seconds)
		if r.Aborted != "" {
			line = fmt.Sprintf("%s: aborted after %.0f s: %s", r.Interface, r.Seconds, r.Aborted)
		}
		if _, ok := r.Counts["arp"]; ok {
			line += fmt.Sprintf("; %d hosts answered ARP", r.Responders)
		}
		fmt.Fprintln(w, line)
		keys := make([]string, 0, len(r.Counts))
		width := 0
		for k := range r.Counts {
			keys = append(keys, k)
			width = max(width, len(k))
		}
		sort.Slice(keys, func(i, j int) bool { return probeOrder(keys[i]) < probeOrder(keys[j]) })
		for _, k := range keys {
			states := make([]string, 0, len(r.Counts[k]))
			for st, n := range r.Counts[k] {
				states = append(states, fmt.Sprintf("%d %s", n, st))
			}
			sort.Strings(states)
			fmt.Fprintf(w, "  %-*s  %s\n", width, k, strings.Join(states, ", "))
		}
	}
}

// probeOrder sorts summary rows in scan order: arp, icmp, tcp, udp.
func probeOrder(k string) string {
	for i, p := range []string{"arp", "icmp", "tcp", "udp"} {
		if k == p || strings.HasPrefix(k, p+"/") {
			return fmt.Sprintf("%d%s", i, k)
		}
	}
	return "9" + k
}
