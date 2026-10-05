package config

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"reflect"
	"sort"
	"strconv"
	"strings"

	"go.yaml.in/yaml/v3"
)

// EnvPrefix prefixes every configuration environment variable.
const EnvPrefix = "LAN_SENTINEL_"

// Reserved environment variables that are not configuration keys.
const (
	// EnvConfigPath selects the config file when --config is not given.
	EnvConfigPath = EnvPrefix + "CONFIG"
	// EnvActiveDisabled is the active-discovery kill switch (FR-CFG-4).
	EnvActiveDisabled = EnvPrefix + "ACTIVE_DISABLED"
)

// Override is a value set from a command-line flag.
type Override struct {
	Key    string // config key path, e.g. "storage.path"
	Value  string
	Origin string // e.g. "--db"
}

// LoadOptions controls Load.
type LoadOptions struct {
	// Path is the config file. Empty means $LAN_SENTINEL_CONFIG or
	// DefaultConfigPath.
	Path string
	// Environ is the process environment (os.Environ()).
	Environ []string
	Flags   []Override
}

// Loaded is a loaded configuration with the origin of every key.
type Loaded struct {
	Config *Config
	Path   string
	// Sources maps a key path to where its value came from: "file <path>",
	// "env <VAR>" or "flag <--name>". Keys not present have their default.
	Sources map[string]string
	lines   map[string]int
}

// SourceOf returns where the value of key came from.
func (l *Loaded) SourceOf(key string) string {
	if s, ok := l.Sources[key]; ok {
		return s
	}
	return "default"
}

// FieldError is one validation problem.
type FieldError struct {
	Key  string
	Line int // line in the config file, 0 if unknown
	Msg  string
}

func (e FieldError) String() string {
	if e.Line > 0 {
		return fmt.Sprintf("line %d: %s: %s", e.Line, e.Key, e.Msg)
	}
	return fmt.Sprintf("%s: %s", e.Key, e.Msg)
}

// ValidationError lists every problem found in a configuration.
type ValidationError struct {
	Path   string
	Errors []FieldError
}

func (e *ValidationError) Error() string {
	var b strings.Builder
	fmt.Fprintf(&b, "invalid configuration %s:", e.Path)
	for _, fe := range e.Errors {
		b.WriteString("\n  ")
		b.WriteString(fe.String())
	}
	return b.String()
}

// ResolvePath returns the config file path Load will use.
func ResolvePath(explicit string, environ []string) string {
	if explicit != "" {
		return explicit
	}
	if v, ok := lookupEnv(environ, EnvConfigPath); ok && v != "" {
		return v
	}
	return DefaultConfigPath
}

// Load reads, merges and validates the configuration. On a validation error
// it returns both the Loaded value (so callers can still show it) and a
// *ValidationError.
func Load(o LoadOptions) (*Loaded, error) {
	path := ResolvePath(o.Path, o.Environ)
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	return load(data, path, o)
}

func load(data []byte, path string, o LoadOptions) (*Loaded, error) {
	cfg := Defaults()
	l := &Loaded{Config: cfg, Path: path, Sources: map[string]string{}, lines: map[string]int{}}
	var errs []FieldError

	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}
	if len(doc.Content) > 0 {
		root := doc.Content[0]
		if root.Kind != yaml.MappingNode {
			return nil, fmt.Errorf("parse config %s: line %d: top level must be a mapping of keys", path, root.Line)
		}
		errs = append(errs, unknownKeys(root, reflect.TypeOf(Config{}), "")...)
		recordFile(root, "", "file "+path, l)
		// Unknown keys are already reported, so decode leniently and keep
		// validating the rest.
		dec := yaml.NewDecoder(bytes.NewReader(data))
		if err := dec.Decode(cfg); err != nil {
			return nil, fmt.Errorf("parse config %s: %w", path, err)
		}
	}

	leaves := settableLeaves()
	errs = append(errs, applyEnv(cfg, o.Environ, leaves, l)...)
	for _, f := range o.Flags {
		lf, ok := leaves.byKey[f.Key]
		if !ok {
			errs = append(errs, FieldError{Key: f.Key, Msg: "not a settable key (" + f.Origin + ")"})
			continue
		}
		if err := lf.set(cfg, f.Value); err != nil {
			errs = append(errs, FieldError{Key: f.Key, Msg: fmt.Sprintf("%s: %v", f.Origin, err)})
			continue
		}
		l.Sources[f.Key] = "flag " + f.Origin
	}

	normalize(cfg)
	for _, fe := range Validate(cfg) {
		if fe.Line == 0 {
			fe.Line = l.lineOf(fe.Key)
		}
		errs = append(errs, fe)
	}
	if len(errs) > 0 {
		sort.SliceStable(errs, func(i, j int) bool { return errs[i].Line < errs[j].Line })
		return l, &ValidationError{Path: path, Errors: errs}
	}
	return l, nil
}

// lineOf returns the file line of key or of its closest recorded parent.
func (l *Loaded) lineOf(key string) int {
	for k := key; k != ""; k = parentKey(k) {
		if n, ok := l.lines[k]; ok {
			return n
		}
	}
	return 0
}

func parentKey(k string) string {
	i := strings.LastIndexAny(k, ".[")
	if i <= 0 {
		return ""
	}
	return k[:i]
}

// normalize fills in defaults that depend on other values.
func normalize(cfg *Config) {
	for i := range cfg.Interfaces {
		ic := &cfg.Interfaces[i]
		if ic.Passive.Enabled == nil {
			v := ic.PassiveEnabled()
			ic.Passive.Enabled = &v
		}
	}
	if cfg.Profiles == nil {
		cfg.Profiles = map[string]ProfileConfig{}
	}
}

// unknownKeys reports mapping keys that do not exist in the schema.
func unknownKeys(n *yaml.Node, t reflect.Type, prefix string) []FieldError {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	var errs []FieldError
	switch {
	case n.Kind == yaml.MappingNode && t.Kind() == reflect.Struct:
		fields := yamlFields(t)
		for i := 0; i+1 < len(n.Content); i += 2 {
			k, v := n.Content[i], n.Content[i+1]
			key := join(prefix, k.Value)
			f, ok := fields[k.Value]
			if !ok {
				errs = append(errs, FieldError{Key: key, Line: k.Line, Msg: "unknown key"})
				continue
			}
			errs = append(errs, unknownKeys(v, f.Type, key)...)
		}
	case n.Kind == yaml.MappingNode && t.Kind() == reflect.Map:
		for i := 0; i+1 < len(n.Content); i += 2 {
			errs = append(errs, unknownKeys(n.Content[i+1], t.Elem(), join(prefix, n.Content[i].Value))...)
		}
	case n.Kind == yaml.SequenceNode && t.Kind() == reflect.Slice:
		for i, item := range n.Content {
			errs = append(errs, unknownKeys(item, t.Elem(), fmt.Sprintf("%s[%d]", prefix, i))...)
		}
	}
	return errs
}

// recordFile records the source and line of every leaf set in the file.
// Sequences of scalars count as one leaf; sequences of mappings are walked
// per item.
func recordFile(n *yaml.Node, prefix, source string, l *Loaded) {
	switch n.Kind {
	case yaml.MappingNode:
		for i := 0; i+1 < len(n.Content); i += 2 {
			key := join(prefix, n.Content[i].Value)
			l.lines[key] = n.Content[i].Line
			recordFile(n.Content[i+1], key, source, l)
		}
	case yaml.SequenceNode:
		if len(n.Content) > 0 && n.Content[0].Kind == yaml.MappingNode {
			for i, item := range n.Content {
				key := fmt.Sprintf("%s[%d]", prefix, i)
				l.lines[key] = item.Line
				recordFile(item, key, source, l)
			}
			return
		}
		l.Sources[prefix] = source
	default:
		l.Sources[prefix] = source
	}
}

func join(prefix, key string) string {
	if prefix == "" {
		return key
	}
	return prefix + "." + key
}

func yamlFields(t reflect.Type) map[string]reflect.StructField {
	m := map[string]reflect.StructField{}
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		name := strings.Split(f.Tag.Get("yaml"), ",")[0]
		if name == "" || name == "-" {
			continue
		}
		m[name] = f
	}
	return m
}

// leaf is a scalar configuration key that can be set from env or flags.
type leaf struct {
	key   string
	env   string
	index []int
}

type leafIndex struct {
	byKey map[string]leaf
	byEnv map[string]leaf
}

var (
	durationType = reflect.TypeOf(Duration(0))
	byteSizeType = reflect.TypeOf(ByteSize(0))
)

// settableLeaves lists every scalar key reachable through structs only.
// Lists of structs (interfaces) and maps (profiles) are file-only.
func settableLeaves() leafIndex {
	idx := leafIndex{byKey: map[string]leaf{}, byEnv: map[string]leaf{}}
	var walk func(t reflect.Type, prefix string, path []int)
	walk = func(t reflect.Type, prefix string, path []int) {
		for name, f := range yamlFields(t) {
			key := join(prefix, name)
			p := append(append([]int(nil), path...), f.Index...)
			switch {
			case f.Type == durationType || f.Type == byteSizeType:
			case f.Type.Kind() == reflect.Struct:
				walk(f.Type, key, p)
				continue
			case f.Type.Kind() == reflect.Slice && f.Type.Elem().Kind() == reflect.String:
			case f.Type.Kind() == reflect.String, f.Type.Kind() == reflect.Bool,
				f.Type.Kind() == reflect.Int, f.Type.Kind() == reflect.Float64:
			default:
				continue
			}
			lf := leaf{key: key, env: EnvPrefix + strings.ToUpper(strings.ReplaceAll(key, ".", "_")), index: p}
			idx.byKey[key] = lf
			idx.byEnv[lf.env] = lf
		}
	}
	walk(reflect.TypeOf(Config{}), "", nil)
	return idx
}

func (lf leaf) set(cfg *Config, raw string) error {
	v := reflect.ValueOf(cfg).Elem().FieldByIndex(lf.index)
	switch {
	case v.Type() == durationType:
		var d Duration
		if err := d.parse(raw); err != nil {
			return err
		}
		v.Set(reflect.ValueOf(d))
	case v.Type() == byteSizeType:
		var b ByteSize
		if err := b.parse(raw); err != nil {
			return err
		}
		v.Set(reflect.ValueOf(b))
	case v.Kind() == reflect.String:
		v.SetString(raw)
	case v.Kind() == reflect.Bool:
		b, err := strconv.ParseBool(strings.TrimSpace(raw))
		if err != nil {
			return fmt.Errorf("invalid boolean %q", raw)
		}
		v.SetBool(b)
	case v.Kind() == reflect.Int:
		n, err := strconv.Atoi(strings.TrimSpace(raw))
		if err != nil {
			return fmt.Errorf("invalid integer %q", raw)
		}
		v.SetInt(int64(n))
	case v.Kind() == reflect.Float64:
		f, err := strconv.ParseFloat(strings.TrimSpace(raw), 64)
		if err != nil {
			return fmt.Errorf("invalid number %q", raw)
		}
		v.SetFloat(f)
	case v.Kind() == reflect.Slice:
		var items []string
		for _, s := range strings.Split(raw, ",") {
			if s = strings.TrimSpace(s); s != "" {
				items = append(items, s)
			}
		}
		v.Set(reflect.ValueOf(items))
	default:
		return errors.New("unsupported key type")
	}
	return nil
}

func applyEnv(cfg *Config, environ []string, leaves leafIndex, l *Loaded) []FieldError {
	var errs []FieldError
	for _, kv := range environ {
		name, value, ok := strings.Cut(kv, "=")
		if !ok || !strings.HasPrefix(name, EnvPrefix) {
			continue
		}
		if name == EnvConfigPath || name == EnvActiveDisabled {
			continue
		}
		lf, ok := leaves.byEnv[name]
		if !ok {
			errs = append(errs, FieldError{Key: name, Msg: "unknown environment variable"})
			continue
		}
		if err := lf.set(cfg, value); err != nil {
			errs = append(errs, FieldError{Key: lf.key, Msg: fmt.Sprintf("%s: %v", name, err)})
			continue
		}
		l.Sources[lf.key] = "env " + name
	}
	return errs
}

func lookupEnv(environ []string, name string) (string, bool) {
	for _, kv := range environ {
		if k, v, ok := strings.Cut(kv, "="); ok && k == name {
			return v, true
		}
	}
	return "", false
}
