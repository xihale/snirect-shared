package rules

import (
	"strings"
	"sync"

	"github.com/xihale/snirect-shared/pattern"
)

// LoadRules loads rules from embedded TOML file (fetched rules only).
func LoadRules() (*Rules, error) {
	rules := NewRules()
	if err := rules.FromTOML([]byte(FetchedRulesTOML)); err != nil {
		return nil, err
	}
	// FromTOML already calls Init internally
	return rules, nil
}

// LoadDefaultRules loads merged rules (fetched + user template).
func LoadDefaultRules() (*Rules, error) {
	rules := NewRules()

	// First load fetched rules
	if err := rules.FromTOML([]byte(FetchedRulesTOML)); err != nil {
		return nil, err
	}

	// Then merge user rules (user rules take precedence)
	userRules := NewRules()
	if err := userRules.FromTOML([]byte(UserRulesTOML)); err != nil {
		return nil, err
	}
	rules.Merge(userRules)

	return rules, nil
}

// CertPolicy represents a certificate verification policy.
type CertPolicy struct {
	Verify bool     // Whether to verify hostname
	Allow  []string // Allowed hostnames (if Verify is false)
}

// Rules represents all rules for SNI spoofing and certificate handling.
type Rules struct {
	mu sync.RWMutex

	// SNI alteration rules: pattern -> target SNI
	AlterHostname map[string]string

	// Certificate verification rules: pattern -> policy
	CertVerify map[string]interface{}

	// Static hosts mapping: pattern -> IP
	Hosts map[string]string

	// Pre-computed sorted keys for efficient matching
	alterHostnameKeys []string
	certVerifyKeys    []string
	hostsKeys         []string
}

// NewRules creates a new empty Rules instance.
func NewRules() *Rules {
	return &Rules{
		AlterHostname: make(map[string]string),
		CertVerify:    make(map[string]interface{}),
		Hosts:         make(map[string]string),
	}
}

// Init initializes and normalizes rules for efficient matching.
func (r *Rules) Init() {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.AlterHostname = normalizeMap(r.AlterHostname)
	r.CertVerify = normalizeMap(r.CertVerify)
	r.Hosts = normalizeMap(r.Hosts)

	r.alterHostnameKeys = getSortedKeys(r.AlterHostname)
	r.certVerifyKeys = getSortedKeys(r.CertVerify)
	r.hostsKeys = getSortedKeys(r.Hosts)
}

// normalizeMap trims the `$` prefix from keys (legacy format).
func normalizeMap[T any](m map[string]T) map[string]T {
	if m == nil {
		return nil
	}
	newM := make(map[string]T, len(m))
	for k, v := range m {
		newK := strings.TrimPrefix(k, "$")
		newM[newK] = v
	}
	return newM
}

// getSortedKeys returns keys sorted by length (longest first) for pattern matching.
func getSortedKeys[T any](m map[string]T) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	// Sort by length descending so more specific patterns match first
	for i := 0; i < len(keys); i++ {
		for j := i + 1; j < len(keys); j++ {
			if len(keys[j]) > len(keys[i]) {
				keys[i], keys[j] = keys[j], keys[i]
			}
		}
	}
	return keys
}

// DeepCopy creates a deep copy of the rules.
func (r *Rules) DeepCopy() *Rules {
	r.mu.RLock()
	defer r.mu.RUnlock()

	newR := &Rules{
		AlterHostname:     copyMap(r.AlterHostname),
		CertVerify:        copyMap(r.CertVerify),
		Hosts:             copyMap(r.Hosts),
		alterHostnameKeys: make([]string, len(r.alterHostnameKeys)),
		certVerifyKeys:    make([]string, len(r.certVerifyKeys)),
		hostsKeys:         make([]string, len(r.hostsKeys)),
	}
	copy(newR.alterHostnameKeys, r.alterHostnameKeys)
	copy(newR.certVerifyKeys, r.certVerifyKeys)
	copy(newR.hostsKeys, r.hostsKeys)
	return newR
}

// copyMap creates a shallow copy of a map.
func copyMap[T any](m map[string]T) map[string]T {
	if m == nil {
		return nil
	}
	newM := make(map[string]T, len(m))
	for k, v := range m {
		newM[k] = v
	}
	return newM
}

// GetAlterHostname returns the target SNI for a host, or false if no rule matches.
func (r *Rules) GetAlterHostname(host string) (string, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	// Exact match first
	if val, ok := r.AlterHostname[host]; ok {
		return val, true
	}

	// Pattern matching
	for _, k := range r.alterHostnameKeys {
		if pattern.MatchPattern(k, host) {
			return r.AlterHostname[k], true
		}
	}

	return "", false
}

// GetHost returns the mapped IP for a host, or false if no rule matches.
func (r *Rules) GetHost(host string) (string, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	// Exact match first
	if val, ok := r.Hosts[host]; ok {
		return val, true
	}

	// Pattern matching
	for _, k := range r.hostsKeys {
		if pattern.MatchPattern(k, host) {
			return r.Hosts[k], true
		}
	}

	return "", false
}

// GetCertVerify returns the certificate verification policy for a host, or false if no rule matches.
func (r *Rules) GetCertVerify(host string) (CertPolicy, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	// Exact match first
	if val, ok := r.CertVerify[host]; ok {
		p, _ := ParseCertPolicy(val)
		return p, true
	}

	// Pattern matching
	for _, k := range r.certVerifyKeys {
		if pattern.MatchPattern(k, host) {
			p, _ := ParseCertPolicy(r.CertVerify[k])
			return p, true
		}
	}

	return CertPolicy{}, false
}

// Merge merges another Rules instance into this one.
// The other rules take precedence for conflicting keys.
func (r *Rules) Merge(other *Rules) {
	r.mu.Lock()
	defer r.mu.Unlock()

	other.mu.RLock()
	defer other.mu.RUnlock()

	for k, v := range other.AlterHostname {
		r.AlterHostname[k] = v
	}
	for k, v := range other.CertVerify {
		r.CertVerify[k] = v
	}
	for k, v := range other.Hosts {
		r.Hosts[k] = v
	}

	// Call Init logic inline to avoid deadlock (r.mu is already held)
	r.AlterHostname = normalizeMap(r.AlterHostname)
	r.CertVerify = normalizeMap(r.CertVerify)
	r.Hosts = normalizeMap(r.Hosts)
	r.alterHostnameKeys = getSortedKeys(r.AlterHostname)
	r.certVerifyKeys = getSortedKeys(r.CertVerify)
	r.hostsKeys = getSortedKeys(r.Hosts)
}

// ParseCertPolicy parses a policy value from config.
// Supports: true/false, string (hostname), []string (hostnames), "strict" keyword.
func ParseCertPolicy(val interface{}) (CertPolicy, bool) {
	policy := CertPolicy{}

	switch v := val.(type) {
	case bool:
		policy.Verify = v
		return policy, true
	case string:
		if v == "strict" {
			policy.Verify = true
			return policy, true
		}
		if v != "" {
			policy.Verify = false
			policy.Allow = []string{v}
			return policy, true
		}
	case []interface{}:
		policy.Verify = false
		policy.Allow = make([]string, len(v))
		for i, item := range v {
			if s, ok := item.(string); ok {
				policy.Allow[i] = s
			}
		}
		return policy, true
	}

	return policy, false
}

// ToJSONRules converts Rules to JSON format for Android.
type JSONRules struct {
	Rules        []JSONRule       `json:"rules"`
	CertVerify   []JSONCertVerify `json:"cert_verify"`
	NameServers  []string         `json:"nameservers,omitempty"`
	BootstrapDNS []string         `json:"bootstrap_dns,omitempty"`
	CheckHN      bool             `json:"check_hostname"`
	MTU          int              `json:"mtu,omitempty"`
	EnableIPv6   bool             `json:"enable_ipv6,omitempty"`
	LogLevel     string           `json:"log_level,omitempty"`
}

// JSONRule represents a rule in JSON format.
type JSONRule struct {
	Patterns   []string `json:"patterns"`
	TargetSNI  *string  `json:"target_sni"`
	TargetIP   *string  `json:"target_ip"`
	CertVerify any      `json:"cert_verify,omitempty"`
}

// JSONCertVerify represents a cert verify rule in JSON format.
type JSONCertVerify struct {
	Patterns []string `json:"patterns"`
	Verify   any      `json:"verify"`
}

// ToJSONRules converts Rules to JSONRules format.
func (r *Rules) ToJSONRules() *JSONRules {
	r.mu.RLock()
	defer r.mu.RUnlock()

	jsonRules := &JSONRules{
		Rules:      make([]JSONRule, 0, len(r.AlterHostname)),
		CertVerify: make([]JSONCertVerify, 0, len(r.CertVerify)),
	}

	for pattern, target := range r.AlterHostname {
		jsonRules.Rules = append(jsonRules.Rules, JSONRule{
			Patterns:  []string{pattern},
			TargetSNI: &target,
		})
	}

	for pattern, policy := range r.CertVerify {
		jsonRules.CertVerify = append(jsonRules.CertVerify, JSONCertVerify{
			Patterns: []string{pattern},
			Verify:   policy,
		})
	}

	return jsonRules
}

// FromJSONRules updates Rules from JSONRules format.
func (r *Rules) FromJSONRules(jsonRules *JSONRules) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.AlterHostname = make(map[string]string, len(jsonRules.Rules))
	r.CertVerify = make(map[string]interface{}, len(jsonRules.CertVerify))

	for _, rule := range jsonRules.Rules {
		for _, pattern := range rule.Patterns {
			if rule.TargetSNI != nil {
				r.AlterHostname[pattern] = *rule.TargetSNI
			}
		}
	}

	for _, rule := range jsonRules.CertVerify {
		for _, pattern := range rule.Patterns {
			r.CertVerify[pattern] = rule.Verify
		}
	}

	// Call Init logic inline to avoid deadlock (r.mu is already held)
	r.AlterHostname = normalizeMap(r.AlterHostname)
	r.CertVerify = normalizeMap(r.CertVerify)
	r.Hosts = normalizeMap(r.Hosts)
	r.alterHostnameKeys = getSortedKeys(r.AlterHostname)
	r.certVerifyKeys = getSortedKeys(r.CertVerify)
	r.hostsKeys = getSortedKeys(r.Hosts)
}
