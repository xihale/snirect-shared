package rules

import (
	"github.com/pelletier/go-toml/v2"
)

// TOMLRules represents rules in TOML format (used by desktop Go project).
type TOMLRules struct {
	AlterHostname map[string]string      `toml:"alter_hostname"`
	CertVerify    map[string]interface{} `toml:"cert_verify"`
	Hosts         map[string]string      `toml:"hosts"`
}

// FromTOML parses TOML data and updates Rules.
func (r *Rules) FromTOML(data []byte) error {
	var tomlRules TOMLRules
	if err := toml.Unmarshal(data, &tomlRules); err != nil {
		return err
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	r.AlterHostname = tomlRules.AlterHostname
	r.CertVerify = tomlRules.CertVerify
	r.Hosts = tomlRules.Hosts

	// Call Init logic inline to avoid deadlock (r.mu is already held)
	r.AlterHostname = normalizeMap(r.AlterHostname)
	r.CertVerify = normalizeMap(r.CertVerify)
	r.Hosts = normalizeMap(r.Hosts)
	r.alterHostnameKeys = getSortedKeys(r.AlterHostname)
	r.certVerifyKeys = getSortedKeys(r.CertVerify)
	r.hostsKeys = getSortedKeys(r.Hosts)

	return nil
}

// ToTOML converts Rules to TOML format.
func (r *Rules) ToTOML() ([]byte, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	tomlRules := TOMLRules{
		AlterHostname: r.AlterHostname,
		CertVerify:    r.CertVerify,
		Hosts:         r.Hosts,
	}

	return toml.Marshal(tomlRules)
}
