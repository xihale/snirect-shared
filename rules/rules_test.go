package rules

import (
	"testing"
)

func TestNewRules(t *testing.T) {
	r := NewRules()
	if r == nil {
		t.Fatal("NewRules() returned nil")
	}
	if r.AlterHostname == nil || r.CertVerify == nil || r.Hosts == nil {
		t.Error("NewRules() didn't initialize maps")
	}
}

func TestLoadRules(t *testing.T) {
	rules, err := LoadRules()
	if err != nil {
		t.Fatalf("LoadRules() error = %v", err)
	}

	// Check that the Hong Kong Google rule is loaded
	targetSNI, ok := rules.GetAlterHostname("www.google.com.hk")
	if !ok {
		t.Error("LoadRules() didn't load alter_hostname rule")
	}
	if targetSNI != "google.com" {
		t.Errorf("LoadRules() wrong target for www.google.com.hk: got %q, want google.com", targetSNI)
	}
}

func TestGetAlterHostname(t *testing.T) {
	r := NewRules()
	r.AlterHostname["*.example.com"] = "spoof.com"
	r.AlterHostname["exact.com"] = "target.com"
	r.AlterHostname["*.base.com"] = "base-target"
	r.Init()

	tests := []struct {
		name     string
		host     string
		want     string
		wantMatch bool
	}{
		{"exact match", "exact.com", "target.com", true},
		{"wildcard match", "sub.example.com", "spoof.com", true},
		{"no match", "other.com", "", false},
		{"root domain wildcard", "example.com", "spoof.com", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := r.GetAlterHostname(tt.host)
			if ok != tt.wantMatch {
				t.Errorf("GetAlterHostname(%q) match = %v, want %v", tt.host, ok, tt.wantMatch)
			}
			if ok && got != tt.want {
				t.Errorf("GetAlterHostname(%q) = %q, want %q", tt.host, got, tt.want)
			}
		})
	}
}

func TestGetHost(t *testing.T) {
	r := NewRules()
	r.Hosts["*.lan"] = "192.168.1.1"
	r.Hosts["fixed.com"] = "10.0.0.1"
	r.Init()

	tests := []struct {
		name     string
		host     string
		want     string
		wantMatch bool
	}{
		{"exact match", "fixed.com", "10.0.0.1", true},
		{"wildcard match", "server.lan", "192.168.1.1", true},
		{"no match", "other.com", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := r.GetHost(tt.host)
			if ok != tt.wantMatch {
				t.Errorf("GetHost(%q) match = %v, want %v", tt.host, ok, tt.wantMatch)
			}
			if ok && got != tt.want {
				t.Errorf("GetHost(%q) = %q, want %q", tt.host, got, tt.want)
			}
		})
	}
}

func TestGetCertVerify(t *testing.T) {
	r := NewRules()
	r.CertVerify["*.bank.com"] = true
	r.CertVerify["*.internal"] = "allowed.com"
	r.CertVerify["*.whitelist.com"] = []interface{}{"safe1.com", "safe2.com"}
	r.CertVerify["*.strict.com"] = "strict"
	r.CertVerify["$exact.com"] = true
	r.Init()

	tests := []struct {
		name     string
		host     string
		wantVerify bool
		wantAllow  []string
		wantMatch bool
	}{
		{"bool true", "sub.bank.com", true, nil, true},
		{"string allow", "host.internal", false, []string{"allowed.com"}, true},
		{"list allow", "sub.whitelist.com", false, []string{"safe1.com", "safe2.com"}, true},
		{"strict keyword", "sub.strict.com", true, nil, true},
		{"no match", "other.com", false, nil, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := r.GetCertVerify(tt.host)
			if ok != tt.wantMatch {
				t.Errorf("GetCertVerify(%q) match = %v, want %v", tt.host, ok, tt.wantMatch)
			}
			if ok {
				if got.Verify != tt.wantVerify {
					t.Errorf("GetCertVerify(%q).Verify = %v, want %v", tt.host, got.Verify, tt.wantVerify)
				}
				if tt.wantAllow != nil && len(got.Allow) != len(tt.wantAllow) {
					t.Errorf("GetCertVerify(%q).Allow length = %d, want %d", tt.host, len(got.Allow), len(tt.wantAllow))
				}
			}
		})
	}
}

func TestDeepCopy(t *testing.T) {
	r := NewRules()
	r.AlterHostname["*.example.com"] = "spoof.com"
	r.CertVerify["*.base.com"] = true
	r.Hosts["*.lan"] = "192.168.1.1"
	r.Init()

	r2 := r.DeepCopy()

	// Modify original
	r.AlterHostname["*.example.com"] = "modified"
	r.CertVerify["*.base.com"] = false
	r.Hosts["*.lan"] = "modified"

	// Copy should be unchanged
	if got, ok := r2.GetAlterHostname("sub.example.com"); !ok || got != "spoof.com" {
		t.Error("DeepCopy didn't create independent copy")
	}

	if got, ok := r2.GetCertVerify("sub.base.com"); !ok || got.Verify != true {
		t.Error("DeepCopy didn't copy CertVerify correctly")
	}

	if got, ok := r2.GetHost("server.lan"); !ok || got != "192.168.1.1" {
		t.Error("DeepCopy didn't copy Hosts correctly")
	}
}

func TestMerge(t *testing.T) {
	r1 := NewRules()
	r1.AlterHostname["*.base.com"] = "base-target"
	r1.CertVerify["*.base.com"] = true
	r1.Init()

	r2 := NewRules()
	r2.AlterHostname["*.override.com"] = "override-target"
	r2.AlterHostname["*.base.com"] = "overridden"
	r2.Init()

	r1.Merge(r2)

	// Both rules should be present
	if _, ok := r1.GetAlterHostname("sub.override.com"); !ok {
		t.Error("Merge didn't include r2's rules")
	}

	// r2's rules take precedence
	if got, _ := r1.GetAlterHostname("sub.base.com"); got != "overridden" {
		t.Errorf("Merge precedence failed: got %q, want %q", got, "overridden")
	}
}

func TestTOMLSerialization(t *testing.T) {
	tomlData := `
[alter_hostname]
"*.google.com" = "baidu.com"

[cert_verify]
"*.google.com" = "healthdatanexus.ai"

[hosts]
"example.com" = "1.2.3.4"
`

	r := NewRules()
	if err := r.FromTOML([]byte(tomlData)); err != nil {
		t.Fatalf("FromTOML() error = %v", err)
	}

	// Check parsed data
	if got, ok := r.GetAlterHostname("www.google.com"); !ok || got != "baidu.com" {
		t.Error("FromTOML() didn't parse alter_hostname correctly")
	}

	if got, ok := r.GetHost("example.com"); !ok || got != "1.2.3.4" {
		t.Error("FromTOML() didn't parse hosts correctly")
	}

	// Serialize back
	data, err := r.ToTOML()
	if err != nil {
		t.Fatalf("ToTOML() error = %v", err)
	}
	if len(data) == 0 {
		t.Error("ToTOML() returned empty data")
	}
}

func TestJSONSerialization(t *testing.T) {
	jsonData := `{
  "rules": [
    {
      "patterns": ["*.google.com"],
      "target_sni": "baidu.com"
    }
  ],
  "cert_verify": [
    {
      "patterns": ["*.google.com"],
      "verify": "healthdatanexus.ai"
    }
  ]
}`

	r := NewRules()
	if err := r.FromJSON([]byte(jsonData)); err != nil {
		t.Fatalf("FromJSON() error = %v", err)
	}

	// Check parsed data
	if got, ok := r.GetAlterHostname("www.google.com"); !ok || got != "baidu.com" {
		t.Error("FromJSON() didn't parse rules correctly")
	}

	// Serialize back
	data, err := r.ToJSON()
	if err != nil {
		t.Fatalf("ToJSON() error = %v", err)
	}
	if len(data) == 0 {
		t.Error("ToJSON() returned empty data")
	}

	// Verify it can be parsed back
	var r2 Rules
	if err := r2.FromJSON(data); err != nil {
		t.Fatalf("ToJSON()/FromJSON() round trip error = %v", err)
	}

	if got, ok := r2.GetAlterHostname("www.google.com"); !ok || got != "baidu.com" {
		t.Error("ToJSON()/FromJSON() round trip failed")
	}
}
