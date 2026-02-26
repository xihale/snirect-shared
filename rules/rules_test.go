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

func TestParseCertPolicy(t *testing.T) {
	tests := []struct {
		name       string
		input      interface{}
		wantOK     bool
		wantVerify bool
		wantAllow  int
	}{
		{name: "bool", input: true, wantOK: true, wantVerify: true, wantAllow: 0},
		{name: "strict", input: "strict", wantOK: true, wantVerify: true, wantAllow: 0},
		{name: "string allow", input: "healthdatanexus.ai", wantOK: true, wantVerify: false, wantAllow: 1},
		{name: "array allow", input: []interface{}{"a.com", "b.com"}, wantOK: true, wantVerify: false, wantAllow: 2},
		{name: "invalid", input: 123, wantOK: false, wantVerify: false, wantAllow: 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, ok := ParseCertPolicy(tt.input)
			if ok != tt.wantOK {
				t.Fatalf("ParseCertPolicy() ok=%v want=%v", ok, tt.wantOK)
			}
			if !ok {
				return
			}
			if p.Verify != tt.wantVerify {
				t.Fatalf("ParseCertPolicy() verify=%v want=%v", p.Verify, tt.wantVerify)
			}
			if len(p.Allow) != tt.wantAllow {
				t.Fatalf("ParseCertPolicy() allow=%d want=%d", len(p.Allow), tt.wantAllow)
			}
		})
	}
}

func TestTOMLSerialization(t *testing.T) {
	tomlData := `
[alter_hostname]
"www.google.com.hk" = "g.cn"

[cert_verify]
"www.google.com.hk" = "healthdatanexus.ai"

[hosts]
"store.steampowered.com" = "__AUTO__"
`

	r := NewRules()
	if err := r.FromTOML([]byte(tomlData)); err != nil {
		t.Fatalf("FromTOML() error = %v", err)
	}

	if got, ok := r.GetAlterHostname("www.google.com.hk"); !ok || got != "g.cn" {
		t.Fatal("FromTOML() did not parse alter_hostname")
	}
	if got, ok := r.GetHost("store.steampowered.com"); !ok || got != "__AUTO__" {
		t.Fatal("FromTOML() did not parse hosts")
	}
	if got, ok := r.GetCertVerify("www.google.com.hk"); !ok || got.Verify || len(got.Allow) != 1 || got.Allow[0] != "healthdatanexus.ai" {
		t.Fatalf("FromTOML() did not parse cert_verify: %+v", got)
	}

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
      "patterns": ["www.google.com.hk"],
      "target_sni": "g.cn"
    }
  ],
  "cert_verify": [
    {
      "patterns": ["www.google.com.hk"],
      "verify": "healthdatanexus.ai"
    }
  ]
}`

	r := NewRules()
	if err := r.FromJSON([]byte(jsonData)); err != nil {
		t.Fatalf("FromJSON() error = %v", err)
	}

	if got, ok := r.GetAlterHostname("www.google.com.hk"); !ok || got != "g.cn" {
		t.Fatal("FromJSON() did not parse rules")
	}
	if got, ok := r.GetCertVerify("www.google.com.hk"); !ok || got.Verify || len(got.Allow) != 1 || got.Allow[0] != "healthdatanexus.ai" {
		t.Fatalf("FromJSON() did not parse cert_verify: %+v", got)
	}

	data, err := r.ToJSON()
	if err != nil {
		t.Fatalf("ToJSON() error = %v", err)
	}
	if len(data) == 0 {
		t.Error("ToJSON() returned empty data")
	}

	var r2 Rules
	if err := r2.FromJSON(data); err != nil {
		t.Fatalf("ToJSON()/FromJSON() round trip error = %v", err)
	}

	if got, ok := r2.GetAlterHostname("www.google.com.hk"); !ok || got != "g.cn" {
		t.Error("ToJSON()/FromJSON() round trip failed")
	}
}

func TestLoadRules_ParseOnly(t *testing.T) {
	r, err := LoadRules()
	if err != nil {
		t.Fatalf("LoadRules() error = %v", err)
	}
	if r.AlterHostname == nil || r.CertVerify == nil || r.Hosts == nil {
		t.Fatalf("LoadRules() should initialize all rule maps")
	}
}

func TestLoadFetchedRules_ParseOnly(t *testing.T) {
	r, err := LoadFetchedRules()
	if err != nil {
		t.Fatalf("LoadFetchedRules() error = %v", err)
	}

	if r.AlterHostname == nil || r.CertVerify == nil || r.Hosts == nil {
		t.Fatalf("LoadFetchedRules() should initialize all rule maps")
	}
}

func TestApplyOverrides_AutoMarkerDeletes(t *testing.T) {
	base := NewRules()
	base.AlterHostname["example.com"] = "target.com"
	base.CertVerify["example.com"] = true
	base.Hosts["example.com"] = "1.1.1.1"
	base.Init()

	override := NewRules()
	override.AlterHostname["example.com"] = DefaultAutoMarker
	override.CertVerify["example.com"] = DefaultAutoMarker
	override.Hosts["example.com"] = DefaultAutoMarker
	override.Init()

	ApplyOverrides(base, override, DefaultAutoMarker)

	if _, ok := base.GetAlterHostname("example.com"); ok {
		t.Fatalf("alter_hostname should be removed by auto marker")
	}
	if _, ok := base.GetCertVerify("example.com"); ok {
		t.Fatalf("cert_verify should be removed by auto marker")
	}
	if _, ok := base.GetHost("example.com"); ok {
		t.Fatalf("hosts should be removed by auto marker")
	}
}
