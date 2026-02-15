package rules

import _ "embed"

// FetchedRulesTOML contains rules fetched from upstream (Cealing-Host).
//
//go:embed fetched.toml
var FetchedRulesTOML string

// UserRulesTOML contains default user rules template.
//
//go:embed rules.toml
var UserRulesTOML string
