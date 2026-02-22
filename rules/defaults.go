package rules

import _ "embed"

// FetchedRulesTOML contains rules fetched from upstream (Cealing-Host).
//
//go:embed fetched.toml
var FetchedRulesTOML string

// DefaultRulesTOML contains built-in default rules shipped with the program.
// These rules override fetched rules and can be updated with app releases.
//
//go:embed rules.default.toml
var DefaultRulesTOML string

// UserRulesTOML contains default user rules template.
//
//go:embed rules.toml
var UserRulesTOML string
