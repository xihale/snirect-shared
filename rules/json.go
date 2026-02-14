package rules

import (
	"encoding/json"
)

// FromJSON parses JSON data and updates Rules.
func (r *Rules) FromJSON(data []byte) error {
	var jsonRules JSONRules
	if err := json.Unmarshal(data, &jsonRules); err != nil {
		return err
	}

	r.FromJSONRules(&jsonRules)
	return nil
}

// ToJSON converts Rules to JSON format.
func (r *Rules) ToJSON() ([]byte, error) {
	return json.Marshal(r.ToJSONRules())
}
