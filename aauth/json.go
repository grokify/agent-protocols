package aauth

import "encoding/json"

// encodeJSON marshals a value to JSON bytes.
func encodeJSON(v interface{}) ([]byte, error) {
	return json.Marshal(v)
}
