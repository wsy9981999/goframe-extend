//go:build !cgo || !amd64

package json

import "encoding/json"

func Marshal(v any) ([]byte, error) {
	return json.Marshal(v)
}
func Unmarshal(data []byte, v any) error {
	return json.Unmarshal(data, v)
}
