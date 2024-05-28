package cryptor

import (
	"crypto/hmac"
	"crypto/sha256"
	"github.com/gogf/gf/v2/encoding/gbase64"
	"github.com/gogf/gf/v2/errors/gcode"
	"github.com/gogf/gf/v2/errors/gerror"
	"github.com/gogf/gf/v2/frame/g"
	"github.com/wsy9981999/goframe-extends/json"
	"hash"
	"sync"
)

const (
	value = "value"
	iv    = "iv"
	mac   = "mac"
)

type payload struct {
	Value []byte
	IV    []byte
	Mac   []byte
}

var hashInstance hash.Hash
var once = sync.Once{}

func (p *payload) UnmarshalJSON(bytes []byte) (err error) {

	var m g.MapStrStr
	if err = json.Unmarshal(bytes, &m); err != nil {
		return err
	}
	for _, v := range []string{iv, value, mac} {
		val, exists := m[v]
		if !exists || len(v) == 0 {
			return gerror.NewCode(gcode.CodeMissingParameter)
		}
		switch v {
		case iv:
			p.IV, err = gbase64.DecodeString(val)
			if err != nil {
				return err
			}
		case value:
			p.Value, err = gbase64.DecodeString(val)
			if err != nil {
				return err
			}
		case mac:
			p.Mac, err = gbase64.DecodeString(val)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func (p *payload) String() string {
	marshalJSON, err := p.MarshalJSON()
	if err != nil {
		return ""
	}
	return gbase64.EncodeToString(marshalJSON)
}

func (p *payload) MarshalJSON() ([]byte, error) {
	var s = g.MapStrStr{}
	s[value] = gbase64.EncodeToString(p.Value)
	s[mac] = gbase64.EncodeToString(p.Mac)
	s[iv] = gbase64.EncodeToString(p.IV)
	return json.Marshal(s)
}

func (p *payload) check(key []byte) bool {
	newMac := calcMac(p.Value, p.IV, key)
	return hmac.Equal(newMac, p.Mac)

}

func newPayload(value, iv, key []byte) *payload {
	return &payload{
		Value: value,
		IV:    iv,
		Mac:   calcMac(value, iv, key),
	}
}

func calcMac(value, iv, key []byte) []byte {
	once.Do(func() {
		hashInstance = hmac.New(sha256.New, key)
	})
	defer hashInstance.Reset()

	hashInstance.Write(value)
	hashInstance.Write(iv)
	return hashInstance.Sum(nil)
}
func parse(value string, key []byte) (*payload, error) {
	decodeString, err := gbase64.DecodeString(value)
	if err != nil {
		return nil, err
	}
	var s *payload
	if err = json.Unmarshal(decodeString, &s); err != nil {
		return nil, err
	}
	if !s.check(key) {
		return nil, gerror.NewCode(gcode.CodeInvalidParameter)
	}
	return s, nil
}
