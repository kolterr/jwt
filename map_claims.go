package jwt

import (
	"encoding/json"
	"fmt"
	"time"
)

// MapClaims ...  key-value payload
type MapClaims map[string]interface{}

//Valid ...
func (o MapClaims) Valid() error {
	var now = time.Now().Unix()
	if ok := o.VerifyExpAt(now, false); !ok {
		overTime := time.Unix(now, 0).Sub(time.Unix(o["exp"].(int64), 0))
		return fmt.Errorf(ErrExpired, overTime)
	}
	if ok := o.VerifyIssAt(now, false); ok {
		return ErrIssAted
	}

	return nil
}

//VerifyExpAt ...
func (o MapClaims) VerifyExpAt(cmp int64, require bool) bool {
	switch exp := o["exp"].(type) {
	case float64:
		return verifyExp(int64(exp), cmp, require)
	case json.Number:
		v, _ := exp.Int64()
		return verifyExp(v, cmp, require)
	}
	return require == false
}

//VerifyAud ...
func (o MapClaims) VerifyAud(cmp string, require bool) bool {
	aud, _ := o["aud"].(string)
	return verifyAud(aud, cmp, require)
}

//VerifyIssAt ...
func (o MapClaims) VerifyIssAt(cmp int64, require bool) bool {
	switch iat := o["iat"].(type) {
	case float64:
		return verifyIssAt(int64(iat), cmp, require)
	case json.Number:
		v, _ := iat.Int64()
		return verifyIssAt(v, cmp, require)
	}
	return require == false
}

func (o MapClaims) verifyIssAt(cmp string, require bool) bool {
	iss, _ := o["iss"].(string)
	return verifyAud(iss, cmp, require)
}
