package jwt

import (
	"crypto/subtle"
	"fmt"
	"time"
)

//Claims ...  payload
type Claims interface {
	Valid() error
}

//StandardClaims ... implements  Claims
type StandardClaims struct {
	Audience  string `json:"aud"`
	ExpiresAt int64  `json:"exp"`
	IssuedAt  int64  `json:"iat"`
	Issuer    string `json:"iss"`
	Subject   string `json:"sub"`
}

//Valid ...
func (o *StandardClaims) Valid() error {
	var now = time.Now().Unix()
	if ok := o.VerifyExpireAt(now, false); !ok {
		overTime := time.Unix(now, 0).Sub(time.Unix(o.ExpiresAt, 0))
		return fmt.Errorf(ErrExpired, overTime)
	}
	if ok := o.VerifyIssAt(now, false); !ok {
		return ErrIssAted
	}

	return nil
}

//VerifyExpireAt ...  Determine if the token expires
func (o *StandardClaims) VerifyExpireAt(now int64, required bool) bool { // 当前时间
	return verifyExp(o.ExpiresAt, now, required)
}

func verifyExp(exp, now int64, required bool) bool {
	if exp == 0 {
		return !required
	}
	return exp <= now
}

//VerifyIssAt ...   verfify token generation time
func (o *StandardClaims) VerifyIssAt(now int64, required bool) bool {
	return verifyIssAt(o.IssuedAt, now, required)
}

func verifyIssAt(issAt, now int64, required bool) bool {
	if issAt == 0 {
		return !required
	}
	return issAt <= now
}

//VerifyAud ...
func (o *StandardClaims) VerifyAud(aud string, required bool) bool {
	return verifyAud(o.Audience, aud, required)
}

func verifyAud(cmp, aud string, required bool) bool {
	if aud == "" {
		return !required
	}
	if ok := subtle.ConstantTimeCompare([]byte(aud), []byte(cmp)); ok != 0 {
		return true
	}
	return false
}

//VerifySub ...
func (o *StandardClaims) VerifySub(cmp string, required bool) bool {
	return verifyAud(o.Subject, cmp, required)
}

//VerifyISs ...
func (o *StandardClaims) VerifyISs(cmp string, required bool) bool {
	return verifyAud(o.Issuer, cmp, required)
}
