package jwt

import (
	_ "crypto/hmac"
	 _"crypto/sha256"
	_ "crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
)

// ...
var (
	ErrHashUnavailable        = errors.New("the requested hash function is unavailable")
	ErrSignStringEmpty        = errors.New("signingString not allowed to be empty")
	ErrSignatureInvalid       = errors.New("signature is invalid")
	ErrInvalidKeyType         = errors.New("key is of invalid type")
	ErrExpired                = "token is expired by %v"
	ErrIssAted                = errors.New("token used before issued ")
	ErrTokenSeg               = errors.New("token contains an invalid number of segments")
	ErrContainBear            = errors.New("tokenstring should not contain 'bearer'")
	ErrSignedMethod           = errors.New("signing method (alg) is unavailable")
	ErrSignedMethodNotInstall = errors.New("signing method (alg) is unspecified")
)

//KeyFunc ...
type KeyFunc func(*Token) (interface{}, error)

//EncodeBase ...
func EncodeBase(seg []byte) string {
	return strings.TrimRight(base64.URLEncoding.EncodeToString(seg), "=")
}

//DecodeBase ...
func DecodeBase(str string) ([]byte, error) {
	if l := len(str) % 4; l > 0 {
		str += strings.Repeat("=", 4-l)
	}
	return base64.URLEncoding.DecodeString(str)
}

//Token ..
type Token struct {
	Header    map[string]interface{} //
	Method    SignMethod             //  Signature method which to encode string
	Claim     Claims                 //  payload  interface{}
	signature interface{}            //  The third secret of the token. when you Parse a token
	Raw       string                 //  enode signure string
	valid     bool                   //  after verify/parse
}

//New ...
func New(m SignMethod, maps MapClaims) *Token {
	return NewTokenWithClaims(m, maps)
}

//NewTokenWithClaims ...
func NewTokenWithClaims(m SignMethod, claims Claims) *Token { // sign method payload  interface{}
	return &Token{
		Header: map[string]interface{}{
			"typ": "JWT",
			"alg": m.Alias(),
		},
		Method: m,
		Claim:  claims,
	}
}

//SignString ...
func (o *Token) SignString() (string, error) { // return encode header and payload
	partsOne, err := json.Marshal(o.Header)
	if err != nil {
		return "", err
	}
	partsTwo, err := json.Marshal(o.Claim)
	if err != nil {
		return "", err
	}
	return strings.Join([]string{EncodeBase(partsOne), EncodeBase(partsTwo)}, "."), nil
}

//SignToken ...
func (o *Token) SignToken(secret interface{}) (string, error) { //Signature key
	var (
		str, signed string
		err         error
	)
	if str, err = o.SignString(); err != nil {
		return "", err
	}
	if signed, err = o.Method.Sign(str, secret); err != nil {
		return "", err
	}
	o.signature = secret
	return strings.Join([]string{str, signed}, "."), nil

}

//IsValid ... return a boolean indicating whether the token is valid
func (o *Token) IsValid() bool {
	return o.valid
}
