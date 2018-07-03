package jwt

import (
	"bytes"
	"encoding/json"
	"strings"
)

//Parser ...
type Parser struct {
	UseJSONNumber bool
}

//ParseMapClaims ...
func (o *Parser) ParseMapClaims(tokenString string, keyFunc KeyFunc) (*Token, error) {
	return o.ParseWithClaims(tokenString, &MapClaims{}, keyFunc)
}

//ParseWithClaims ...
func (o *Parser) ParseWithClaims(tokenString string, clarms Claims, keyfunc KeyFunc) (*Token, error) {
	token, T, err := o.parseTokenString(tokenString, clarms)
	if err != nil {
		return token, err
	}
	if err = token.Claim.Valid(); err != nil { //载荷是否验证通过
		return token, err
	}

	var key interface{}
	if key, err = keyfunc(token); err != nil {
		return token, err
	}
	if err = token.Method.Verify(strings.Join(T[0:2], "."), T[2], key); err != nil { //验证Token是否正确
		return token, err
	}
	token.valid = true
	return token, nil
}

func (o *Parser) parseTokenString(tokenString string, clarms Claims) (token *Token, T []string, err error) {
	T = strings.Split(tokenString, ".") // jwt 拆分
	if len(T) < 3 {
		return nil, T, ErrTokenSeg
	}
	token = &Token{Raw: tokenString}
	var (
		header, clarmsByte []byte
	)

	if header, err = DecodeBase(T[0]); err != nil { // 检查头部
		if strings.HasPrefix(strings.ToLower(tokenString), "bearer ") {
			return token, T, ErrContainBear
		}
		return token, T, err
	}
	if err = json.Unmarshal(header, &token.Header); err != nil {
		return token, T, err
	}
	token.Claim = clarms

	if clarmsByte, err = DecodeBase(T[1]); err != nil {
		return token, T, err
	}

	dec := json.NewDecoder(bytes.NewBuffer(clarmsByte))
	if o.UseJSONNumber {
		dec.UseNumber()
	}
	if c, ok := token.Claim.(MapClaims); ok {
		err = dec.Decode(&c)
	} else {
		err = dec.Decode(&clarms)
	}
	if err != nil {
		return token, T, err
	}
	//check signure method
	if m, ok := token.Header["alg"].(string); ok {
		if token.Method = GetSigningMethod(m); token.Method == nil {
			return token, T, ErrSignedMethod
		}
	} else {
		return token, T, ErrSignedMethodNotInstall
	}
	return token, T, nil
}
