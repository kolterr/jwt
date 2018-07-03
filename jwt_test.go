package jwt_test

import (
	"testing"
	"time"

	jwt "ycyz.com/jwt"
)

var jwtTestTokenData = []struct {
	name   string
	claims jwt.Claims
	method string
	key    interface{}
}{
	{
		"standardClaims",
		&jwt.StandardClaims{Audience: "123131", ExpiresAt: 1522118792, IssuedAt: 1522118792, Issuer: "http://www.baidu.com"},
		"HS512",
		[]byte(`JWT`),
	},
	{
		"mapClaims",
		jwt.MapClaims{"aud": "123131", "exp": time.Now().Unix(), "iat": 1522118792, "iss": "http://www.baidu.name"},
		"HS512",
		[]byte(`123131`),
	},
	{
		"mapClaims",
		jwt.MapClaims{"aud": "123131", "exp": time.Now().Unix(), "iat": 1522118792, "iss": "http://www.baidu.name"},
		"HS256",
		[]byte(`Hello world!`),
	},
	{
		"mapClaims",
		jwt.MapClaims{"aud": "123131", "exp": time.Now().Unix(), "iat": 1522118792, "iss": "http://www.baidu.name"},
		"HS384",
		[]byte(`Hello world!`),
	},
}

func TestToken(t *testing.T) {
	for _, v := range jwtTestTokenData {
		token := jwt.NewTokenWithClaims(jwt.GetSigningMethod(v.method), v.claims)
		_, err := token.SignString()
		if err != nil {
			t.Errorf(" Error signing string:  ssss%v", err)
		}
		res, err := token.SignToken(v.key)
		t.Errorf(res)
		if err != nil {
			t.Errorf(" Error signing token: %v", err)
		}
	}
}
