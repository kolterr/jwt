package jwt_test

import (
	"encoding/json"
	"fmt"
	"reflect"
	"testing"

	jwt "ycyz.com/jwt"
)

var (
	defaultKeyFunc jwt.KeyFunc = func(*jwt.Token) (interface{}, error) { return []byte("123131"), nil }
)

var jwtTestParseData = []struct {
	name        string
	tokenString string
	keyfunc     jwt.KeyFunc
	claims      jwt.Claims
	valid       bool
	parser      *jwt.Parser
}{
	{
		"standardClaims",
		"eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiIxMjMxMzEiLCJleHAiOjUwMDAsImlhdCI6MTUyMjExODc5MiwiaXNzIjoiaHR0cDovL3d3dy5iYWlkdS5uYW1lIiwic3ViIjoiIn0.c75jC4B_MxC1PYfmTWKetVYcELZuHa3bvQW1to5rtUf41ycjGVQ4KkcFtPvvYZDDdBJxTIW1jch4_-m7GhhfTA",
		defaultKeyFunc,
		&jwt.StandardClaims{Audience: "123131", ExpiresAt: 5000, IssuedAt: 1522118792, Issuer: "http://www.baidu.name"},
		false,
		nil,
	},
	{
		"mapClaims",
		"eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiIxMjMxMzEiLCJleHAiOjE1MjIxMjg2NjYsImlhdCI6MTUyMjExODc5MiwiaXNzIjoiaHR0cDovL3d3dy5iYWlkdS5uYW1lIn0.VXnqRuDfF_SG2BKtCA5CBGHc2e5mmO3ZAfaW5tTpyW53flqStat0hmciS7ME84IWcaKTT4kzWIm44K7LlI6l1w",
		defaultKeyFunc,
		jwt.MapClaims{"aud": "123131", "exp": json.Number(fmt.Sprintf("%v", 1522128666)), "iat": json.Number(fmt.Sprintf("%v", 1522118792)), "iss": "http://www.baidu.name"},
		false,
		nil,
	},
}

func TestParse(t *testing.T) {
	for _, v := range jwtTestParseData {
		var parser = v.parser
		if v.parser == nil {
			parser = new(jwt.Parser)
		}
		var err error
		var token *jwt.Token
		parser.UseJSONNumber = true
		switch v.claims.(type) {
		case jwt.MapClaims:
			token, err = parser.ParseWithClaims(v.tokenString, jwt.MapClaims{}, v.keyfunc)
		case *jwt.StandardClaims:
			token, err = parser.ParseWithClaims(v.tokenString, &jwt.StandardClaims{}, v.keyfunc)
		}
		if !reflect.DeepEqual(v.claims, token.Claim) {
			t.Errorf("[%v] Claims mismatch. Expecting: %v  Got: %v", v.name, v.claims, token.Claim)
		}
		if err != nil {
			t.Errorf("[%v] Error while verifying token: %T:%v", v.name, err, err)
		}
	}
}
