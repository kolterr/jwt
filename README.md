# jwt
Golang implementation of JSON Web Tokens (JWT)
## Features 

This library supports the parsing and verification as well as the generation and signing of JWTs. Current supported signing algorithms are HMAC SHA, though hooks are present for adding your own.

## Example
```
//  generate Token
c := &jwt.StandardClaims{Audience: "123131", ExpiresAt: time.Now().Unix(), IssuedAt: time.Now().Unix(), Issuer: "http://www.baidu.com"}
// or
c := jwt.MapClaims{"aud": "123131", "exp": time.Now().Unix(), "iat": time.Now().Unix(), "iss": "http://www.baidu.name"},
token := jwt.NewTokenWithClaims(jwt.GetSigningMethod(“HS256”),c)

headPayloadString, _ := token.SignString() 

tokenString,_ :=token.SignToken([]byte(`JWT`))
```
//  Parse Token 
```
case MapClaims
    token, err := parser.ParseWithClaims(v.tokenString, jwt.MapClaims{}, v.keyfunc)
case YourClaims
    token, err := parser.ParseWithClaims(v.tokenString, &jwt.YourClaims{}, v.keyfunc)
```
### so can get header and payload
```
    header := token.Header
    payload := token.Claim
```
### verify token is valid 
>  token.IsValid()
## If you want to customize the load，you should  use Map or Struct to implements Claims insterface

```
type yourClaims struct{
    Name   string  `json:"name"`
    ID     int64   `json:"id"`
}

func (o *yourClaims) Valid() error{
    if condition {
        return errors.New(error)
    }
    ...
    return nil
}

```

## Add signMethod for your business  Example:Rsa or ECDSA, You can refer hmac package    <https://github.com/ycyz/jwt/blob/master/hmac.go>
