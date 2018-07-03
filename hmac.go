package jwt

import (
	"crypto"
	"crypto/hmac"
)

type signMethodHmac struct {
	Name string
	Hash crypto.Hash
}

var (
	signMethodHmacHS256 *signMethodHmac
	signMethodHmacHS384 *signMethodHmac
	signMethodHmacHS512 *signMethodHmac
)

func init() {
	signMethodHmacHS256 = &signMethodHmac{"HS256", crypto.SHA256}
	signMethodHmacHS384 = &signMethodHmac{"HS384", crypto.SHA384}
	signMethodHmacHS512 = &signMethodHmac{"HS512", crypto.SHA512}
	RegisterSignMethod(signMethodHmacHS256.Alias(), func() SignMethod {
		return signMethodHmacHS256
	})
	RegisterSignMethod(signMethodHmacHS384.Alias(), func() SignMethod {
		return signMethodHmacHS384
	})
	RegisterSignMethod(signMethodHmacHS512.Alias(), func() SignMethod {
		return signMethodHmacHS512
	})
}

func (o *signMethodHmac) Alias() string { // get  signMethod name
	return o.Name
}

func (o *signMethodHmac) Sign(signingString string, key interface{}) (string, error) { // signingString   key:secret
	var secret []byte
	var ok bool
	if secret, ok = key.([]byte); ok {
		if signingString == "" {
			return "", ErrSignStringEmpty
		}
		if !o.Hash.Available() {
			return "", ErrHashUnavailable
		}
		hash := hmac.New(o.Hash.New, secret)
		hash.Write([]byte(signingString))
		return EncodeBase(hash.Sum(nil)), nil
	}
	return "", ErrInvalidKeyType
}

func (o *signMethodHmac) Verify(signingString, signureString string, key interface{}) error { // signingString:已签名的header+payload signure:已签名且未解密的字符串  key:密匙
	var secret []byte
	var ok bool
	if secret, ok = key.([]byte); ok {
		if signingString == "" {
			return ErrSignStringEmpty
		}
		res, err := DecodeBase(signureString)
		if err != nil {
			return err
		}
		if !o.Hash.Available() {
			return ErrHashUnavailable
		}
		hash := hmac.New(o.Hash.New, secret)
		hash.Write([]byte(signingString))
		if ok := !hmac.Equal(hash.Sum(nil), res); ok {
			return ErrSignatureInvalid
		}
		return nil
	}
	return ErrInvalidKeyType
}
