package jwt

import "sync"

//sign  methods set
var signMethods = map[string]func() SignMethod{}
var signingMethodLock = new(sync.RWMutex)

//SignMethod interface{}
type SignMethod interface {
	Verify(signingString, signature string, key interface{}) error //compare signed string with not encode string
	Sign(signingString string, key interface{}) (string, error)    // returns encoded signature or error
	Alias() string                                                 // returns the alg identifier for this method
}

//RegisterSignMethod  register a factory function for signment
func RegisterSignMethod(alg string, f func() SignMethod) {
	signingMethodLock.Lock()
	defer signingMethodLock.Unlock()
	signMethods[alg] = f
}

// GetSigningMethod  Get a signing method from an "alias" string
func GetSigningMethod(alg string) (method SignMethod) {
	signingMethodLock.RLock()
	defer signingMethodLock.RUnlock()
	if methodF, ok := signMethods[alg]; ok {
		method = methodF()
	}
	return
}
