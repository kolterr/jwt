package request

import (
	"errors"
	"net/http"

	jwt "ycyz.com/jwt"
)

//ErrNoTokenInRequest ...
var (
	ErrNoTokenInRequest = errors.New("no token present in request")
)

//ParseFromRequest ...
func ParseFromRequest(req *http.Request, extractor Extractor, keyFunc jwt.KeyFunc, options ...ParseFromRequestOption) (token *jwt.Token, err error) {
	// Create basic parser struct
	p := &fromRequestParser{req, extractor, nil, nil}

	// Handle options
	for _, option := range options {
		option(p)
	}

	// Set defaults
	if p.claims == nil {
		p.claims = jwt.MapClaims{}
	}
	if p.parser == nil {
		p.parser = &jwt.Parser{}
	}

	// perform extract
	tokenString, err := p.extractor.ExtractToken(req)
	if err != nil {
		return nil, err
	}

	// perform parse
	return p.parser.ParseWithClaims(tokenString, p.claims, keyFunc)
}

//ParseFromRequestWithClaims ...
func ParseFromRequestWithClaims(req *http.Request, extractor Extractor, claims jwt.Claims, keyFunc jwt.KeyFunc) (token *jwt.Token, err error) {
	return ParseFromRequest(req, extractor, keyFunc, WithClaims(claims))
}

type fromRequestParser struct {
	req       *http.Request
	extractor Extractor
	claims    jwt.Claims
	parser    *jwt.Parser
}

//ParseFromRequestOption ...
type ParseFromRequestOption func(*fromRequestParser)

// WithClaims  Parse with custom claims
func WithClaims(claims jwt.Claims) ParseFromRequestOption {
	return func(p *fromRequestParser) {
		p.claims = claims
	}
}

//WithParser  Parse using a custom parser
func WithParser(parser *jwt.Parser) ParseFromRequestOption {
	return func(p *fromRequestParser) {
		p.parser = parser
	}
}
