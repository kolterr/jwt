package request

import (
	"net/http"
)

//Extractor ...
type Extractor interface {
	ExtractToken(*http.Request) (string, error)
}

//HeaderExtractor ...  //从 header 里面取
type HeaderExtractor []string

//ExtractToken ...
func (o HeaderExtractor) ExtractToken(r *http.Request) (string, error) {
	for _, v := range o {
		if token := r.Header.Get(v); token != "" {
			return token, nil
		}
	}
	return "", ErrNoTokenInRequest
}

//FormExtrator ...   //从  form 里面取
type FormExtrator []string

//ExtractToken ...
func (o FormExtrator) ExtractToken(r *http.Request) (string, error) {
	r.ParseMultipartForm(10e6)
	for _, v := range o {
		if token := r.Form.Get(v); token != "" {
			return token, nil
		}
	}
	return "", ErrNoTokenInRequest
}

//MultiExtract ...
type MultiExtract []Extractor

//ExtractToken ...
func (o MultiExtract) ExtractToken(r *http.Request) (string, error) {
	for _, v := range o {
		if token, err := v.ExtractToken(r); err == nil {
			return token, nil
		}
		return "", ErrNoTokenInRequest
	}
	return "", ErrNoTokenInRequest
}

//PostExtractionFilter ...
type PostExtractionFilter struct {
	Extractor
	Filter func(string) (string, error)
}

//ExtractToken  ...
func (e *PostExtractionFilter) ExtractToken(req *http.Request) (string, error) {
	var err error
	var token string
	if token, err = e.Extractor.ExtractToken(req); token != "" {
		return e.Filter(token)
	}
	return "", err
}
