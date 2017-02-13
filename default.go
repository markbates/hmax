package hmax

import "net/http"

var defaultHMAX = HMAX{Header: "X-Signature"}

func Sign(secret, message []byte) string {
	defaultHMAX.Secret = secret
	return defaultHMAX.Sign(message)
}

func Verify(signature string, secret, message []byte) bool {
	defaultHMAX.Secret = secret
	return defaultHMAX.Verify(signature, message)
}

func SignRequest(req *http.Request, secret []byte) error {
	defaultHMAX.Secret = secret
	return defaultHMAX.SignRequest(req)
}

func VerifyRequest(req *http.Request, secret []byte) (bool, error) {
	defaultHMAX.Secret = secret
	return defaultHMAX.VerifyRequest(req)
}
