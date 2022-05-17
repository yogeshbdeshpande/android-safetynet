package safetynet

import (
	"crypto/x509"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"gopkg.in/square/go-jose.v2"
)

// for mocking
var TimeFunction = time.Now

/*
func Validate(token []byte) (out Attestation, err error) {
	jwt, err := jwt.ParseSigned(string(token))
	if err != nil {
		return
	}

	if len(jwt.Headers) != 1 {
		err = ErrorSafetyNetDecode
		return
	}
	key := jwt.Headers[0]

	certs, err := key.Certificates(x509.VerifyOptions{
		DNSName:                   "attest.android.com",
		MaxConstraintComparisions: 5,
		CurrentTime:               TimeFunction(),
	})
	if err != nil {
		return
	}

	err = jwt.Claims(certs[0][0].PublicKey, &out)
	if err != nil {
		return
	}

	if out.Error != "" {
		err = ErrorSafetyNetError
		return
	}

	return
}
*/

/* New code starts here */
func ValidateNew(token string) (out Attestation, err error) {
	emptyAttestation := Attestation{}
	signedAttestation, err := jose.ParseSigned(token)
	if err != nil {
		return emptyAttestation, err
	}

	opts := x509.VerifyOptions{}
	certs, err := signedAttestation.Signatures[0].Header.Certificates(opts)
	if err != nil {
		return emptyAttestation, err
	}
	attestationPayload, err := signedAttestation.Verify(certs[0][0].PublicKey)
	if err != nil {
		log.Fatalf("Error on verifying attestation %s", err)
		return emptyAttestation, err
	}
	attestation := &Attestation{}
	json.Unmarshal(attestationPayload, &attestation)
	fmt.Printf("%+v", attestation)
	return *attestation, nil
}
