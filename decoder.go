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

// Method to Validate the Attestation Results received in a SafetyNet Attestation Response.

func ValidateNew(token string) (out Attestation, err error) {
	emptyAttestation := Attestation{}
	signedAttestation, err := jose.ParseSigned(token)
	if err != nil {
		return emptyAttestation, err
	} else {
		fmt.Printf("Valid JWS Token Detected")
	}

	// Fetch the Certificates in Header to check they are indeed X.509 Certificates ?
	opts := x509.VerifyOptions{}
	certs, err := signedAttestation.Signatures[0].Header.Certificates(opts)
	if err != nil {
		return emptyAttestation, err
	} else {
		fmt.Printf("\nValid X.509 Certificate Chain detected\n")
	}

	attestationPayload, err := signedAttestation.Verify(certs[0][0].PublicKey)
	if err != nil {
		log.Fatalf("Error on verifying attestation %s", err)
		return emptyAttestation, err
	} else {
		fmt.Printf("\nSignature on the Token Verified\n")
	}

	// Verify Hostname in the Certificate to expected cerfificate host name
	if err = certs[0][0].VerifyHostname("attest.android.com"); err != nil {
		return emptyAttestation, err
	} else {
		fmt.Printf("\nHost Name matched to attest.android.com \n")
	}

	attestation := &Attestation{}
	json.Unmarshal(attestationPayload, &attestation)
	fmt.Printf("%+v", attestation)
	return *attestation, nil
}
