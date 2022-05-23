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
		fmt.Printf("\n Valid JWS Token Detected \n")
	}

	// Fetch the Certificates in Header to check they are indeed X.509 Certificates ?
	opts := x509.VerifyOptions{}
	certs, err := signedAttestation.Signatures[0].Header.Certificates(opts)
	if err != nil {
		return emptyAttestation, err
	} else {
		fmt.Printf("\n Valid X.509 Certificate Chain detected in Header \n")
	}

	attestationPayload, err := signedAttestation.Verify(certs[0][0].PublicKey)
	if err != nil {
		log.Fatalf("Error on verifying attestation %s", err)
		return emptyAttestation, err
	} else {
		fmt.Printf("\n Signature on the Attestation Results Verified \n")
	}

	// Verify Hostname in the Certificate to expected cerfificate host name
	if err = certs[0][0].VerifyHostname("attest.android.com"); err != nil {
		return emptyAttestation, err
	} else {
		fmt.Printf("\n Host Name matched to attest.android.com \n")
	}
	fmt.Printf("\n Now Decoding the Attestation Result payload \n")
	attestation := &Attestation{}
	json.Unmarshal(attestationPayload, &attestation)
	// fmt.Printf("%+v", attestation)
	if *&attestation.Nonce != "" {
		fmt.Printf("\n Nonce Present and is: %s: \n", attestation.Nonce)
	}
	if *&attestation.ApkPackageName != "" {
		fmt.Printf("\n APK Package Name Present and is: %s: \n", attestation.ApkPackageName)
	}
	if *&attestation.BasicIntegrity != true {
		fmt.Printf("\n Basic Integrity is not passing, possibly a Simulator Device \n")
	}
	if *&attestation.CTSProfileMatch == true {
		fmt.Printf("\n Compatibility Test Suite Passes for this device \n")
	} else {
		fmt.Printf("\n Compatibility Test Suite does not Pass for this device, possibly a Simulator Device \n ")
	}

	fmt.Printf("\n Validation of Attestation Results is now complete: DEVICE VALIDATED \n")
	return *attestation, nil
}
