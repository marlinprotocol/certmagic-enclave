package attestation

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"crypto/x509"

	"github.com/fxamacker/cbor/v2"
	"github.com/veraison/go-cose"
)

// Document represents the AWS Nitro Enclave Attestation Document.
type AttestationDocument struct {
	ModuleID    string          `cbor:"module_id" json:"module_id"`
	Timestamp   uint64          `cbor:"timestamp" json:"timestamp"`
	Digest      string          `cbor:"digest" json:"digest"`
	PCRs        map[uint][]byte `cbor:"pcrs" json:"pcrs"`
	Certificate []byte          `cbor:"certificate" json:"certificate"`
	CABundle    [][]byte        `cbor:"cabundle" json:"cabundle"`

	PublicKey []byte `cbor:"public_key" json:"public_key,omitempty"`
	UserData  []byte `cbor:"user_data" json:"user_data,omitempty"`
	Nonce     []byte `cbor:"nonce" json:"nonce,omitempty"`
}

type EnclaveConfig struct {
	TotalMemory uint64 `json:"total_memory"`
	TotalCpus   uint64 `json:"total_cpus"`
}
type coseSign1 struct {
	_ struct{} `cbor:",toarray"`

	Protected   []byte
	Unprotected cbor.RawMessage
	Payload     []byte
	Signature   []byte
}

func Verify(data []byte, pcrs map[uint][]byte, rootCertPem []byte, minCpus uint64, minMem uint64, maxAge int64) ([]byte, error) {
	coseObj := coseSign1{}

	err := cbor.Unmarshal(data, &coseObj)
	if err != nil {
		return nil, errors.New("cbor bad coseSign1")
	}

	doc := AttestationDocument{}
	err = cbor.Unmarshal(coseObj.Payload, &doc)
	if nil != err {
		return nil, errors.New("cbor bad attestation document")
	}

	// verify PCRs
	for index, value := range pcrs {
		doc_pcr, found := doc.PCRs[index]

		if !found {
			return nil, fmt.Errorf("pcr%d not found", index)
		}
		if !bytes.Equal(doc_pcr, value) {
			return nil, fmt.Errorf("pcr%d match failed", index)
		}
	}

	// validating Signature
	cert, err := x509.ParseCertificate(doc.Certificate)
	if err != nil {
		return nil, errors.New("certificate parsing failed")
	}
	publicKey, err := x509.ParsePKIXPublicKey(cert.RawSubjectPublicKeyInfo)
	if err != nil {
		return nil, errors.New("public key parsing failed")
	}
	var sign1MessagePrefix = []byte{
		0xd2, // #6.18
	}
	var msg cose.Sign1Message
	err = msg.UnmarshalCBOR(append(sign1MessagePrefix[:], data[:]...))
	if err != nil {
		return nil, errors.New("coseSign1Message unmarshal failed")
	}
	algorithm, _ := msg.Headers.Protected.Algorithm()
	verifier, _ := cose.NewVerifier(algorithm, publicKey)

	// Verify the signature using the public_key (`*rsa.PublicKey`, `*ecdsa.PublicKey`, and `ed25519.PublicKey` are accepted)
	if msg.Verify(nil, verifier) != nil {
		return nil, errors.New("cose signature verfication failed")
	}

	// Validating signing certificate PKI
	if rootCertPem != nil {
		intermediates, err := x509.ParseCertificates(concatCerts(doc.CABundle))
		if err != nil {
			return nil, errors.New("CABundle parsing failed")
		}
		root := intermediates[0]

		pool1 := x509.NewCertPool()
		pool2 := x509.NewCertPool()

		for _, intercert := range intermediates {
			pool1.AddCert(intercert)
		}
		pool2.AddCert(root)
		opts := x509.VerifyOptions{
			Intermediates: pool1,
			Roots:         pool2,
		}
		if _, err := cert.Verify(opts); err != nil {
			return nil, errors.New("certificate chain verification failed")
		}
	}

	// verify enclave size
	var userData EnclaveConfig
	if err := json.Unmarshal(doc.UserData, &userData); err != nil {
		return nil, errors.New("userData parse failed")
	}
	if userData.TotalCpus < minCpus {
		return nil, errors.New("enclave does not meet minimum cpus requirement")
	}
	if userData.TotalMemory < minMem {
		return nil, errors.New("enclave does not meet minimum memory requirement")
	}

	// verify age
	now := time.Now().UnixMilli()
	if (now - maxAge) > int64(doc.Timestamp) {
		return nil, errors.New("attestation is too old")
	}

	// return public key
	return doc.PublicKey, nil
}

func concatCerts(x interface{}) []byte {
	res := []byte{}
	for _, cert := range x.([]interface{}) {
		res = append(res, cert.([]byte)...)
	}
	return res
}
