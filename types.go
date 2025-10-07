package goats

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"strings"

	"go.mozilla.org/pkcs7"
)

// SignatureAlgorithm represents the algorithm to use for signing
type SignatureAlgorithm string

// SignatureStatus represents the status of a signing operation
type SignatureStatus string

const (
	// RS256 is the RSASSA-PSS algorithm with a 256-bit hash
	RS256 SignatureAlgorithm = "RS256"

	// RS384 is the RSASSA-PSS algorithm with a 384-bit hash
	RS384 SignatureAlgorithm = "RS384"

	// RS512 is the RSASSA-PSS algorithm with a 512-bit hash
	RS512 SignatureAlgorithm = "RS512"

	// PS256 is the RSASSA-PSS algorithm with a 256-bit hash
	PS256 SignatureAlgorithm = "PS256"

	// PS384 is the RSASSA-PSS algorithm with a 384-bit hash
	PS384 SignatureAlgorithm = "PS384"

	// PS512 is the RSASSA-PSS algorithm with a 512-bit hash
	PS512 SignatureAlgorithm = "PS512"

	// ES256 is the ECDSA algorithm with a 256-bit hash
	ES256 SignatureAlgorithm = "ES256"

	// ES384 is the ECDSA algorithm with a 384-bit hash
	ES384 SignatureAlgorithm = "ES384"

	// ES512 is the ECDSA algorithm with a 512-bit hash
	ES512 SignatureAlgorithm = "ES512"

	// ES256K is the ECDSA using secp256k1 curve and a 256-bit hash
	ES256K SignatureAlgorithm = "ES256K"

	// StatusInProgress indicates that the signing operation is still in progress
	// You need to re-fetch the status to get the final result
	StatusInProgress SignatureStatus = "InProgress"

	// StatusRunning indicates that the signing operation is currently still running
	// You need to re-fetch the status to get the final result
	StatusRunning SignatureStatus = "Running"

	// StatusSucceeded indicates that the signing operation has completed successfully
	StatusSucceeded SignatureStatus = "Succeeded"

	// StatusFailed indicates that the signing operation has failed
	StatusFailed SignatureStatus = "Failed"

	// StatusTimedOut indicates that the signing operation has timed out
	StatusTimedOut SignatureStatus = "TimedOut"

	// StatusNotFound indicates that the requested signing operation was not found
	StatusNotFound SignatureStatus = "NotFound"
)

var FromHashFunc = map[string]SignatureAlgorithm{
	"SHA256": RS256,
	"SHA384": RS384,
	"SHA512": RS512,
}

// SignRequest represents a request to sign a digest or list of file hashes
type SignRequest struct {
	SignatureAlgorithm   SignatureAlgorithm
	Digest               []byte
	FileHashList         [][]byte
	AuthenticodeHashList [][]byte
}

// MarshalJSON implements the json.Marshaler interface for SignRequest
// It encodes the byte slices as base64 strings
func (sr SignRequest) MarshalJSON() ([]byte, error) {
	var realSignRequest struct {
		SignatureAlgorithm         SignatureAlgorithm `json:"signatureAlgorithm"`
		DigestBase64               string             `json:"digest"`
		FileHashListBase64         []string           `json:"fileHashList,omitempty"`
		AuthenticodeHashListBase64 []string           `json:"authenticodeHashList,omitempty"`
	}

	realSignRequest.SignatureAlgorithm = sr.SignatureAlgorithm
	realSignRequest.DigestBase64 = base64.StdEncoding.EncodeToString(sr.Digest)

	if len(sr.FileHashList) > 0 {
		realSignRequest.FileHashListBase64 = make([]string, len(sr.FileHashList))
		for i, fh := range sr.FileHashList {
			realSignRequest.FileHashListBase64[i] = base64.StdEncoding.EncodeToString(fh)
		}
	}

	if len(sr.AuthenticodeHashList) > 0 {
		realSignRequest.AuthenticodeHashListBase64 = make([]string, len(sr.AuthenticodeHashList))
		for i, ah := range sr.AuthenticodeHashList {
			realSignRequest.AuthenticodeHashListBase64[i] = base64.StdEncoding.EncodeToString(ah)
		}
	}

	return json.Marshal(realSignRequest)
}

// UnmarshalJSON implements the json.Unmarshaler interface for SignRequest
// It decodes the base64 strings into byte slices
// This is strictly not needed, but implemented for completeness
func (sr *SignRequest) UnmarshalJSON(data []byte) error {
	var realSignRequest struct {
		SignatureAlgorithm         SignatureAlgorithm `json:"signatureAlgorithm"`
		digestBase64               string             `json:"digest"`
		fileHashListBase64         []string           `json:"fileHashList,omitempty"`
		authenticodeHashListBase64 []string           `json:"authenticodeHashList,omitempty"`
	}

	if err := json.Unmarshal(data, &realSignRequest); err != nil {
		return err
	}

	sr.SignatureAlgorithm = realSignRequest.SignatureAlgorithm

	if realSignRequest.digestBase64 != "" {
		digest, err := base64.StdEncoding.DecodeString(realSignRequest.digestBase64)
		if err != nil {
			return err
		}
		sr.Digest = digest
	}

	if len(realSignRequest.fileHashListBase64) > 0 {
		sr.FileHashList = make([][]byte, len(realSignRequest.fileHashListBase64))
		for i, fhb64 := range realSignRequest.fileHashListBase64 {
			fh, err := base64.StdEncoding.DecodeString(fhb64)
			if err != nil {
				return err
			}
			sr.FileHashList[i] = fh
		}
	}

	if len(realSignRequest.authenticodeHashListBase64) > 0 {
		sr.AuthenticodeHashList = make([][]byte, len(realSignRequest.authenticodeHashListBase64))
		for i, ahb64 := range realSignRequest.authenticodeHashListBase64 {
			ah, err := base64.StdEncoding.DecodeString(ahb64)
			if err != nil {
				return err
			}
			sr.AuthenticodeHashList[i] = ah
		}
	}

	return nil
}

// SignStatus represents the status of a signing operation
// It is returned from the RequestSignature and GetSignatureStatus methods
type SignStatus struct {
	OperationId             string              `json:"operationId,omitempty"`
	Status                  SignatureStatus     `json:"status,omitempty"`
	Signature               []byte              `json:"-"`
	SigningCertificateChain []*x509.Certificate `json:"-"`
}

// UnmarshalJSON implements the json.Unmarshaler interface for SignStatus
// It decodes the base64 strings into byte slices and x509 certificates
func (ss *SignStatus) UnmarshalJSON(data []byte) error {
	var realSignStatus struct {
		OperationId              string          `json:"operationId,omitempty"`
		Status                   SignatureStatus `json:"status,omitempty"`
		SignatureBase64          string          `json:"signature,omitempty"`
		SigningCertificateBase64 string          `json:"signingCertificate,omitempty"`
	}

	if err := json.Unmarshal(data, &realSignStatus); err != nil {
		return err
	}

	ss.OperationId = realSignStatus.OperationId
	ss.Status = realSignStatus.Status

	if realSignStatus.SignatureBase64 != "" {
		sig, err := base64.StdEncoding.DecodeString(realSignStatus.SignatureBase64)
		if err != nil {
			return err
		}
		ss.Signature = sig
	}

	if realSignStatus.SigningCertificateBase64 != "" {
		certBytes, err := base64.StdEncoding.DecodeString(realSignStatus.SigningCertificateBase64)
		if err != nil {
			return err
		}

		fixedNewlines := strings.ReplaceAll(string(certBytes), "\r\n", "\n")

		decodeSecond, err := base64.StdEncoding.DecodeString(fixedNewlines)
		if err != nil {
			return err
		}

		certs, err := pkcs7.Parse(decodeSecond)
		if err != nil {
			return err
		}

		ss.SigningCertificateChain = certs.Certificates
	}

	return nil
}
