// ThreatSpec package github.com/pki-io/core/x509 as x509
package x509

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"github.com/pki-io/core/crypto"
	"github.com/pki-io/core/document"
	"time"
)

const CertificateDefault string = `{
    "scope": "pki.io",
    "version": 1,
    "type": "certificate-document",
    "options": "",
    "body": {
        "id": "",
        "name": "",
        "key-type": "ec",
        "expiry": 0,
        "tags": [],
        "certificate": "",
        "private-key": "",
        "ca-certificate": ""
    }
}`

const CertificateSchema string = `{
  "$schema": "http://json-schema.org/draft-04/schema#",
  "title": "CertificateDocument",
  "description": "Certificate Document",
  "type": "object",
  "required": ["scope","version","type","options","body"],
  "additionalProperties": false,
  "properties": {
      "scope": {
          "description": "Scope of the document",
          "type": "string"
      },
      "version": {
          "description": "Document schema version",
          "type": "integer"
      },
      "type": {
          "description": "Type of document",
          "type": "string"
      },
      "options": {
          "description": "Options data",
          "type": "string"
      },
      "body": {
          "description": "Body data",
          "type": "object",
          "required": ["id", "name", "key-type", "tags", "certificate", "private-key", "ca-certificate"],
          "additionalProperties": false,
          "properties": {
              "id" : {
                  "description": "Entity ID",
                  "type": "string"
              },
              "name" : {
                  "description": "Entity name",
                  "type": "string"
              },
              "expiry": {
                  "description": "Expiry period in days",
                  "type": "integer"
              },
              "key-type": {
              	  "description": "Key type. Must be either rsa or ec",
              	  "type": "string"
              },
              "tags": {
                  "description": "Tags defined for cert",
                  "type": "array"
              },
              "certificate" : {
                  "description": "PEM encoded X.509 certificate",
                  "type": "string"
              },
              "private-key" : {
                  "description": "PEM encoded private key",
                  "type": "string"
              },
              "ca-certificate" : {
                  "description": "PEM encoded CA certificate",
                  "type": "string"
              }
          }
      }
  }
}`

type CertificateData struct {
	Scope   string `json:"scope"`
	Version int    `json:"version"`
	Type    string `json:"type"`
	Options string `json:"options"`
	Body    struct {
		Id            string   `json:"id"`
		Name          string   `json:"name"`
		Expiry        int      `json:"expiry"`
		KeyType       string   `json:"key-type"`
		Tags          []string `json:"tags"`
		Certificate   string   `json:"certificate"`
		PrivateKey    string   `json:"private-key"`
		CACertificate string   `json:"ca-certificate"`
	} `json:"body"`
}

type Certificate struct {
	document.Document
	Data CertificateData
}

// ThreatSpec TMv0.1 for NewCertificate
// Creates new certificate for App:X509

func NewCertificate(jsonString interface{}) (*Certificate, error) {
	certificate := new(Certificate)
	certificate.Schema = CertificateSchema
	certificate.Default = CertificateDefault
	if err := certificate.Load(jsonString); err != nil {
		return nil, fmt.Errorf("Could not create new Certificate: %s", err)
	} else {
		return certificate, nil
	}
}

// ThreatSpec TMv0.1 for Certificate.Load
// Does certificate JSON loading for App:X509

func (certificate *Certificate) Load(jsonString interface{}) error {
	data := new(CertificateData)
	if data, err := certificate.FromJson(jsonString, data); err != nil {
		return fmt.Errorf("Could not load Certificate JSON: %s", err)
	} else {
		certificate.Data = *data.(*CertificateData)
		return nil
	}
}

// ThreatSpec TMv0.1 for Certificate.Dump
// Does certificate JSON dumping for App:X509
func (certificate *Certificate) Dump() string {
	if jsonString, err := certificate.ToJson(certificate.Data); err != nil {
		return ""
	} else {
		return jsonString
	}
}

func (certificate *Certificate) Name() string {
	return certificate.Data.Body.Name
}

func (certificate *Certificate) Id() string {
	return certificate.Data.Body.Id
}

// ThreatSpec TMv0.1 for Certificate.Generate
// Does certificate generation for App:X509

func (certificate *Certificate) Generate(parentCertificate interface{}, subject *pkix.Name) error {
	//https://www.socketloop.com/tutorials/golang-create-x509-certificate-private-and-public-keys

	serial, err := NewSerial()
	if err != nil {
		return fmt.Errorf("Could not create serial: %s", err)
	}

	notBefore := time.Now()
	notAfter := notBefore.AddDate(0, 0, certificate.Data.Body.Expiry)

	template := &x509.Certificate{
		IsCA: false,
		BasicConstraintsValid: true,
		SerialNumber:          serial,
		Subject:               *subject,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		// see http://golang.org/pkg/crypto/x509/#KeyUsage
		// http://security.stackexchange.com/questions/24106/which-key-usages-are-required-by-each-key-exchange-method
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageKeyEncipherment | x509.KeyUsageKeyAgreement,
	}

	var privateKey interface{}
	var publicKey interface{}

	switch crypto.KeyType(certificate.Data.Body.KeyType) {
	case crypto.KeyTypeRSA:
		rsaKey, err := crypto.GenerateRSAKey()
		if err != nil {
			return fmt.Errorf("Could not generate RSA key: %s", err)
		}
		privateKey = rsaKey
		publicKey = &rsaKey.PublicKey
	case crypto.KeyTypeEC:
		ecKey, err := crypto.GenerateECKey()
		if err != nil {
			return fmt.Errorf("Could not generate ec key: %s", err)
		}
		privateKey = ecKey
		publicKey = &ecKey.PublicKey
	}

	var parent *x509.Certificate
	var signingKey interface{}

	switch t := parentCertificate.(type) {
	case *CA:
		parent, err = parentCertificate.(*CA).Certificate()
		if err != nil {
			return fmt.Errorf("Could not get certificate: %s", err)
		}
		signingKey, err = parentCertificate.(*CA).PrivateKey()
		if err != nil {
			return fmt.Errorf("Could not get private key: %s", err)
		}
		// TODO - Should probably track CA by name and load cert if required.
		certificate.Data.Body.CACertificate = parentCertificate.(*CA).Data.Body.Certificate
	case nil:
		// Self signed
		parent = template
		signingKey = privateKey
	default:
		return fmt.Errorf("Invalid parent type: %T", t)
	}

	der, err := x509.CreateCertificate(rand.Reader, template, parent, publicKey, signingKey)
	if err != nil {
		return fmt.Errorf("Could not create certificate: %s", err)
	}
	certificate.Data.Body.Certificate = string(PemEncodeX509CertificateDER(der))
	certificate.Data.Body.Id = fmt.Sprintf("%d", template.SerialNumber)
	enc, err := crypto.PemEncodePrivate(privateKey)
	if err != nil {
		return fmt.Errorf("Failed to pem encode private key: %s", err)
	}
	certificate.Data.Body.PrivateKey = string(enc)

	return nil
}

// ThreatSpec TMv0.1 for Certificate.Certificate
// Returns certificate for App:X509

func (certificate *Certificate) Certificate() (*x509.Certificate, error) {
	return PemDecodeX509Certificate([]byte(certificate.Data.Body.Certificate))
}

// ThreatSpec TMv0.1 for Certificate.PrivateKey
// Returns certificate private key for App:X509
func (certificate *Certificate) PrivateKey() (interface{}, error) {
	if privateKey, err := crypto.PemDecodePrivate([]byte(certificate.Data.Body.PrivateKey)); err != nil {
		return nil, fmt.Errorf("Could not decode rsa private key: %s", err)
	} else {
		return privateKey, nil
	}
}
