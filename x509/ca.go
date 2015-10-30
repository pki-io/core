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

const CADefault string = `{
    "scope": "pki.io",
    "version": 1,
    "type": "ca-document",
    "options": "",
    "body": {
        "id": "",
        "name": "",
        "certificate": "",
        "ca-expiry": 1,
        "cert-expiry": 1,
        "key-type": "ec",
        "private-key": "",
        "dn-scope": {
            "country": "",
            "organization": "",
            "organizational-unit": "",
            "locality": "",
            "province": "",
            "street-address": "",
            "postal-code": ""
        }
    }
}`

const CASchema string = `{
  "$schema": "http://json-schema.org/draft-04/schema#",
  "title": "CADocument",
  "description": "CA Document",
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
          "required": ["id", "name", "ca-expiry", "cert-expiry", "key-type", "certificate", "private-key", "dn-scope"],
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
              "ca-expiry" : {
                  "description": "CA expiry period in days",
                  "type": "integer"
              },
              "cert-expiry" : {
                  "description": "Cert expiry period in days",
                  "type": "integer"
              },
              "certificate" : {
                  "description": "PEM encoded X.509 certificate",
                  "type": "string"
              },
              "key-type": {
              	  "description": "the type of keys to use. Must be either rsa or ec.",
              	  "type": "string"
              },
              "private-key" : {
                  "description": "PEM encoded private key",
                  "type": "string"
              },
              "dn-scope": {
                  "description": "Scope the DN for all child certs",
                  "type": "object",
                  "required": [
                      "country", 
                      "organization", 
                      "organizational-unit", 
                      "locality",
                      "province",
                      "street-address",
                      "postal-code"
                  ],
                  "additionalProperties": false,
                  "properties": {
                      "country": {
                          "description": "X.509 distinguished name country field",
                          "type": "string"
                      },
                      "organization": {
                          "description": "X.509 distinguished name organization field",
                          "type": "string"
                      },
                      "organizational-unit": {
                          "description": "X.509 distinguished name organizational-unit field",
                          "type": "string"
                      },
                      "locality": {
                          "description": "X.509 distinguished name locality field",
                          "type": "string"
                      },
                      "province": {
                          "description": "X.509 distinguished name province field",
                          "type": "string"
                      },
                      "street-address": {
                          "description": "X.509 distinguished name street-address field",
                          "type": "string"
                      },
                      "postal-code": {
                          "description": "X.509 distinguished name postal-code field",
                          "type": "string"
                      }
                  }
              }
          }
      }
  }
}`

type CAData struct {
	Scope   string `json:"scope"`
	Version int    `json:"version"`
	Type    string `json:"type"`
	Options string `json:"options"`
	Body    struct {
		Id          string `json:"id"`
		Name        string `json:"name"`
		CAExpiry    int    `json:"ca-expiry"`
		CertExpiry  int    `json:"cert-expiry"`
		Certificate string `json:"certificate"`
		PrivateKey  string `json:"private-key"`
		KeyType     string `json:"key-type"`
		DNScope     struct {
			Country            string `json:"country"`
			Organization       string `json:"organization"`
			OrganizationalUnit string `json:"organizational-unit"`
			Locality           string `json:"locality"`
			Province           string `json:"province"`
			StreetAddress      string `json:"street-address"`
			PostalCode         string `json:"postal-code"`
		} `json:"dn-scope"`
	} `json:"body"`
}

type CA struct {
	document.Document
	Data CAData
}

// ThreatSpec TMv0.1 for NewCA
// Does new CA creation for App:X509

func NewCA(jsonString interface{}) (*CA, error) {
	ca := new(CA)
	ca.Schema = CASchema
	ca.Default = CADefault
	if err := ca.Load(jsonString); err != nil {
		return nil, fmt.Errorf("Could not create new CA: %s", err)
	} else {
		return ca, nil
	}
}

// ThreatSpec TMv0.1 for CA.Load
// Does CA JSON loading for App:X509

func (ca *CA) Load(jsonString interface{}) error {
	data := new(CAData)
	if data, err := ca.FromJson(jsonString, data); err != nil {
		return fmt.Errorf("Could not load CA JSON: %s", err)
	} else {
		ca.Data = *data.(*CAData)
		return nil
	}
}

func (ca *CA) Id() string {
	return ca.Data.Body.Id
}

func (ca *CA) Name() string {
	return ca.Data.Body.Name
}

// ThreatSpec TMv0.1 for CA.Dump
// Does CA JSON dumping for App:X509

func (ca *CA) Dump() string {
	if jsonString, err := ca.ToJson(ca.Data); err != nil {
		return ""
	} else {
		return jsonString
	}
}

// ThreatSpec TMv0.1 for CA.GenerateRoot
// Does Root CA certificate generation for App:X509

func (ca *CA) GenerateRoot() error {
	return ca.GenerateSub(nil)
}

// ThreatSpec TMv0.1 for CA.GenerateSub
// Does Sub-CA certificate generation for App:X509
func (ca *CA) GenerateSub(parentCA interface{}) error {
	//https://www.socketloop.com/tutorials/golang-create-x509-certificate-private-and-public-keys

	// Override from parent if necessary
	// Ugly as hell. Need to fix.
	switch parentCA.(type) {
	case *CA:
		p := parentCA.(*CA)
		if p.Data.Body.DNScope.Country != "" {
			ca.Data.Body.DNScope.Country = p.Data.Body.DNScope.Country
		}
		if p.Data.Body.DNScope.Organization != "" {
			ca.Data.Body.DNScope.Organization = p.Data.Body.DNScope.Organization
		}
		if p.Data.Body.DNScope.OrganizationalUnit != "" {
			ca.Data.Body.DNScope.OrganizationalUnit = p.Data.Body.DNScope.OrganizationalUnit
		}
		if p.Data.Body.DNScope.Locality != "" {
			ca.Data.Body.DNScope.Locality = p.Data.Body.DNScope.Locality
		}
		if p.Data.Body.DNScope.Province != "" {
			ca.Data.Body.DNScope.Province = p.Data.Body.DNScope.Province
		}
		if p.Data.Body.DNScope.StreetAddress != "" {
			ca.Data.Body.DNScope.StreetAddress = p.Data.Body.DNScope.StreetAddress
		}
		if p.Data.Body.DNScope.PostalCode != "" {
			ca.Data.Body.DNScope.PostalCode = p.Data.Body.DNScope.PostalCode
		}
	}

	subject := new(pkix.Name)
	subject.CommonName = ca.Data.Body.Name

	// Set using CA's DNScope
	if ca.Data.Body.DNScope.Country != "" {
		subject.Country = []string{ca.Data.Body.DNScope.Country}
	}
	if ca.Data.Body.DNScope.Organization != "" {
		subject.Organization = []string{ca.Data.Body.DNScope.Organization}
	}
	if ca.Data.Body.DNScope.OrganizationalUnit != "" {
		subject.OrganizationalUnit = []string{ca.Data.Body.DNScope.OrganizationalUnit}
	}
	if ca.Data.Body.DNScope.Locality != "" {
		subject.Locality = []string{ca.Data.Body.DNScope.Locality}
	}
	if ca.Data.Body.DNScope.Province != "" {
		subject.Province = []string{ca.Data.Body.DNScope.Province}
	}
	if ca.Data.Body.DNScope.StreetAddress != "" {
		subject.StreetAddress = []string{ca.Data.Body.DNScope.StreetAddress}
	}
	if ca.Data.Body.DNScope.PostalCode != "" {
		subject.PostalCode = []string{ca.Data.Body.DNScope.PostalCode}
	}

	serial, err := NewSerial()
	if err != nil {
		return fmt.Errorf("Could not create serial: %s", err)
	}

	notBefore := time.Now()
	notAfter := notBefore.AddDate(0, 0, ca.Data.Body.CAExpiry)

	template := &x509.Certificate{
		IsCA: true,
		BasicConstraintsValid: true,
		SubjectKeyId:          []byte{1, 2, 3},
		SerialNumber:          serial,
		Subject:               *subject,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		// see http://golang.org/pkg/crypto/x509/#KeyUsage
		// http://security.stackexchange.com/questions/49229/root-certificate-key-usage-non-self-signed-end-entity
		//ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	var privateKey interface{}
	var publicKey interface{}
	keyType := crypto.KeyType(ca.Data.Body.KeyType)

	switch keyType {
	case crypto.KeyTypeRSA:
		rsaKey, err := crypto.GenerateRSAKey()
		if err != nil {
			return fmt.Errorf("Failed to generate RSA Key: %s", err)
		}
		privateKey = rsaKey
		publicKey = &rsaKey.PublicKey
	case crypto.KeyTypeEC:
		ecKey, err := crypto.GenerateECKey()
		if err != nil {
			return fmt.Errorf("")
		}
		privateKey = ecKey
		publicKey = &ecKey.PublicKey
	default:
		return fmt.Errorf("Invalid key type: %s", keyType)
	}

	var parent *x509.Certificate
	var signingKey interface{}

	switch t := parentCA.(type) {
	case *CA:
		parent, err = parentCA.(*CA).Certificate()
		if err != nil {
			return fmt.Errorf("Could not get certificate: %s", err)
		}
		signingKey, err = parentCA.(*CA).PrivateKey()
		if err != nil {
			return fmt.Errorf("Could not get private key: %s", err)
		}
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
	ca.Data.Body.Id = NewID()
	ca.Data.Body.Certificate = string(PemEncodeX509CertificateDER(der))
	enc, err := crypto.PemEncodePrivate(privateKey)
	if err != nil {
		return fmt.Errorf("Could not pem encode private key: %s", err)
	}
	ca.Data.Body.PrivateKey = string(enc)

	return nil
}

// ThreatSpec TMv0.1 for CA.Certificate
// Returns CA certificate for App:X509

func (ca *CA) Certificate() (*x509.Certificate, error) {
	return PemDecodeX509Certificate([]byte(ca.Data.Body.Certificate))
}

// ThreatSpec TMv0.1 for CA.PrivateKey
// Returns CA private key for App:X509

func (ca *CA) PrivateKey() (interface{}, error) {
	if privateKey, err := crypto.PemDecodePrivate([]byte(ca.Data.Body.PrivateKey)); err != nil {
		return nil, fmt.Errorf("Could not decode rsa private key: %s", err)
	} else {
		return privateKey, nil
	}
}

// ThreatSpec TMv0.1 for CA.Sign
// Does CSR signing by CA for App:X509
func (ca *CA) Sign(csr *CSR, useCSRSubject bool) (*Certificate, error) {

	subject := new(pkix.Name)

	if useCSRSubject {
		decodedCSR, err := PemDecodeX509CSR([]byte(csr.Data.Body.CSR))
		if err != nil {
			return nil, err
		}
		subject = &decodedCSR.Subject
	} else {
		subject.CommonName = csr.Data.Body.Name

		if ca.Data.Body.DNScope.Country != "" {
			subject.Country = []string{ca.Data.Body.DNScope.Country}
		}
		if ca.Data.Body.DNScope.Organization != "" {
			subject.Organization = []string{ca.Data.Body.DNScope.Organization}
		}
		if ca.Data.Body.DNScope.OrganizationalUnit != "" {
			subject.OrganizationalUnit = []string{ca.Data.Body.DNScope.OrganizationalUnit}
		}
		if ca.Data.Body.DNScope.Locality != "" {
			subject.Locality = []string{ca.Data.Body.DNScope.Locality}
		}
		if ca.Data.Body.DNScope.Province != "" {
			subject.Province = []string{ca.Data.Body.DNScope.Province}
		}
		if ca.Data.Body.DNScope.StreetAddress != "" {
			subject.StreetAddress = []string{ca.Data.Body.DNScope.StreetAddress}
		}
		if ca.Data.Body.DNScope.PostalCode != "" {
			subject.PostalCode = []string{ca.Data.Body.DNScope.PostalCode}
		}
	}

	serial, err := NewSerial()
	if err != nil {
		return nil, fmt.Errorf("Could not create serial: %s", err)
	}

	notBefore := time.Now()
	notAfter := notBefore.AddDate(0, 0, ca.Data.Body.CertExpiry)

	template := &x509.Certificate{
		IsCA: false,
		BasicConstraintsValid: true,
		SubjectKeyId:          []byte{1, 2, 3},
		SerialNumber:          serial,
		Subject:               *subject,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		// see http://golang.org/pkg/crypto/x509/#KeyUsage
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
	}
	parent, _ := ca.Certificate()
	csrPublicKey, err := csr.PublicKey()
	if err != nil {
		return nil, fmt.Errorf("Could not get public key from CSR: %s", err)
	}
	signingKey, _ := ca.PrivateKey()

	der, err := x509.CreateCertificate(rand.Reader, template, parent, csrPublicKey, signingKey)
	if err != nil {
		return nil, fmt.Errorf("Could not create certificate der: %s", err)
	}

	cert, err := NewCertificate(nil)
	if err != nil {
		return nil, fmt.Errorf("Could not create certificate: %s", err)
	}
	cert.Data.Body.Id = csr.Data.Body.Id
	cert.Data.Body.Name = csr.Data.Body.Name
	cert.Data.Body.Certificate = string(PemEncodeX509CertificateDER(der))
	cert.Data.Body.KeyType = ca.Data.Body.KeyType
	cert.Data.Body.CACertificate = ca.Data.Body.Certificate
	return cert, nil
}
