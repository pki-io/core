package x509

import (
	"fmt"
	//"time"
	//"math/big"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	//"crypto/x509/pkix"
	"pki.io/crypto"
	"pki.io/document"
)

const CSRDefault string = `{
    "scope": "pki.io",
    "version": 1,
    "type": "csr-document",
    "options": "",
    "body": {
        "id": "",
        "name": "",
        "csr": "",
        "private-key": ""
    }
}`

const CSRSchema string = `{
  "$schema": "http://json-schema.org/draft-04/schema#",
  "title": "CSRDocument",
  "description": "CSR Document",
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
          "required": ["id", "name", "csr"],
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
              "csr" : {
                  "description": "PEM encoded X.509 csr",
                  "type": "string"
              },
              "private-key" : {
                  "description": "PEM encoded private key",
                  "type": "string"
              }
          }
      }
  }
}`

type CSRData struct {
	Scope   string `json:"scope"`
	Version int    `json:"version"`
	Type    string `json:"type"`
	Options string `json:"options"`
	Body    struct {
		Id         string `json:"id"`
		Name       string `json:"name"`
		CSR        string `json:"csr"`
		PrivateKey string `json:"private-key"`
	} `json:"body"`
}

type CSR struct {
	document.Document
	Data CSRData
}

func NewCSR(jsonString interface{}) (*CSR, error) {
	csr := new(CSR)
	csr.Schema = CSRSchema
	csr.Default = CSRDefault
	if err := csr.Load(jsonString); err != nil {
		return nil, fmt.Errorf("Could not create new CSR: %s", err.Error())
	} else {
		return csr, nil
	}
}

func (csr *CSR) Load(jsonString interface{}) error {
	data := new(CSRData)
	if data, err := csr.FromJson(jsonString, data); err != nil {
		return fmt.Errorf("Could not load CSR JSON: %s", err.Error())
	} else {
		csr.Data = *data.(*CSRData)
		return nil
	}
}

func (csr *CSR) Dump() string {
	if jsonString, err := csr.ToJson(csr.Data); err != nil {
		return ""
	} else {
		return jsonString
	}
}

func (csr *CSR) Generate() error {

	privateKey := crypto.GenerateRSAKey()
	csr.Data.Body.PrivateKey = string(crypto.PemEncodeRSAPrivate(privateKey))

	template := &x509.CertificateRequest{
	//Raw                      []byte // Complete ASN.1 DER content (CSR, signature algorithm and signature).
	//RawTBSCertificateRequest []byte // Certificate request info part of raw ASN.1 DER content.
	//RawSubjectPublicKeyInfo  []byte // DER encoded SubjectPublicKeyInfo.
	//RawSubject               []byte // DER encoded Subject.

	//Version            int
	//Signature          []byte
	//SignatureAlgorithm SignatureAlgorithm

	//PublicKeyAlgorithm PublicKeyAlgorithm
	//PublicKey          interface{}

	//Subject pkix.Name

	// Attributes is a collection of attributes providing
	// additional information about the subject of the certificate.
	// See RFC 2986 section 4.1.
	//Attributes []pkix.AttributeTypeAndValueSET

	// Extensions contains raw X.509 extensions. When parsing CSRs, this
	// can be used to extract extensions that are not parsed by this
	// package.
	//Extensions []pkix.Extension

	// ExtraExtensions contains extensions to be copied, raw, into any
	// marshaled CSR. Values override any extensions that would otherwise
	// be produced based on the other fields but are overridden by any
	// extensions specified in Attributes.
	//
	// The ExtraExtensions field is not populated when parsing CSRs, see
	// Extensions.
	//ExtraExtensions []pkix.Extension

	// Subject Alternate Name values.
	//DNSNames       []string
	//EmailAddresses []string
	//IPAddresses    []net.IP
	}

	der, err := x509.CreateCertificateRequest(rand.Reader, template, privateKey)
	if err != nil {
		return fmt.Errorf("Could not create certificate: %s", err.Error())
	}
	csr.Data.Body.CSR = string(PemEncodeX509CSRDER(der))
	return nil
}

func (csr *CSR) Public() (*CSR, error) {
	selfJson := csr.Dump()
	publicCSR, err := NewCSR(selfJson)
	if err != nil {
		return nil, fmt.Errorf("Could not create public CSR: %s", err.Error())
	}
	publicCSR.Data.Body.PrivateKey = ""
	return publicCSR, nil
}

func (csr *CSR) PublicKey() (*rsa.PublicKey, error) {
	if rawCSR, err := PemDecodeX509CSR([]byte(csr.Data.Body.CSR)); err != nil {
		return nil, fmt.Errorf("Could not decode csr key: %s", err.Error())
	} else {
		return rawCSR.PublicKey.(*rsa.PublicKey), nil
	}
}
