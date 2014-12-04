package document

const CADefault string = `{
  "scope": "pki.io",
  "version": 1,
  "type": "ca-document",
  "options": {
    "source": "00112233445566778899aabbccddeeff",
    "signature-mode": "sha256+rsa",
    "signature": "abc"
  },
  "body": {
    "tags": [],
    "certificate": "xxx",
    "private-key": "yyy"
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
          "type": "object",
          "required": ["source", "signature-mode", "signature"],
          "additionalProperties": false,
          "properties": {
              "source" : {
                  "description": "Source ID",
                  "type": "string",
                  "pattern": "^[a-fA-F0-9]{32}$"
              },
              "signature-mode" : {
                  "description": "Signature mode",
                  "type": "string"
              },
              "signature" : {
                  "description": "Base64 encoded signature",
                  "type": "string"
              }
          }
      },
      "body": {
          "description": "Body data",
          "type": "object",
          "required": ["tags","certificate","private-key"],
          "additionalProperties": false,
          "properties": {
              "tags" : {
                  "description": "Tags",
                  "type": "array",
                  "minItems": 0,
                  "uniqueItems": true,
                  "items": {
                      "type": "string"
                  }
              },
              "certificate" : {
                  "description": "Base64 encoded X.509 certificate",
                  "type": "string"
              },
              "private-key" : {
                  "description": "Base64 encoded private key",
                  "type": "string"
              }
          }
      }
  }
}`

type CADocumentData struct {
    Scope string `json:"scope"`
    Version int `json:"version"`
    Type string `json:"type"`
    Options struct {
        Source string `json:"source"`
        SignatureMode string `json:"signature-mode"`
        Signature string `json:"signature"`
    } `json:"options"`
    Body struct {
        Tags []string `json:"tags"`
        Certificate string `json:"certificate"`
        PrivateKey string `json:"private-key"`
    } `json:"body"`
}

type CADocument struct {
    document
    Data CADocumentData
}

func NewCA(jsonData interface{}) (*CADocument, error) {
    doc := new(CADocument)
    data := new(CADocumentData)
    doc.schema = CASchema
    doc.defaultValue = CADefault
    if data, err := doc.fromJson(jsonData, data); err != nil {
        return nil, err
    } else {
        doc.Data = *data.(*CADocumentData)
        return doc, nil
    }
}

func (doc *CADocument) Json() (string, error) {
    if jsonString, err := doc.toJson(doc.Data); err != nil {
        return "", err
    } else {
        return jsonString, nil
    }
}
