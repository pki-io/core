package index

import (
	"fmt"
	"github.com/pki-io/core/document"
)

const OrgIndexDefault string = `{
    "scope": "pki.io",
    "version": 1,
    "type": "org-index-document",
    "options": "",
    "body": {
        "id": "",
        "parent-id": "",
        "tags": {
          "ca-forward": {},
          "ca-reverse": {},
          "entity-forward": {},
          "entity-reverse": {},
          "cert-forward": {},
          "cert-reverse": {},
          "csr-forward": {},
          "csr-reverse": {}
        },
        "nodes": {},
        "admins": {},
        "pairing-keys": {},
        "invite-keys": {},
        "cas": {},
        "certs": {},
        "csrs": {}
    }
}`

const OrgIndexSchema string = `{
  "$schema": "http://json-schema.org/draft-04/schema#",
  "title": "OrgIndexDocument",
  "description": "Org Index Document",
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
          "required": ["id", "parent-id", "invite-keys", "pairing-keys", "nodes", "admins", "cas", "certs", "tags"],
          "additionalProperties": false,
          "properties": {
              "id": {
                  "description": "ID",
                  "type": "string"
              },
              "parent-id" : {
                  "description": "Parent ID",
                  "type": "string"
              },
              "pairing-keys": {
                  "description": "Pairing Keys",
                  "type": "object"
              },
              "invite-keys": {
                  "description": "Invite Keys",
                  "type": "object"
              },
              "nodes": {
                  "description": "Nodes name to ID map",
                  "type": "object"
              },
              "admins": {
                  "description": "Admins name to ID map",
                  "type": "object"
              },
              "cas": {
                  "description": "CAs name to ID map",
                  "type": "object"
              },
              "certs": {
                  "description": "Certs name to ID map",
                  "type": "object"
              },
              "csrs": {
                  "description": "CSRs name to ID map",
                  "type": "object"
              },
              "tags": {
                  "description": "Tags",
                  "type": "object",
                  "required": ["ca-forward","ca-reverse","entity-forward","entity-reverse", "cert-forward", "cert-reverse", "csr-forward", "csr-reverse"],
                  "additionalProperties": false,
                  "properties": {
                      "ca-forward": {
                          "description": "Tags to CAs",
                          "type": "object"
                      },
                      "ca-reverse": {
                          "description": "CA to tags",
                          "type": "object"
                      },
                      "entity-forward": {
                          "description": "Tags to entities",
                          "type": "object"
                      },
                      "entity-reverse": {
                          "description": "Entities to tags",
                          "type": "object"
                      },
                      "cert-forward": {
                          "description": "Tags to Certs",
                          "type": "object"
                      },
                      "cert-reverse": {
                          "description": "Cert to tags",
                          "type": "object"
                      },
                      "csr-forward": {
                          "description": "Tags to CSRs",
                          "type": "object"
                      },
                      "csr-reverse": {
                          "description": "CSRs to tags",
                          "type": "object"
                      } 
                  }
              }
          }
      }
  }
}`

type PairingKey struct {
	Key  string   `json:"key"`
	Tags []string `json:"tags"`
}

type InviteKey struct {
	Name string `json:"name"`
	Key  string `json:"key"`
}

type OrgIndexData struct {
	Scope   string `json:"scope"`
	Version int    `json:"version"`
	Type    string `json:"type"`
	Options string `json:"options"`
	Body    struct {
		Id          string                 `json:"id"`
		ParentId    string                 `json:"parent-id"`
		PairingKeys map[string]*PairingKey `json:"pairing-keys"`
		InviteKeys  map[string]*InviteKey  `json:"invite-keys"`
		Nodes       map[string]string      `json:"nodes"`
		Admins      map[string]string      `json:"admins"`
		CAs         map[string]string      `json:"cas"`
		Certs       map[string]string      `json:"certs"`
		CSRs        map[string]string      `json:"csrs"`
		Tags        struct {
			CAForward     map[string][]string `json:"ca-forward"`
			CAReverse     map[string][]string `json:"ca-reverse"`
			EntityForward map[string][]string `json:"entity-forward"`
			EntityReverse map[string][]string `json:"entity-reverse"`
			CertForward   map[string][]string `json:"cert-forward"`
			CertReverse   map[string][]string `json:"cert-reverse"`
			CSRForward    map[string][]string `json:"csr-forward"`
			CSRReverse    map[string][]string `json:"csr-reverse"`
		} `json:"tags"`
	} `json:"body"`
}

type OrgIndex struct {
	document.Document
	Data OrgIndexData
}

func NewOrg(jsonString interface{}) (*OrgIndex, error) {
	index := new(OrgIndex)
	index.Schema = OrgIndexSchema
	index.Default = OrgIndexDefault
	if err := index.Load(jsonString); err != nil {
		return nil, fmt.Errorf("Could not create new Index: %s", err)
	} else {
		return index, nil
	}
}

func (index *OrgIndex) Load(jsonString interface{}) error {
	data := new(OrgIndexData)
	if data, err := index.FromJson(jsonString, data); err != nil {
		return fmt.Errorf("Could not load Index JSON: %s", err)
	} else {
		index.Data = *data.(*OrgIndexData)
		return nil
	}
}

func (index *OrgIndex) Dump() string {
	if jsonString, err := index.ToJson(index.Data); err != nil {
		return ""
	} else {
		return jsonString
	}
}

func (index *OrgIndex) Id() string {
	return index.Data.Body.Id
}

func (index *OrgIndex) AddCATags(ca string, i interface{}) error {
	var inTags []string
	switch t := i.(type) {
	case string:
		inTags = []string{i.(string)}
	case []string:
		inTags = i.([]string)
	default:
		return fmt.Errorf("Could not add CA tags. Wrong data type for tags: %T", t)
	}

	for _, tag := range inTags {
		index.Data.Body.Tags.CAForward[tag] = AppendUnique(index.Data.Body.Tags.CAForward[tag], ca)
		index.Data.Body.Tags.CAReverse[ca] = AppendUnique(index.Data.Body.Tags.CAReverse[ca], tag)
	}

	return nil
}

func (index *OrgIndex) ClearCATags(ca string) error {
	_, ok := index.Data.Body.Tags.CAReverse[ca]
	if ok {
		delete(index.Data.Body.Tags.CAReverse, ca)
	}
	for tag, _ := range index.Data.Body.Tags.CAForward {
		for i, taggedCA := range index.Data.Body.Tags.CAForward[tag] {
			if taggedCA == ca {
				index.Data.Body.Tags.CAForward[tag] = append(index.Data.Body.Tags.CAForward[tag][:i], index.Data.Body.Tags.CAForward[tag][i+1:]...)
			}
		}
	}
	return nil
}

func (index *OrgIndex) AddEntityTags(entity string, i interface{}) error {
	var inTags []string
	switch t := i.(type) {
	case string:
		inTags = []string{i.(string)}
	case []string:
		inTags = i.([]string)
	default:
		return fmt.Errorf("Could not add Entity tags. Wrong data type for tags: %T", t)
	}
	for _, tag := range inTags {
		index.Data.Body.Tags.EntityForward[tag] = AppendUnique(index.Data.Body.Tags.EntityForward[tag], entity)
		index.Data.Body.Tags.EntityReverse[entity] = AppendUnique(index.Data.Body.Tags.EntityReverse[entity], tag)
	}

	return nil
}

func (index *OrgIndex) AddPairingKey(id, key string, i interface{}) error {
	_, ok := index.Data.Body.PairingKeys[id]
	if ok {
		return fmt.Errorf("key %s already exists", id)
	}

	var inTags []string
	switch t := i.(type) {
	case string:
		inTags = []string{i.(string)}
	case []string:
		inTags = i.([]string)
	default:
		return fmt.Errorf("Could not add pairing key. Wrong data type for tags: %T", t)
	}

	pairingKey := new(PairingKey)
	pairingKey.Key = key

	for _, tag := range inTags {
		pairingKey.Tags = AppendUnique(pairingKey.Tags, tag)
	}
	index.Data.Body.PairingKeys[id] = pairingKey
	return nil
}

func (index *OrgIndex) GetPairingKeys() map[string]*PairingKey {
	return index.Data.Body.PairingKeys
}

func (index *OrgIndex) GetPairingKey(id string) (*PairingKey, error) {
	_, ok := index.Data.Body.PairingKeys[id]
	if !ok {
		return nil, fmt.Errorf("key %s does not exist", id)
	}
	return index.Data.Body.PairingKeys[id], nil
}

func (index *OrgIndex) RemovePairingKey(id string) error {
	_, ok := index.Data.Body.PairingKeys[id]
	if !ok {
		return fmt.Errorf("key %s does not exist", id)
	}
	delete(index.Data.Body.PairingKeys, id)
	return nil
}

func (index *OrgIndex) AddInviteKey(id, key, name string) error {
	_, ok := index.Data.Body.InviteKeys[id]
	if ok {
		return fmt.Errorf("key %s already exists", id)
	}
	inviteKey := new(InviteKey)
	inviteKey.Name = name
	inviteKey.Key = key
	index.Data.Body.InviteKeys[id] = inviteKey
	return nil
}

func (index *OrgIndex) GetInviteKey(id string) (*InviteKey, error) {
	_, ok := index.Data.Body.InviteKeys[id]
	if !ok {
		return nil, fmt.Errorf("key %s does not exist", id)
	}
	return index.Data.Body.InviteKeys[id], nil
}

func (index *OrgIndex) AddNode(name, id string) error {
	_, ok := index.Data.Body.Nodes[name]
	if ok {
		return fmt.Errorf("key %s already exists", name)
	}
	index.Data.Body.Nodes[name] = id
	return nil
}

func (index *OrgIndex) GetNode(name string) (string, error) {
	_, ok := index.Data.Body.Nodes[name]
	if !ok {
		return "", fmt.Errorf("key %s does not exist", name)
	}
	return index.Data.Body.Nodes[name], nil
}

func (index *OrgIndex) RemoveNode(name string) error {
	_, ok := index.Data.Body.Nodes[name]
	if !ok {
		return fmt.Errorf("key %s does not exist", name)
	}
	delete(index.Data.Body.Nodes, name)
	return nil
}

func (index *OrgIndex) GetNodes() map[string]string {
	return index.Data.Body.Nodes
}

func (index *OrgIndex) AddAdmin(name, id string) error {
	_, ok := index.Data.Body.Admins[name]
	if ok {
		return fmt.Errorf("key %s already exists", name)
	}
	index.Data.Body.Admins[name] = id
	return nil
}

func (index *OrgIndex) RemoveAdmin(name string) error {
	_, ok := index.Data.Body.Admins[name]
	if !ok {
		return fmt.Errorf("key %s does not exist", name)
	}
	delete(index.Data.Body.Admins, name)
	return nil
}

func (index *OrgIndex) GetAdmin(name string) (string, error) {
	_, ok := index.Data.Body.Admins[name]
	if !ok {
		return "", fmt.Errorf("key %s does not exist", name)
	}
	return index.Data.Body.Admins[name], nil
}

func (index *OrgIndex) GetAdmins() (map[string]string, error) {
	return index.Data.Body.Admins, nil
}

func (index *OrgIndex) AddCA(name, id string) error {
	_, ok := index.Data.Body.CAs[name]
	if ok {
		return fmt.Errorf("key %s already exists", name)
	}
	index.Data.Body.CAs[name] = id
	return nil
}

func (index *OrgIndex) GetCA(name string) (string, error) {
	_, ok := index.Data.Body.CAs[name]
	if !ok {
		return "", fmt.Errorf("key %s does not exist", name)
	}
	return index.Data.Body.CAs[name], nil
}

func (index *OrgIndex) GetCAs() map[string]string {
	return index.Data.Body.CAs
}

func (index *OrgIndex) RemoveCA(name string) error {
	_, ok := index.Data.Body.CAs[name]
	if !ok {
		return fmt.Errorf("CA %s does not exist", name)
	}
	delete(index.Data.Body.CAs, name)
	return nil
}

func (index *OrgIndex) AddCertTags(cert string, i interface{}) error {
	var inTags []string
	switch t := i.(type) {
	case string:
		inTags = []string{i.(string)}
	case []string:
		inTags = i.([]string)
	default:
		return fmt.Errorf("Could not add Cert tags. Wrong data type for tags: %T", t)
	}

	for _, tag := range inTags {
		index.Data.Body.Tags.CertForward[tag] = AppendUnique(index.Data.Body.Tags.CertForward[tag], cert)
		index.Data.Body.Tags.CertReverse[cert] = AppendUnique(index.Data.Body.Tags.CertReverse[cert], tag)
	}

	return nil
}

func (index *OrgIndex) AddCert(name, id string) error {
	_, ok := index.Data.Body.Certs[name]
	if ok {
		return fmt.Errorf("key %s already exists", name)
	}
	index.Data.Body.Certs[name] = id
	return nil
}

func (index *OrgIndex) GetCert(name string) (string, error) {
	_, ok := index.Data.Body.Certs[name]
	if !ok {
		return "", fmt.Errorf("key %s does not exist", name)
	}
	return index.Data.Body.Certs[name], nil
}

func (index *OrgIndex) GetCerts() map[string]string {
	return index.Data.Body.Certs
}

func (index *OrgIndex) RemoveCert(name string) error {
	_, ok := index.Data.Body.Certs[name]
	if !ok {
		return fmt.Errorf("Cert %s does not exist", name)
	}
	delete(index.Data.Body.Certs, name)
	return nil
}

func (index *OrgIndex) ClearCertTags(cert string) error {
	_, ok := index.Data.Body.Tags.CertReverse[cert]
	if ok {
		delete(index.Data.Body.Tags.CertReverse, cert)
	}
	for tag, _ := range index.Data.Body.Tags.CertForward {
		for i, taggedCert := range index.Data.Body.Tags.CertForward[tag] {
			if taggedCert == cert {
				index.Data.Body.Tags.CertForward[tag] = append(index.Data.Body.Tags.CertForward[tag][:i], index.Data.Body.Tags.CertForward[tag][i+1:]...)
			}
		}
	}
	return nil
}

func (index *OrgIndex) AddCSRTags(csr string, i interface{}) error {
	var inTags []string
	switch t := i.(type) {
	case string:
		inTags = []string{i.(string)}
	case []string:
		inTags = i.([]string)
	default:
		return fmt.Errorf("Could not add CSR tags. Wrong data type for tags: %T", t)
	}

	for _, tag := range inTags {
		index.Data.Body.Tags.CSRForward[tag] = AppendUnique(index.Data.Body.Tags.CSRForward[tag], csr)
		index.Data.Body.Tags.CSRReverse[csr] = AppendUnique(index.Data.Body.Tags.CSRReverse[csr], tag)
	}

	return nil
}

func (index *OrgIndex) AddCSR(name, id string) error {
	_, ok := index.Data.Body.CSRs[name]
	if ok {
		return fmt.Errorf("key %s already exists", name)
	}
	index.Data.Body.CSRs[name] = id
	return nil
}

func (index *OrgIndex) GetCSR(name string) (string, error) {
	_, ok := index.Data.Body.CSRs[name]
	if !ok {
		return "", fmt.Errorf("key %s does not exist", name)
	}
	return index.Data.Body.CSRs[name], nil
}

func (index *OrgIndex) GetCSRs() map[string]string {
	return index.Data.Body.CSRs
}

func (index *OrgIndex) RemoveCSR(name string) error {
	_, ok := index.Data.Body.CSRs[name]
	if !ok {
		return fmt.Errorf("Cert %s does not exist", name)
	}
	delete(index.Data.Body.CSRs, name)
	return nil
}

func (index *OrgIndex) ClearCSRTags(csr string) error {
	_, ok := index.Data.Body.Tags.CSRReverse[csr]
	if ok {
		delete(index.Data.Body.Tags.CSRReverse, csr)
	}
	for tag, _ := range index.Data.Body.Tags.CSRForward {
		for i, taggedCSR := range index.Data.Body.Tags.CSRForward[tag] {
			if taggedCSR == csr {
				index.Data.Body.Tags.CSRForward[tag] = append(index.Data.Body.Tags.CSRForward[tag][:i], index.Data.Body.Tags.CSRForward[tag][i+1:]...)
			}
		}
	}
	return nil
}
