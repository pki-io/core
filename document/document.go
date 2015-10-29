// ThreatSpec package github.com/pki-io/core/document as document
package document

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/xeipuuv/gojsonschema"
	"strings"
)

type Documenter interface {
	Dump()
	Load()
}

// Documents represents a generic JSON schema based document
type Document struct {
	Schema  string
	Default string
}

// ThreatSpec TMv0.1 for Document.FromJson
// Creates document from JSON for App:Document

// FromJson parses the provided data after verifying the schema. If the data is nil, it uses the default values set for the document.
func (doc *Document) FromJson(data interface{}, target interface{}) (interface{}, error) {
	var jsonData string
	doValidation := true

	switch t := data.(type) {
	case []byte:
		jsonData = string(t)
	case string:
		jsonData = t
	case nil:
		jsonData = doc.Default
		doValidation = false
	default:
		return nil, fmt.Errorf("Invalid input type: %T", t)
	}

	if doValidation {
		documentLoader := gojsonschema.NewStringLoader(jsonData)
		schemaLoader := gojsonschema.NewStringLoader(doc.Schema)

		if result, err := gojsonschema.Validate(schemaLoader, documentLoader); err != nil {
			return nil, errors.New("Something went wrong when trying to validate json.")
		} else if result.Valid() {
			if err := json.Unmarshal([]byte(jsonData), target); err != nil {
				return nil, err
			} else {
				return target, nil
			}
		} else {
			// Loop through errors
			var errs []string
			for _, desc := range result.Errors() {
				errs = append(errs, fmt.Sprint(desc))
			}
			return nil, errors.New(strings.Join(errs, "\n"))
		}
	} else {
		if err := json.Unmarshal([]byte(jsonData), target); err != nil {
			return nil, err
		} else {
			return target, nil
		}
	}
}

// ThreatSpec TMv0.1 for Document.ToJson
// Returns document as JSON for App:Document

// ToJson serializes the document to JSON.
func (doc *Document) ToJson(data interface{}) (string, error) {
	jsonData, err := json.Marshal(data)
	if err != nil {
		return "", err
	}

	documentLoader := gojsonschema.NewStringLoader(string(jsonData))
	schemaLoader := gojsonschema.NewStringLoader(doc.Schema)

	if result, err := gojsonschema.Validate(schemaLoader, documentLoader); err != nil {
		return "", errors.New("something went wrong when trying to validate json.")
	} else if result.Valid() {
		return string(jsonData), nil
	} else {
		// Loop through errors
		for _, desc := range result.Errors() {
			fmt.Printf("- %s\n", desc)
		}
		return "", errors.New("ffs")
	}
}
