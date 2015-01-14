package document

import (
    "encoding/json"
    "fmt"
    "github.com/xeipuuv/gojsonschema"
    "errors"
)

type Documenter interface {
    Dump()
    Load()
}

type Document struct {
    Schema string
    Default string
}

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
            for _, desc := range result.Errors() {
                fmt.Printf("- %s\n", desc)
            }
            return nil, errors.New("ffs")
        }
    } else {
        if err := json.Unmarshal([]byte(jsonData), target); err != nil {
            return nil, err
        } else {
          return target, nil
        }
    }
}

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
