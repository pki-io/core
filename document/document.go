package document

import (
    "encoding/json"
    "fmt"
    "github.com/xeipuuv/gojsonschema"
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
    var jsonData []byte
    doValidation := true

    switch t := data.(type) {
    case []byte:
        jsonData = data.([]byte)
    case string:
        jsonData = []byte(data.(string))
    case nil:
        jsonData = []byte(doc.Default)
        doValidation = false
    default:
        return nil, fmt.Errorf("Invalid input type: %T", t)
    }

    if doValidation {
        var jsonDocument interface{}
        if err := json.Unmarshal(jsonData, &jsonDocument); err != nil {
            return nil, err
        }

        var schemaMap map[string]interface{}
        if err := json.Unmarshal([]byte(doc.Schema), &schemaMap); err != nil {
            return nil, fmt.Errorf("Can't unmarshal schema: %s", err.Error())
        }

        schemaDocument, err := gojsonschema.NewJsonSchemaDocument(schemaMap)
        if err != nil {
            return nil, fmt.Errorf("Can't create schema document: %s", err.Error())
        }

        result := schemaDocument.Validate(jsonDocument)
        if result.Valid() {
            if err := json.Unmarshal(jsonData, target); err != nil {
                return nil, err
            } else {
              return target, nil
            }
        } else {
            // Loop through errors
            for _, desc := range result.Errors() {
                fmt.Printf("- %s\n", desc)
            }
            return nil, fmt.Errorf("ffs")
        }
    } else {
        if err := json.Unmarshal(jsonData, target); err != nil {
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

    var jsonDocument interface{}
    if err := json.Unmarshal(jsonData, &jsonDocument); err != nil {
        return "", err
    }

    var schemaMap map[string]interface{}
    if err := json.Unmarshal([]byte(doc.Schema), &schemaMap); err != nil {
        return "", fmt.Errorf("Can't unmarshal schema: %s", err.Error())
    }

    schemaDocument, err := gojsonschema.NewJsonSchemaDocument(schemaMap)
    if err != nil {
        return "", fmt.Errorf("Can't create schema document: %s", err.Error())
    }

    result := schemaDocument.Validate(jsonDocument)
    if result.Valid() {
        return string(jsonData), nil
    } else {
        // Loop through errors
        for _, desc := range result.Errors() {
            fmt.Printf("- %s\n", desc)
        }
        return "", fmt.Errorf("ffs")
    }
}
