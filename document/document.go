package document

import (
    "encoding/json"
    "fmt"
    "github.com/xeipuuv/gojsonschema"
)

type document struct {
    schema string
    defaultValue string
}

func (doc *document) fromJson(data interface{}, target interface{}) (interface{}, error) {
    var jsonData []byte
    switch t := data.(type) {
    case []byte:
        jsonData = data.([]byte)
    case string:
        jsonData = []byte(data.(string))
    case nil:
        jsonData = []byte(doc.defaultValue)
    default:
        return nil, fmt.Errorf("Invalid input type: %T", t)
    }

    var jsonDocument interface{}
    if err := json.Unmarshal(jsonData, &jsonDocument); err != nil {
        return nil, err
    }

    var schemaMap map[string]interface{}
    if err := json.Unmarshal([]byte(doc.schema), &schemaMap); err != nil {
        return nil, fmt.Errorf("Can't unmarshal schema: %s", err.Error())
    }

    schemaDocument, err := gojsonschema.NewJsonSchemaDocument(schemaMap)
    if err != nil {
        return nil, fmt.Errorf("Can't create schema document: %s", err.Error())
    }

    result := schemaDocument.Validate(jsonDocument)
    if result.Valid() {
        fmt.Printf("The document is valid\n")
        if err := json.Unmarshal(jsonData, target); err != nil {
            return nil, err
        } else {
          return target, nil
        }
    } else {
        fmt.Printf("The document is not valid. see errors :\n")
        // Loop through errors
        for _, desc := range result.Errors() {
            fmt.Printf("- %s\n", desc)
        }
        return nil, fmt.Errorf("ffs")
    }
}

func (doc *document) toJson(data interface{}) (string, error) {
    jsonData, err := json.Marshal(data)
    if err != nil {
        return "", err
    }

    var jsonDocument interface{}
    if err := json.Unmarshal(jsonData, &jsonDocument); err != nil {
        return "", err
    }

    var schemaMap map[string]interface{}
    if err := json.Unmarshal([]byte(doc.schema), &schemaMap); err != nil {
        return "", fmt.Errorf("Can't unmarshal schema: %s", err.Error())
    }

    schemaDocument, err := gojsonschema.NewJsonSchemaDocument(schemaMap)
    if err != nil {
        return "", fmt.Errorf("Can't create schema document: %s", err.Error())
    }

    result := schemaDocument.Validate(jsonDocument)
    if result.Valid() {
        fmt.Printf("The document is valid\n")
        return string(jsonData), nil
    } else {
        fmt.Printf("The document is not valid. see errors :\n")
        // Loop through errors
        for _, desc := range result.Errors() {
            fmt.Printf("- %s\n", desc)
        }
        return "", fmt.Errorf("ffs")
    }
}
