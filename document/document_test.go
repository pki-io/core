package document

import (
    "testing"
    "github.com/stretchr/testify/assert"
)

func TestAbstractDocument(t *testing.T) {
    d := new(document)
    assert.NotNil(t, d)
}

func TestDocumentDefault(t *testing.T) {
    schema := `{
      "$schema": "http://json-schema.org/draft-04/schema#",
      "title": "CADocument",
      "description": "CA Document",
      "type": "object"
    }`
    defaultValue := `{"test":"testing"}`

    type TestData struct {
        Test string `json:"test"`
    }

    type TestDocument struct {
        document
        Data TestData
    }

    doc := new(TestDocument)
    data := new(TestData)
    assert.NotNil(t, doc)
    assert.NotNil(t, data)
    doc.schema = schema
    doc.defaultValue = defaultValue
    d, err := doc.fromJson(nil, data)
    assert.Nil(t, err)
    assert.NotNil(t, data)
    doc.Data = *d.(*TestData)
    assert.Equal(t, doc.Data.Test, "testing")
}

func TestDocumentJson(t *testing.T) {
    schema := `{
      "$schema": "http://json-schema.org/draft-04/schema#",
      "title": "CADocument",
      "description": "CA Document",
      "type": "object"
    }`
    defaultValue := `{"test":"testing"}`

    type TestData struct {
        Test string `json:"test"`
    }

    type TestDocument struct {
        document
        Data TestData
    }

    inputJson := `{"test":"badgers"}`

    doc := new(TestDocument)
    data := new(TestData)
    assert.NotNil(t, doc)
    assert.NotNil(t, data)
    doc.schema = schema
    doc.defaultValue = defaultValue
    d, err := doc.fromJson(inputJson, data)
    assert.Nil(t, err)
    assert.NotNil(t, data)
    doc.Data = *d.(*TestData)
    assert.Equal(t, doc.Data.Test, "badgers")
}
