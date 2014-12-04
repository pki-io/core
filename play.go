package main

import (
    "fmt"
    "pki.io/entity"
    "pki.io/crypto"
    "pki.io/document"
    "encoding/hex"
)

func main() {

    /**************************************************************************************************
    * Initialise the environment
    **************************************************************************************************/

    fmt.Println("Creating Org entity")
    org, err := entity.New(nil)
    if err != nil {
      panic(fmt.Sprintf("Could not create org entity: %s", err.Error()))
    }

    org.Data.Body.Id = hex.EncodeToString(crypto.RandomBytes(16))
    org.Data.Body.Name = "Org"

    /**************************************************************************************************
    * Create the admin
    **************************************************************************************************/

    fmt.Println("Creating Admin entity")
    admin, err := entity.New(nil)
    if err != nil {
      panic(fmt.Sprintf("Could not create admin entity: %s", err.Error()))
    }

    admin.Data.Body.Id = hex.EncodeToString(crypto.RandomBytes(16))
    admin.Data.Body.Name = "Admin"
    err = admin.GenerateKeys()
    if err != nil {
      panic(fmt.Sprintf("Could not generate admin keys: %s", err.Error()))
    }

    /**************************************************************************************************
    * Protect the Org
    **************************************************************************************************/

    fmt.Println("Generating Org keys")
    err = org.GenerateKeys()
    if err != nil {
      panic(fmt.Sprintf("Could not generate org keys: %s", err.Error()))
    }

    fmt.Println("Creating public copy of org to save locally")
    publicOrg, err := org.Public()
    publicOrgJson, _ := publicOrg.Dump()
    fmt.Println(publicOrgJson)
    
    fmt.Println("Encrypting org for admin")
    keys := make(map[string]string)
    keys[admin.Data.Body.Id] = admin.Data.Body.PublicEncryptionKey

    orgJson, err := org.Dump()
    if err != nil {
      panic(fmt.Sprintf("Could not dump org to json: %s", err.Error()))
    }

    fmt.Println("Creating container document")
    orgContainer, err := document.NewContainer(nil)
    if err != nil {
        panic(fmt.Sprintf("Could not create container: %s", err.Error()))
    }
    orgContainer.Data.Options.Source = org.Data.Body.Id

    fmt.Println("Encrypting org data")
    err = orgContainer.Encrypt(orgJson, keys)
    if err != nil {
      panic(fmt.Sprintf("Could not encrypt org: %s", err.Error()))
    }

    fmt.Println("Signing container")
    if err := org.Sign(orgContainer); err != nil  {
      panic(fmt.Sprintf("Could not sign container: %s", err.Error()))
    }

    fmt.Println("Dumping org container")
    orgContainerJson, err := orgContainer.Dump()
    if err != nil {
        panic(fmt.Sprintf("Could not dump org container json: %s", err.Error()))
    }

    // ..... some time later ......

    /**************************************************************************************************
    * Retrieve the Org
    **************************************************************************************************/

    fmt.Println("Creating new container from json")
    newOrgContainer, err := document.NewContainer(orgContainerJson)
    if err != nil {
        panic(fmt.Sprintf("Could not create new container from json: %s", err.Error()))
    }

    fmt.Println("Verifying container")
    if err := org.Verify(newOrgContainer); err != nil {
        panic(fmt.Sprintf("Could not verify new container: %s", err.Error()))
    } else {
        fmt.Println("Woot, verified")
    }

    fmt.Println("Decrypting new container")
    decryptedOrg, err := admin.Decrypt(newOrgContainer)

    newOrg, err := entity.New(decryptedOrg)

    /**************************************************************************************************
    * Create a new CA
    **************************************************************************************************/

    fmt.Println("Creating New CA")
    caJson := `{"certificate":"abc","private-key":"xxx"}`

    caContainer, err := document.NewContainer(nil) 
    if err != nil {
        panic(fmt.Sprintf("Could not create container: %s", err.Error()))
    }
    caContainer.Data.Options.Source = org.Data.Body.Id

    fmt.Println("Encrypting CA")
    orgKeys := make(map[string]string)
    orgKeys[newOrg.Data.Body.Id] = newOrg.Data.Body.PublicEncryptionKey

    err = caContainer.Encrypt(caJson, orgKeys)
    if err != nil {
      panic(fmt.Sprintf("Could not encrypt ca: %s", err.Error()))
    }

    fmt.Println("Signing CA container")
    if err := newOrg.Sign(caContainer); err != nil  {
      panic(fmt.Sprintf("Could not sign container: %s", err.Error()))
    }

    fmt.Println("Dumping CA container")
    caContainerJson, err := caContainer.Dump()
    if err != nil {
        panic(fmt.Sprintf("Could not dump org container json: %s", err.Error()))
    }

    // ... some time later ...

    /**************************************************************************************************
    * Sign a CSR
    **************************************************************************************************/

    //csrJson := `{"source":"123","csr":"mno"}`

    fmt.Println("Creating new ca container from json")
    newCAContainer, err := document.NewContainer(caContainerJson)
    if err != nil {
        panic(fmt.Sprintf("Could not create new container from json: %s", err.Error()))
    }

    fmt.Println("Verifying container")
    if err := newOrg.Verify(newCAContainer); err != nil {
        panic(fmt.Sprintf("Could not verify new container: %s", err.Error()))
    } else {
        fmt.Println("Woot, verified")
    }

    fmt.Println("Decrypting new CA container")
    decryptedCA, err := org.Decrypt(newCAContainer)

    fmt.Println(decryptedCA)

    // Create CA from json and sign CSR etc..

}
