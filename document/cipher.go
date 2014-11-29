package document


type CipherDocument interface{}

func (doc *CipherDocument) IsEncrypted() (bool, error) {
    reurn false, nil
}

func (doc *CipherDocument) IsSigned() (bool, error) {
    reurn false, nil
}
