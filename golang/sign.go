package main

import (
	"crypto/ed25519"
	"fmt"
	"os"
	"time"
  "encoding/base64"
)

type KeyPair struct {
	publicKey  ed25519.PublicKey
	privateKey ed25519.PrivateKey
}

type IssuerMetadata struct {
	context          []string
	id               string
	typeOfCredential []string
	issuer           string
	issuanceDate     time.Time
}

type Claim struct {
	id            string
	awardTo       string
	university    string
	department    string
	degreeAwarded string
}

type Proof struct {
	typeOfProof string
	created     time.Time
	creator     ed25519.PublicKey
	signature   []byte
}

type Credential struct {
	context           []string
	id                string
	typeOfCredential  []string
	issuer            string
	issuanceDate      time.Time
	credentialSubject Claim
	proof             Proof
}

func createCredential(keyPair KeyPair, metadata IssuerMetadata, claim Claim) Credential {
	//create credential
	credential := Credential{
		context:           metadata.context,
		id:                metadata.id,
		typeOfCredential:  metadata.typeOfCredential,
		issuer:            metadata.issuer,
		issuanceDate:      metadata.issuanceDate,
		credentialSubject: claim,
	}

	//create proof
	proof := Proof{
		typeOfProof: "ed25519",
		created:     time.Now(),
		creator:     keyPair.publicKey,
		signature:   ed25519.Sign(keyPair.privateKey, []byte(fmt.Sprintf("%v", credential))),
	}

	credential.proof = proof

	return credential
}
func verifyCredential(publicKey ed25519.PublicKey, credential Credential) bool {
	if string(publicKey) != string(credential.proof.creator) {
		return false
	}
	proofObj := credential.proof
	credential.proof = Proof{}
  
	return ed25519.Verify(publicKey, []byte(fmt.Sprintf("%v", credential)), proofObj.signature)
}

func main() {
	c_name := "Fred Smith"
	c_degree := "PhD"
	c_university := "Achelous University"
	c_department := "School of Winds and Air"
	argCount := len(os.Args[1:])

	if argCount > 0 {
		c_name = os.Args[1]
	}
	if argCount > 1 {
		c_degree = os.Args[2]
	}
	if argCount > 2 {
		c_university = os.Args[3]
	}
	if argCount > 3 {
		c_department = os.Args[4]
	}

	publ, priv, _ := ed25519.GenerateKey(nil)

	keyPair := KeyPair{
		publicKey:  publ,
		privateKey: priv,
	}

	metadata := IssuerMetadata{
		context:          []string{"https://www.w3.org/2018/credentials/v1", "https://www.w3.org/2018/credentials/examples/v1"},
		id:               "did:example:123#owner",
		typeOfCredential: []string{"VerifiableCredential", "UniversityDegreeCredential"},
		issuer:           "https://example.edu/issuers/565049",
		issuanceDate:     time.Now(),
	}

	claim := Claim{
		id:            "did:example:ebfeb1f712ebc6f1c276e12ec21",
		awardTo:       c_name,
		university:    c_university,
		department:    c_department,
		degreeAwarded: c_degree,
	}

	createdCredential := createCredential(keyPair, metadata, claim)

	fmt.Printf("Private key: %x\n", priv)
	fmt.Printf("Public key: %x\n", publ)
	fmt.Printf("\n--- Credentials ---\n")
	fmt.Printf("Credential ID: %s\n", createdCredential.id)
	fmt.Printf("Credential Issuer: %s\n", createdCredential.issuer)
	fmt.Printf("Credential Date: %s\n", createdCredential.issuanceDate)

	fmt.Printf("Credential Subject (ID): %s\n", createdCredential.credentialSubject.id)
	fmt.Printf("Credential Subject (Awarded To): %s\n", createdCredential.credentialSubject.awardTo)

	fmt.Printf("Credential Subject (University): %s\n", createdCredential.credentialSubject.university)
	fmt.Printf("Credential Subject (Department): %s\n", createdCredential.credentialSubject.department)
	fmt.Printf("Credential Subject (DegreeAwarded): %s\n", createdCredential.credentialSubject.degreeAwarded)

  fmt.Printf("\n--- Credentials (Base64 Format for Verification) ---\n")
  //Make a copy of creatdCredential to not affect original...
  copyCreatedCredential := createdCredential
  copyCreatedCredential.proof = Proof{}

  se := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%v", copyCreatedCredential)))
  fmt.Printf("Signed Base64 Message: %s\n", se)

	fmt.Printf("\n\n--- Proof ---\n")
	fmt.Printf("Creator: %x\n", createdCredential.proof.creator)
	fmt.Printf("Type: %s\n", createdCredential.proof.typeOfProof)
	fmt.Printf("Created: %s\n", createdCredential.proof.created)
	fmt.Printf("Proof signature: %x\n", createdCredential.proof.signature)

	rtn := verifyCredential(keyPair.publicKey, createdCredential)
  
	if rtn {
		fmt.Println("Valid proof")
	}
}