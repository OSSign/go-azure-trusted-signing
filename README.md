# go-azure-trusted-signing
Native implementation of Azure Trusted Signing in Go

## Usage
```go
import (
    "context"
    "crypto/x509"
    "encoding/pem"
    "fmt"
    "log"

	goats "github.com/ossign/go-azure-trusted-signing"
)

func main() {
    signableData := []byte("data to be signed")

	digest := sha256.New()
	digest.Write(signableData)
	digestSum := digest.Sum(nil)

	client, err := goats.NewClientSecretClient(
		goats.RegionNorthEurope,
		tenantId,
		clientId,
		clientSecret,
		accountname,
		profilename,
	)
	if err != nil {
		log.Fatalf("failed to create client: %v", err)
	}

	rootCert, err := client.GetRootCertificate(context.Background())
	if err != nil {
		log.Fatalf("failed to get root certificate: %v", err)
	}

	fmt.Printf("Root Certificate:\n%s\n", rootCert.Subject)

	signature, err := client.SignAndWait(context.Background(), goats.SignRequest{
		SignatureAlgorithm: goats.RS256,
		Digest:             digestSum,
	})
	if err != nil {
		log.Fatalf("failed to sign data: %v", err)
	}

	fmt.Printf("Signature was %x\n", string(signature.Status))
	fmt.Printf("Signature: %x\n", signature.Signature)
}
```
