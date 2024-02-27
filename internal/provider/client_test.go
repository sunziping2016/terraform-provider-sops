package provider

import (
	"testing"

	"github.com/getsops/sops/v3/aes"
	"github.com/getsops/sops/v3/cmd/sops/formats"
	"github.com/stretchr/testify/assert"
)

var pgpKey1 pgpFingerprint = "811B2B9D8815710F13105517F15D3C50575B206E"

func TestSopsClient(t *testing.T) {
	keyServices, err := (&keyServiceOpts{}).keyServices()
	if err != nil {
		t.Fatalf("failed to create key services: %v", err)
	}

	sopsClient := &sopsClient{
		cipher:      aes.NewCipher(),
		keyServices: keyServices,
	}
	storeOpts := storeOpts{
		decryptedFormat: formats.Yaml,
		encryptedFormat: formats.Json,
	}

	content := []byte("a: 1\nb: 2\n")
	encrypted := sopsClient.mustEncrypt(content, encryptOpts{
		storeOpts: storeOpts,
		keyGroupsOpts: keyGroupsOpts{
			groups: []keyGroup{
				{
					{pgpFingerprint: &pgpKey1},
				},
			},
		},
	})
	decrypted := sopsClient.mustDecrypt(encrypted, decryptOpts{storeOpts: storeOpts})
	assert.Equal(t, content, decrypted, "decrypted content should match original content")

	content = []byte("a: 2\nb: 3\n")
	encrypted = sopsClient.mustEdit(encrypted, content, editOpts{storeOpts: storeOpts})
	decrypted = sopsClient.mustDecrypt(encrypted, decryptOpts{storeOpts: storeOpts})
	assert.Equal(t, content, decrypted, "decrypted content should match edited content")

	content = []byte("a: 3\nb: 4\n")
	encrypted = sopsClient.mustEdit(encrypted, content, editOpts{storeOpts: storeOpts})
	decrypted = sopsClient.mustDecrypt(encrypted, decryptOpts{storeOpts: storeOpts})
	assert.Equal(t, content, decrypted, "decrypted content should match edited content")
}
