package client

import (
	"testing"

	"github.com/getsops/sops/v3/cmd/sops/formats"
	"github.com/getsops/sops/v3/version"
	"github.com/stretchr/testify/assert"
)

const testPgpKey string = "811B2B9D8815710F13105517F15D3C50575B206E"

var testMetadataOpts = MetadataOpts{
	Version: version.Version,
	KeyGroupsOpts: KeyGroupsOpts{
		Groups: []KeyGroupOpts{
			{
				{PgpKeyOpts: &PgpKeyOpts{Fingerprint: testPgpKey}},
			},
		},
		ShamirThreshold: 1,
	},
	CryptRules: DefaultCryptRules,
}

func TestSopsClient(t *testing.T) {
	keyServices, err := NewKeyServices(DefaultKeyServiceOpts)
	if err != nil {
		t.Fatalf("failed to create key services: %v", err)
	}
	sopsClient := NewSopsClient(keyServices)
	stores := NewStores(&StoreOpts{
		DecryptedFormat: formats.Yaml,
		EncryptedFormat: formats.Json,
	})
	if err := testMetadataOpts.Validate(); err != nil {
		t.Fatalf("failed to validate metadata: %v", err)
	}
	metadata := NewMetadata(&testMetadataOpts)
	recoveredMetadataOpts := RecoverMetadataOpts(&metadata)
	assert.Equal(t, &testMetadataOpts, &recoveredMetadataOpts, "recovered metadata should match original metadata")

	content := []byte("a: 1\nb: 2\n")
	encrypted := sopsClient.MustEncrypt(content, EncryptOpts{
		Metadata: metadata,
		Stores:   stores,
	})
	decrypted := sopsClient.MustDecrypt(encrypted, DecryptOpts{Stores: stores})
	assert.Equal(t, content, decrypted, "decrypted content should match original content")

	content = []byte("a: 2\nb: 3\n")
	encrypted = sopsClient.MustEdit(encrypted, content, EditOpts{Stores: stores})
	decrypted = sopsClient.MustDecrypt(encrypted, DecryptOpts{Stores: stores})
	assert.Equal(t, content, decrypted, "decrypted content should match edited content")

	content = []byte("a: 3\nb: 4\n")
	encrypted = sopsClient.MustEdit(encrypted, content, EditOpts{Stores: stores})
	decrypted = sopsClient.MustDecrypt(encrypted, DecryptOpts{Stores: stores})
	assert.Equal(t, content, decrypted, "decrypted content should match edited content")
}
