package client

import (
	"errors"
	"fmt"
	"time"

	"github.com/getsops/sops/v3"
	"github.com/getsops/sops/v3/aes"
	"github.com/getsops/sops/v3/cmd/sops/common"
	"github.com/getsops/sops/v3/keyservice"
)

type SopsClient struct {
	cipher      sops.Cipher
	keyServices []keyservice.KeyServiceClient
}

func NewSopsClient(keyServices []keyservice.KeyServiceClient) *SopsClient {
	return &SopsClient{
		cipher:      aes.NewCipher(),
		keyServices: keyServices,
	}
}

type DecryptOpts struct {
	Stores
	IgnoreMAC bool
}

type DecryptResults struct {
	Content  []byte
	Metadata sops.Metadata
}

func (c *SopsClient) Decrypt(encrypted []byte, o DecryptOpts) (DecryptResults, error) {
	// Step 1: deserialize
	tree, err := o.Encrypted.LoadEncryptedFile(encrypted)
	if err != nil {
		return DecryptResults{}, fmt.Errorf("failed to parse encrypted content: %w", err)
	}

	// Step 2: decrypt
	_, err = common.DecryptTree(common.DecryptTreeOpts{
		Cipher:      c.cipher,
		IgnoreMac:   o.IgnoreMAC,
		Tree:        &tree,
		KeyServices: c.keyServices,
	})
	if err != nil {
		return DecryptResults{}, fmt.Errorf("failed to decrypt content: %w", err)
	}

	// Step 3: serialize
	decrypted, err := o.Stores.Decrypted.EmitPlainFile(tree.Branches)
	if err != nil {
		return DecryptResults{}, fmt.Errorf("failed to emit decrypted content: %w", err)
	}
	return DecryptResults{
		Content:  decrypted,
		Metadata: tree.Metadata,
	}, nil
}

type EncryptOpts struct {
	Stores
	sops.Metadata
}

type EncryptResults struct {
	Content      []byte
	LastModified time.Time
}

func (c *SopsClient) Encrypt(origin []byte, o EncryptOpts) (EncryptResults, error) {
	// Step 1: deserialize
	branches, err := o.Decrypted.LoadPlainFile(origin)
	if err != nil {
		return EncryptResults{}, fmt.Errorf("failed to parse plain content: %w", err)
	}
	if len(branches) < 1 {
		return EncryptResults{}, fmt.Errorf("content must not be empty, i.e., it must contain at least one document")
	}

	// Step 2: encrypt
	tree := sops.Tree{
		Branches: branches,
		Metadata: o.Metadata,
	}
	dataKey, errs := tree.GenerateDataKeyWithKeyServices(c.keyServices)
	if len(errs) > 0 {
		return EncryptResults{}, fmt.Errorf("failed to generate data key: %w", errors.Join(errs...))
	}
	err = common.EncryptTree(common.EncryptTreeOpts{
		DataKey: dataKey,
		Tree:    &tree,
		Cipher:  c.cipher,
	})
	if err != nil {
		return EncryptResults{}, fmt.Errorf("failed to encrypt content: %w", err)
	}

	// Step 3: serialize
	encrypted, err := o.Encrypted.EmitEncryptedFile(tree)
	if err != nil {
		return EncryptResults{}, fmt.Errorf("failed to emit encrypted content: %w", err)
	}
	return EncryptResults{
		Content:      encrypted,
		LastModified: tree.Metadata.LastModified,
	}, nil
}

type EditOpts struct {
	Stores
	IgnoreMAC bool
}

type EditResults struct {
	Content  []byte
	Metadata sops.Metadata
}

func (c *SopsClient) Edit(origin []byte, income []byte, o EditOpts) (EditResults, error) {
	// Step 1: deserialize origin
	tree, err := o.Encrypted.LoadEncryptedFile(origin)
	if err != nil {
		return EditResults{}, fmt.Errorf("failed to parse encrypted content: %w", err)
	}

	// Step 2: decrypt
	dataKey, err := common.DecryptTree(common.DecryptTreeOpts{
		Cipher:      c.cipher,
		IgnoreMac:   o.IgnoreMAC,
		Tree:        &tree,
		KeyServices: c.keyServices,
	})
	if err != nil {
		return EditResults{}, fmt.Errorf("failed to decrypt content: %w", err)
	}

	// Step 3: deserialize income
	branches, err := o.Decrypted.LoadPlainFile(income)
	if err != nil {
		return EditResults{}, fmt.Errorf("failed to parse plain content: %w", err)
	}

	// Step 4: merge
	tree.Branches = branches

	// Step 5: encrypt
	err = common.EncryptTree(common.EncryptTreeOpts{
		DataKey: dataKey,
		Tree:    &tree,
		Cipher:  c.cipher,
	})
	if err != nil {
		return EditResults{}, fmt.Errorf("failed to encrypt content: %w", err)
	}

	// Step 6: serialize
	encrypted, err := o.Encrypted.EmitEncryptedFile(tree)
	if err != nil {
		return EditResults{}, fmt.Errorf("failed to emit encrypted content: %w", err)
	}
	return EditResults{
		Content:  encrypted,
		Metadata: tree.Metadata,
	}, nil
}
