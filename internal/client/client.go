package client

import (
	"errors"
	"fmt"

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

func (c *SopsClient) Decrypt(bytes []byte, o DecryptOpts) ([]byte, error) {
	// Step 1: deserialize
	tree, err := o.Encrypted.LoadEncryptedFile(bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse encrypted content: %w", err)
	}

	// Step 2: decrypt
	_, err = common.DecryptTree(common.DecryptTreeOpts{
		Cipher:      c.cipher,
		IgnoreMac:   o.IgnoreMAC,
		Tree:        &tree,
		KeyServices: c.keyServices,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt content: %w", err)
	}

	// Step 3: serialize
	result, err := o.Decrypted.EmitPlainFile(tree.Branches)
	if err != nil {
		return nil, fmt.Errorf("failed to emit decrypted content: %w", err)
	}
	return result, err
}

func (c *SopsClient) MustDecrypt(bytes []byte, o DecryptOpts) []byte {
	result, err := c.Decrypt(bytes, o)
	if err != nil {
		panic(err)
	}
	return result
}

type EncryptOpts struct {
	Stores
	sops.Metadata
}

func (c *SopsClient) Encrypt(bytes []byte, o EncryptOpts) ([]byte, error) {
	// Step 1: deserialize
	branches, err := o.Decrypted.LoadPlainFile(bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse plain content: %w", err)
	}
	if len(branches) < 1 {
		return nil, fmt.Errorf("content must not be empty, i.e., it must contain at least one document")
	}

	// Step 2: encrypt
	tree := sops.Tree{
		Branches: branches,
		Metadata: o.Metadata,
	}
	dataKey, errs := tree.GenerateDataKeyWithKeyServices(c.keyServices)
	if len(errs) > 0 {
		return nil, fmt.Errorf("failed to generate data key: %w", errors.Join(errs...))
	}
	err = common.EncryptTree(common.EncryptTreeOpts{
		DataKey: dataKey,
		Tree:    &tree,
		Cipher:  c.cipher,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt content: %w", err)
	}

	// Step 3: serialize
	result, err := o.Encrypted.EmitEncryptedFile(tree)
	if err != nil {
		return nil, fmt.Errorf("failed to emit encrypted content: %w", err)
	}

	return result, nil
}

func (c *SopsClient) MustEncrypt(bytes []byte, o EncryptOpts) []byte {
	result, err := c.Encrypt(bytes, o)
	if err != nil {
		panic(err)
	}
	return result
}

type EditOpts DecryptOpts

func (c *SopsClient) Edit(origin []byte, income []byte, o EditOpts) ([]byte, error) {
	// Step 1: deserialize origin
	tree, err := o.Encrypted.LoadEncryptedFile(origin)
	if err != nil {
		return nil, fmt.Errorf("failed to parse encrypted content: %w", err)
	}

	// Step 2: decrypt
	dataKey, err := common.DecryptTree(common.DecryptTreeOpts{
		Cipher:      c.cipher,
		IgnoreMac:   o.IgnoreMAC,
		Tree:        &tree,
		KeyServices: c.keyServices,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt content: %w", err)
	}

	// Step 3: deserialize income
	branches, err := o.Decrypted.LoadPlainFile(income)
	if err != nil {
		return nil, fmt.Errorf("failed to parse plain content: %w", err)
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
		return nil, fmt.Errorf("failed to encrypt content: %w", err)
	}

	// Step 6: serialize
	result, err := o.Encrypted.EmitEncryptedFile(tree)
	if err != nil {
		return nil, fmt.Errorf("failed to emit encrypted content: %w", err)
	}
	return result, nil
}

func (c *SopsClient) MustEdit(origin []byte, income []byte, o EditOpts) []byte {
	result, err := c.Edit(origin, income, o)
	if err != nil {
		panic(err)
	}
	return result
}
