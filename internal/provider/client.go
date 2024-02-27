package provider

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"time"

	"github.com/getsops/sops/v3"
	"github.com/getsops/sops/v3/age"
	"github.com/getsops/sops/v3/azkv"
	"github.com/getsops/sops/v3/cmd/sops/common"
	"github.com/getsops/sops/v3/cmd/sops/formats"
	"github.com/getsops/sops/v3/gcpkms"
	"github.com/getsops/sops/v3/hcvault"
	"github.com/getsops/sops/v3/keys"
	"github.com/getsops/sops/v3/keyservice"
	"github.com/getsops/sops/v3/kms"
	"github.com/getsops/sops/v3/pgp"
	"github.com/getsops/sops/v3/version"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type sopsClient struct {
	configPath  string
	cipher      sops.Cipher
	keyServices []keyservice.KeyServiceClient
}

type formatType string

const (
	formatTypeBinary formatType = "binary"
	formatTypeDotenv formatType = "dotenv"
	formatTypeIni    formatType = "ini"
	formatTypeJson   formatType = "json"
	formatTypeYaml   formatType = "yaml"
)

type keyServiceOpts struct {
	disableLocalKeyService bool
	keyServiceURIs         []string
}

func (o *keyServiceOpts) keyServices() ([]keyservice.KeyServiceClient, error) {
	var svcs []keyservice.KeyServiceClient
	if !o.disableLocalKeyService {
		svcs = append(svcs, keyservice.NewLocalClient())
	}
	var errs []error
	for _, uri := range o.keyServiceURIs {
		url, err := url.Parse((uri))
		if err != nil {
			errs = append(errs, fmt.Errorf("failed to parse key service URI %s: %w", uri, err))
			continue
		}
		addr := url.Host
		if url.Scheme == "unix" {
			addr = url.Path
		}
		conn, err := grpc.Dial(addr,
			grpc.WithTransportCredentials(insecure.NewCredentials()),
			grpc.WithContextDialer(
				func(ctx context.Context, addr string) (net.Conn, error) {
					return (&net.Dialer{}).DialContext(ctx, url.Scheme, addr)
				},
			))
		if err != nil {
			errs = append(errs, fmt.Errorf("failed to dial key service at %s: %w", uri, err))
			continue
		}
		svcs = append(svcs, keyservice.NewKeyServiceClient(conn))
	}
	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	return svcs, nil
}

type ageKey string

func (o *ageKey) key() (keys.MasterKey, error) {
	return age.MasterKeyFromRecipient(string(*o))
}

type pgpFingerprint string

func (o *pgpFingerprint) key() keys.MasterKey {
	return pgp.NewMasterKeyFromFingerprint(string(*o))
}

type kmsKey struct {
	arn        string
	role       string
	context    map[string]*string
	awsProfile string
}

func (o *kmsKey) key() keys.MasterKey {
	return &kms.MasterKey{
		Arn:               o.arn,
		Role:              o.role,
		EncryptionContext: o.context,
		AwsProfile:        o.awsProfile,
		CreationDate:      time.Now().UTC(),
	}
}

type gcpKms string

func (o *gcpKms) key() keys.MasterKey {
	return gcpkms.NewMasterKeyFromResourceID(string(*o))
}

type azureKVKey struct {
	vaultURL   string
	keyName    string
	keyVersion string
}

func (o *azureKVKey) key() keys.MasterKey {
	return azkv.NewMasterKey(o.vaultURL, o.keyName, o.keyVersion)
}

type vaultURI string

func (o *vaultURI) key() (keys.MasterKey, error) {
	return hcvault.NewMasterKeyFromURI(string(*o))
}

type key struct {
	ageKey         *ageKey
	pgpFingerprint *pgpFingerprint
	kmsKey         *kmsKey
	gcpKms         *gcpKms
	azureKVKey     *azureKVKey
	vaultURI       *vaultURI
}

func (o *key) key() (keys.MasterKey, error) {
	switch {
	case o.ageKey != nil:
		return o.ageKey.key()
	case o.pgpFingerprint != nil:
		return o.pgpFingerprint.key(), nil
	case o.kmsKey != nil:
		return o.kmsKey.key(), nil
	case o.gcpKms != nil:
		return o.gcpKms.key(), nil
	case o.azureKVKey != nil:
		return o.azureKVKey.key(), nil
	case o.vaultURI != nil:
		return o.vaultURI.key()
	default:
		return nil, errors.New("no key provided")
	}
}

type keyGroup []key

func (o *keyGroup) keyGroup() (sops.KeyGroup, error) {
	var keys sops.KeyGroup
	for _, k := range *o {
		key, err := k.key()
		if err != nil {
			return nil, err
		}
		keys = append(keys, key)
	}
	return keys, nil
}

type keyGroupsOpts struct {
	groups          []keyGroup
	shamirThreshold int
}

func (o *keyGroupsOpts) keyGroups() ([]sops.KeyGroup, error) {
	var groups []sops.KeyGroup
	for _, g := range o.groups {
		group, err := g.keyGroup()
		if err != nil {
			return nil, err
		}
		groups = append(groups, group)
	}
	return groups, nil
}

type storeOpts struct {
	encryptedFormat formats.Format
	decryptedFormat formats.Format
}

func (o *storeOpts) stores() stores {
	return stores{
		encrypted: common.StoreForFormat(o.encryptedFormat),
		decrypted: common.StoreForFormat(o.decryptedFormat),
	}
}

type stores struct {
	encrypted common.Store
	decrypted common.Store
}

type decryptOpts struct {
	storeOpts
	ignoreMAC bool
}

func (c *sopsClient) decrypt(bytes []byte, o decryptOpts) ([]byte, error) {
	stores := o.stores()

	// Step 1: deserialize
	tree, err := stores.encrypted.LoadEncryptedFile(bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse encrypted content: %w", err)
	}

	// Step 2: decrypt
	_, err = common.DecryptTree(common.DecryptTreeOpts{
		Cipher:      c.cipher,
		IgnoreMac:   o.ignoreMAC,
		Tree:        &tree,
		KeyServices: c.keyServices,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt content: %w", err)
	}

	// Step 3: serialize
	result, err := stores.decrypted.EmitPlainFile(tree.Branches)
	if err != nil {
		return nil, fmt.Errorf("failed to emit decrypted content: %w", err)
	}
	return result, err
}

func (c *sopsClient) mustDecrypt(bytes []byte, o decryptOpts) []byte {
	result, err := c.decrypt(bytes, o)
	if err != nil {
		panic(err)
	}
	return result
}

type partialEncryptOpts struct {
	unencryptedSuffix string
	encryptedSuffix   string
	unencryptedRegex  string
	encryptedRegex    string
}

type encryptOpts struct {
	storeOpts
	keyGroupsOpts
	partialEncryptOpts
}

func (c *sopsClient) encrypt(bytes []byte, o encryptOpts) ([]byte, error) {
	stores := o.stores()

	// Step 1: parse config
	keyGroups, err := o.keyGroups()
	if err != nil {
		return nil, fmt.Errorf("failed to parse key groups: %w", err)
	}

	// Step 2: deserialize
	branches, err := stores.decrypted.LoadPlainFile(bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse plain content: %w", err)
	}
	if len(branches) < 1 {
		return nil, fmt.Errorf("content must not be empty, i.e., it must contain at least one document")
	}

	// Step 3: encrypt
	tree := sops.Tree{
		Branches: branches,
		Metadata: sops.Metadata{
			Version: version.Version,
			// keys
			KeyGroups:       keyGroups,
			ShamirThreshold: o.shamirThreshold,
			// partial encrypt
			UnencryptedSuffix: o.unencryptedSuffix,
			EncryptedSuffix:   o.encryptedSuffix,
			UnencryptedRegex:  o.unencryptedRegex,
			EncryptedRegex:    o.encryptedRegex,
		},
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

	// Step 4: serialize
	result, err := stores.encrypted.EmitEncryptedFile(tree)
	if err != nil {
		return nil, fmt.Errorf("failed to emit encrypted content: %w", err)
	}

	return result, nil
}

func (c *sopsClient) mustEncrypt(bytes []byte, o encryptOpts) []byte {
	result, err := c.encrypt(bytes, o)
	if err != nil {
		panic(err)
	}
	return result
}

type editOpts decryptOpts

func (c *sopsClient) edit(origin []byte, income []byte, o editOpts) ([]byte, error) {
	stores := o.stores()

	// Step 1: deserialize origin
	tree, err := stores.encrypted.LoadEncryptedFile(origin)
	if err != nil {
		return nil, fmt.Errorf("failed to parse encrypted content: %w", err)
	}

	// Step 2: decrypt
	dataKey, err := common.DecryptTree(common.DecryptTreeOpts{
		Cipher:      c.cipher,
		IgnoreMac:   o.ignoreMAC,
		Tree:        &tree,
		KeyServices: c.keyServices,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt content: %w", err)
	}

	// Step 3: deserialize income
	branches, err := stores.decrypted.LoadPlainFile(income)
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
	result, err := stores.encrypted.EmitEncryptedFile(tree)
	if err != nil {
		return nil, fmt.Errorf("failed to emit encrypted content: %w", err)
	}
	return result, nil
}

func (c *sopsClient) mustEdit(origin []byte, income []byte, o editOpts) []byte {
	result, err := c.edit(origin, income, o)
	if err != nil {
		panic(err)
	}
	return result
}
