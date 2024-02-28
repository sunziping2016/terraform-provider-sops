package client

import (
	"errors"
	"fmt"
	"time"

	"github.com/getsops/sops/v3"
	"github.com/getsops/sops/v3/age"
	"github.com/getsops/sops/v3/azkv"
	"github.com/getsops/sops/v3/gcpkms"
	"github.com/getsops/sops/v3/hcvault"
	"github.com/getsops/sops/v3/keys"
	"github.com/getsops/sops/v3/kms"
	"github.com/getsops/sops/v3/pgp"
)

type (
	AgeKeyOpts struct {
		Recipient string
	}
	PgpKeyOpts struct {
		CreationDate time.Time
		Fingerprint  string
	}
	KmsKeyOpts struct {
		CreationDate      time.Time
		Arn               string
		Role              string
		EncryptionContext map[string]*string
		AwsProfile        string
	}
	GcpKmsKeyOpts struct {
		CreationDate time.Time
		ResourceID   string
	}
	AzureKVKeyOpts struct {
		CreationDate time.Time
		VaultURI     string
		KeyName      string
		KeyVersion   string
	}
	HCVaultOpts struct {
		CreationDate time.Time
		VaultAddress string
		EnginePath   string
		KeyName      string
	}
)

type KeyOpts struct {
	AgeKeyOpts     *AgeKeyOpts
	PgpKeyOpts     *PgpKeyOpts
	KmsKeyOpts     *KmsKeyOpts
	GcpKmsKeyOpts  *GcpKmsKeyOpts
	AzureKVKeyOpts *AzureKVKeyOpts
	HCVaultOpts    *HCVaultOpts
}

func (o *KeyOpts) Validate() error {
	keyCount := 0
	if o.AgeKeyOpts != nil {
		keyCount++
	}
	if o.PgpKeyOpts != nil {
		keyCount++
	}
	if o.KmsKeyOpts != nil {
		keyCount++
	}
	if o.GcpKmsKeyOpts != nil {
		keyCount++
	}
	if o.AzureKVKeyOpts != nil {
		keyCount++
	}
	if o.HCVaultOpts != nil {
		keyCount++
	}
	if keyCount == 0 {
		return errors.New("at least one key option must be set")
	}
	if keyCount > 1 {
		return errors.New("only one key option can be set at a time")
	}
	return nil
}

func NewKey(o *KeyOpts) keys.MasterKey {
	switch {
	case o.AgeKeyOpts != nil:
		opts := o.AgeKeyOpts
		return &age.MasterKey{
			Recipient: opts.Recipient,
		}
	case o.PgpKeyOpts != nil:
		opts := o.PgpKeyOpts
		return &pgp.MasterKey{
			CreationDate: opts.CreationDate,
			Fingerprint:  opts.Fingerprint,
		}
	case o.KmsKeyOpts != nil:
		opts := o.KmsKeyOpts
		return &kms.MasterKey{
			CreationDate:      opts.CreationDate,
			Arn:               opts.Arn,
			Role:              opts.Role,
			EncryptionContext: opts.EncryptionContext,
			AwsProfile:        opts.AwsProfile,
		}
	case o.GcpKmsKeyOpts != nil:
		opts := o.GcpKmsKeyOpts
		return &gcpkms.MasterKey{
			CreationDate: opts.CreationDate,
			ResourceID:   opts.ResourceID,
		}
	case o.AzureKVKeyOpts != nil:
		opts := o.AzureKVKeyOpts
		return &azkv.MasterKey{
			CreationDate: opts.CreationDate,
			VaultURL:     opts.VaultURI,
			Name:         opts.KeyName,
			Version:      opts.KeyVersion,
		}
	case o.HCVaultOpts != nil:
		opts := o.HCVaultOpts
		return &hcvault.MasterKey{
			CreationDate: opts.CreationDate,
			VaultAddress: opts.VaultAddress,
			EnginePath:   opts.EnginePath,
			KeyName:      opts.KeyName,
		}
	default:
		return nil
	}
}

func RecoverKeyOpts(key keys.MasterKey) KeyOpts {
	switch k := key.(type) {
	case *age.MasterKey:
		return KeyOpts{AgeKeyOpts: &AgeKeyOpts{
			Recipient: k.Recipient,
		}}
	case *pgp.MasterKey:
		return KeyOpts{PgpKeyOpts: &PgpKeyOpts{
			CreationDate: k.CreationDate,
			Fingerprint:  k.Fingerprint,
		}}
	case *kms.MasterKey:
		return KeyOpts{KmsKeyOpts: &KmsKeyOpts{
			CreationDate:      k.CreationDate,
			Arn:               k.Arn,
			Role:              k.Role,
			EncryptionContext: k.EncryptionContext,
			AwsProfile:        k.AwsProfile,
		}}
	case *gcpkms.MasterKey:
		return KeyOpts{GcpKmsKeyOpts: &GcpKmsKeyOpts{
			CreationDate: k.CreationDate,
			ResourceID:   k.ResourceID,
		}}
	case *azkv.MasterKey:
		return KeyOpts{AzureKVKeyOpts: &AzureKVKeyOpts{
			CreationDate: k.CreationDate,
			VaultURI:     k.VaultURL,
			KeyName:      k.Name,
			KeyVersion:   k.Version,
		}}
	case *hcvault.MasterKey:
		return KeyOpts{HCVaultOpts: &HCVaultOpts{
			CreationDate: k.CreationDate,
			VaultAddress: k.VaultAddress,
			EnginePath:   k.EnginePath,
			KeyName:      k.KeyName,
		}}
	default:
		return KeyOpts{}
	}
}

type KeyGroupOpts []KeyOpts

func (o KeyGroupOpts) Validate() error {
	if len(o) == 0 {
		return errors.New("at least one key must be provided")
	}
	for i := range o {
		if err := o[i].Validate(); err != nil {
			return fmt.Errorf("key %d: %w", i, err)
		}
	}
	return nil
}

func NewKeyGroup(o KeyGroupOpts) sops.KeyGroup {
	keys := make(sops.KeyGroup, len(o))
	for i := range o {
		keys[i] = NewKey(&o[i])
	}
	return keys
}

func RecoverKeyGroupOpts(kg sops.KeyGroup) KeyGroupOpts {
	opts := make(KeyGroupOpts, len(kg))
	for i := range kg {
		opts[i] = RecoverKeyOpts(kg[i])
	}
	return opts
}

type KeyGroupsOpts struct {
	Groups          []KeyGroupOpts
	ShamirThreshold int
}

func (o *KeyGroupsOpts) Validate() error {
	if len(o.Groups) == 0 {
		return errors.New("at least one key group must be provided")
	}
	for i := range o.Groups {
		if err := o.Groups[i].Validate(); err != nil {
			return fmt.Errorf("group %d: %w", i, err)
		}
	}
	if o.ShamirThreshold <= 0 || o.ShamirThreshold > len(o.Groups) {
		return errors.New("invalid Shamir threshold, must be between 1 and the number of key groups")
	}
	return nil
}

type KeyGroups struct {
	Groups          []sops.KeyGroup
	ShamirThreshold int
}

func NewKeyGroups(o *KeyGroupsOpts) KeyGroups {
	groups := make([]sops.KeyGroup, len(o.Groups))
	for i := range o.Groups {
		groups[i] = NewKeyGroup(o.Groups[i])
	}
	return KeyGroups{
		Groups:          groups,
		ShamirThreshold: o.ShamirThreshold,
	}
}

func RecoverKeyGroupsOpts(kg KeyGroups) KeyGroupsOpts {
	groups := make([]KeyGroupOpts, len(kg.Groups))
	for i := range kg.Groups {
		groups[i] = RecoverKeyGroupOpts(kg.Groups[i])
	}
	return KeyGroupsOpts{
		Groups:          groups,
		ShamirThreshold: kg.ShamirThreshold,
	}
}

type CryptRules struct {
	UnencryptedSuffix string
	EncryptedSuffix   string
	UnencryptedRegex  string
	EncryptedRegex    string
}

func (o *CryptRules) Validate() error {
	cryptRuleCount := 0
	if o.UnencryptedSuffix != "" {
		cryptRuleCount++
	}
	if o.EncryptedSuffix != "" {
		cryptRuleCount++
	}
	if o.UnencryptedRegex != "" {
		cryptRuleCount++
	}
	if o.EncryptedRegex != "" {
		cryptRuleCount++
	}
	if cryptRuleCount > 1 {
		return errors.New("only one crypt rule option can be set at a time")
	}
	return nil
}

var DefaultCryptRules = CryptRules{
	UnencryptedSuffix: sops.DefaultUnencryptedSuffix,
	EncryptedSuffix:   "",
	UnencryptedRegex:  "",
	EncryptedRegex:    "",
}

type MetadataOpts struct {
	Version string
	KeyGroupsOpts
	CryptRules
}

func (o *MetadataOpts) Validate() error {
	if o.Version == "" {
		return errors.New("version must be set")
	}
	if err := o.KeyGroupsOpts.Validate(); err != nil {
		return fmt.Errorf("invalid key groups: %w", err)
	}
	if err := o.CryptRules.Validate(); err != nil {
		return fmt.Errorf("invalid crypt rules: %w", err)
	}
	return nil
}

func NewMetadata(o *MetadataOpts) sops.Metadata {
	kgs := NewKeyGroups(&o.KeyGroupsOpts)
	return sops.Metadata{
		Version:           o.Version,
		KeyGroups:         kgs.Groups,
		ShamirThreshold:   kgs.ShamirThreshold,
		UnencryptedSuffix: o.UnencryptedSuffix,
		EncryptedSuffix:   o.EncryptedSuffix,
		UnencryptedRegex:  o.UnencryptedRegex,
		EncryptedRegex:    o.EncryptedRegex,
	}
}

func RecoverMetadataOpts(m *sops.Metadata) MetadataOpts {
	kgs := RecoverKeyGroupsOpts(KeyGroups{
		Groups:          m.KeyGroups,
		ShamirThreshold: m.ShamirThreshold,
	})
	return MetadataOpts{
		Version: m.Version,
		KeyGroupsOpts: KeyGroupsOpts{
			Groups:          kgs.Groups,
			ShamirThreshold: kgs.ShamirThreshold,
		},
		CryptRules: CryptRules{
			UnencryptedSuffix: m.UnencryptedSuffix,
			EncryptedSuffix:   m.EncryptedSuffix,
			UnencryptedRegex:  m.UnencryptedRegex,
			EncryptedRegex:    m.EncryptedRegex,
		},
	}
}
