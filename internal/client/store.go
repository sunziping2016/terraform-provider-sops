package client

import (
	"github.com/getsops/sops/v3/cmd/sops/common"
	"github.com/getsops/sops/v3/cmd/sops/formats"
)

type StoreOpts struct {
	EncryptedFormat formats.Format
	DecryptedFormat formats.Format
}

type Stores struct {
	Encrypted common.Store
	Decrypted common.Store
}

func NewStores(o *StoreOpts) Stores {
	return Stores{
		Encrypted: common.StoreForFormat(o.EncryptedFormat),
		Decrypted: common.StoreForFormat(o.DecryptedFormat),
	}
}
