package client

import (
	"github.com/getsops/sops/v3/cmd/sops/common"
	"github.com/getsops/sops/v3/cmd/sops/formats"
)

var StringToFormat = map[string]formats.Format{
	"json":   formats.Json,
	"yaml":   formats.Yaml,
	"ini":    formats.Ini,
	"dotenv": formats.Dotenv,
	// binary is zero value, so it will be used as default
	"binary": formats.Binary,
}

var FormatToString = map[formats.Format]string{
	formats.Json:   "json",
	formats.Yaml:   "yaml",
	formats.Ini:    "ini",
	formats.Dotenv: "dotenv",
	formats.Binary: "binary",
}

type Stores struct {
	Encrypted common.Store
	Decrypted common.Store
}

type StoreOpts struct {
	EncryptedFormat formats.Format
	DecryptedFormat formats.Format
}

func NewStores(
	o StoreOpts,
) Stores {
	return Stores{
		Encrypted: common.StoreForFormat(o.EncryptedFormat),
		Decrypted: common.StoreForFormat(o.DecryptedFormat),
	}
}
