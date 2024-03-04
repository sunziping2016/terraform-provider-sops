package provider

import (
	_ "embed"
	"encoding/base64"
	"fmt"
	"testing"

	r "github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

var (
	//go:embed testdata/basic_encrypted.yaml
	basicEncryptedYaml []byte
	//go:embed testdata/basic_decrypted.yaml
	basicDecryptedYaml []byte
	//go:embed testdata/basic_decrypted.json
	basicDecryptedJson []byte
)

func TestSopsDecryptDataSource_Basic(t *testing.T) {
	var config1 = fmt.Sprintf(`
data "sops_decrypt" "basic" {
	format = "yaml"
	encrypted_content = %q
}`, basicEncryptedYaml)

	r.UnitTest(t, r.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []r.TestStep{
			{
				Config: config1,
				Check: r.ComposeAggregateTestCheckFunc(
					r.TestCheckResourceAttr("data.sops_decrypt.basic", "encrypted_format", "yaml"),
					r.TestCheckResourceAttr("data.sops_decrypt.basic", "decrypted_format", "yaml"),
					r.TestCheckResourceAttr("data.sops_decrypt.basic", "decrypted_content", string(basicDecryptedYaml)),
					r.TestCheckResourceAttr("data.sops_decrypt.basic", "decrypted_content_base64", base64.StdEncoding.EncodeToString(basicDecryptedYaml)),
				),
			},
		},
	})
}

func TestSopsDecryptDataSource_CustomizeFormat(t *testing.T) {
	var config = fmt.Sprintf(`
data "sops_decrypt" "basic" {
	encrypted_format = "yaml"
	decrypted_format = "json"
	encrypted_content = %q
}`, basicEncryptedYaml)

	r.UnitTest(t, r.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []r.TestStep{
			{
				Config: config,
				Check: r.ComposeAggregateTestCheckFunc(
					r.TestCheckResourceAttr("data.sops_decrypt.basic", "encrypted_format", "yaml"),
					r.TestCheckResourceAttr("data.sops_decrypt.basic", "decrypted_format", "json"),
					r.TestCheckResourceAttr("data.sops_decrypt.basic", "decrypted_content", string(basicDecryptedJson)),
					r.TestCheckResourceAttr("data.sops_decrypt.basic", "decrypted_content_base64", base64.StdEncoding.EncodeToString(basicDecryptedJson)),
				),
			},
		},
	})
}

func TestSopsDecryptDataSource_EncryptedFile(t *testing.T) {
	var config = `
data "sops_decrypt" "basic" {
	source = "testdata/basic_encrypted.yaml"
}`
	r.UnitTest(t, r.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []r.TestStep{
			{
				Config: config,
				Check: r.ComposeAggregateTestCheckFunc(
					r.TestCheckResourceAttr("data.sops_decrypt.basic", "encrypted_format", "yaml"),
					r.TestCheckResourceAttr("data.sops_decrypt.basic", "decrypted_format", "yaml"),
					r.TestCheckResourceAttr("data.sops_decrypt.basic", "decrypted_content", string(basicDecryptedYaml)),
					r.TestCheckResourceAttr("data.sops_decrypt.basic", "decrypted_content_base64", base64.StdEncoding.EncodeToString(basicDecryptedYaml)),
				),
			},
		},
	})
}

func TestSopsDecryptDataSource_EncryptedContentBase64(t *testing.T) {
	var config = fmt.Sprintf(`
data "sops_decrypt" "basic" {
	format = "yaml"
	encrypted_content_base64 = %q
}`, base64.StdEncoding.EncodeToString(basicEncryptedYaml))

	r.UnitTest(t, r.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []r.TestStep{
			{
				Config: config,
				Check: r.ComposeAggregateTestCheckFunc(
					r.TestCheckResourceAttr("data.sops_decrypt.basic", "encrypted_format", "yaml"),
					r.TestCheckResourceAttr("data.sops_decrypt.basic", "decrypted_format", "yaml"),
					r.TestCheckResourceAttr("data.sops_decrypt.basic", "decrypted_content", string(basicDecryptedYaml)),
					r.TestCheckResourceAttr("data.sops_decrypt.basic", "decrypted_content_base64", base64.StdEncoding.EncodeToString(basicDecryptedYaml)),
				),
			},
		},
	})
}
