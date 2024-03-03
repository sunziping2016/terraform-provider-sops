package provider

import (
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	r "github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

var testAccProtoV6ProviderFactories = map[string]func() (tfprotov6.ProviderServer, error){
	"sops": providerserver.NewProtocol6WithError(New("test")()),
}

func TestSopsProvider(t *testing.T) {
	var config = `
provider "sops" {
	disable_local_key_service = true
}
`
	var restConfig = `
data "sops_decrypt" "basic" {
	source = "testdata/basic_encrypted.yaml"
}`
	r.UnitTest(t, r.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []r.TestStep{
			{
				Config:      config + restConfig,
				ExpectError: regexp.MustCompile(`Failed to initialize key services`),
			},
		},
	})
}
