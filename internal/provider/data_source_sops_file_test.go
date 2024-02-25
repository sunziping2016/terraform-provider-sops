package provider

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

const (
	config = `
data "sops_file" "file" {
	filename = "./testdata/basic.yaml"
}
`
	content     = "hello: world\n"
	contentJson = `{
	"hello": "world"
}`
)

func TestSopsFileDataSource(t *testing.T) {

	resource.UnitTest(t, resource.TestCase{
		ProtoV5ProviderFactories: protoV5ProviderFactories(),
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("data.sops_file.file", "content", content),
					resource.TestCheckResourceAttr("data.sops_file.file", "content_json", contentJson),
				),
			},
		},
	})
}
