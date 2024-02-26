package provider

import (
	"testing"

	r "github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestSopsFileDataSource(t *testing.T) {
	const (
		config = `
			data "sops_file" "file" {
				filename = "./testdata/basic.yaml"
			}`
		content     = "hello: world\n"
		contentJson = "{\n\t\"hello\": \"world\"\n}"
	)

	r.UnitTest(t, r.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []r.TestStep{
			{
				Config: config,
				Check: r.ComposeAggregateTestCheckFunc(
					r.TestCheckResourceAttr("data.sops_file.file", "content", content),
					r.TestCheckResourceAttr("data.sops_file.file", "content_json", contentJson),
				),
			},
		},
	})
}
