package provider

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	r "github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestLocalFile_Basic(t *testing.T) {
	f := filepath.Join(t.TempDir(), "local_file.json")
	f = strings.ReplaceAll(f, `\`, `\\`)

	config, err := os.ReadFile("../../.sops.yaml")
	if err != nil {
		t.Fatalf("Error occurred while reading .sops.yaml file, error: %s", err)
	}
	err = os.WriteFile(filepath.Join(t.TempDir(), ".sops.yaml"), config, 0644)
	if err != nil {
		t.Fatalf("Error occurred while writing .sops.yaml file, error: %s", err)
	}

	r.UnitTest(t, r.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []r.TestStep{
			{
				Config: providerConfig + testAccConfigLocalFileContent(`{"local":"basic"}`, f),
				Check:  checkFileCreation("sops_file.file", f),
			},
		},
		CheckDestroy: checkFileDeleted(f),
	})
}

func testAccConfigLocalFileContent(content, filename string) string {
	return fmt.Sprintf(`
		resource "sops_file" "file" {
			content  = %[1]q
			filename = %[2]q
		}`, content, filename)
}
