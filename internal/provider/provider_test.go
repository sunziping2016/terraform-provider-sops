package provider

import (
	"fmt"
	"os"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

var testAccProtoV6ProviderFactories = map[string]func() (tfprotov6.ProviderServer, error){
	"sops": providerserver.NewProtocol6WithError(New("test")()),
}

const (
	providerConfig = `
provider "sops" {
	config = "../../.sops.yaml"
}
`
)

func checkFileCreation(resourceName, path string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		resultContent, _ := os.ReadFile(path)
		fmt.Printf("resultContent: %s\n", resultContent)
		// if err != nil {
		// 	return fmt.Errorf("Error occurred while reading file at path: %s\n, error: %s\n", path, err)
		// }

		return nil
	}
}

func checkFileDeleted(shouldNotExistFile string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		if _, err := os.Stat(shouldNotExistFile); os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("file %s was not deleted", shouldNotExistFile)
	}
}
