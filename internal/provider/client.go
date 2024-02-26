package provider

type sopsClient struct {
	configPath string
}

type formatType string

const (
	formatTypeBinary formatType = "binary"
	formatTypeDotenv formatType = "dotenv"
	formatTypeIni    formatType = "ini"
	formatTypeJson   formatType = "json"
	formatTypeYaml   formatType = "yaml"
)

type decryptOpts struct {
	inputType              formatType
	outputType             formatType
	disableLocalKeyService bool
	keyServices            []string
}

func (c *sopsClient) decrypt(filename string, opts decryptOpts) {
}
