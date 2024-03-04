package provider

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/carlpett/terraform-provider-sops/internal/client"
	"github.com/hashicorp/terraform-plugin-framework-validators/setvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	_ provider.Provider = (*sopsProvider)(nil)
)

const configFileName = ".sops.yaml"

func New(version string) func() provider.Provider {
	return func() provider.Provider {
		return &sopsProvider{
			version: version,
		}
	}
}

type sopsProvider struct {
	version string
}

type sopsProviderModel struct {
	DisableLocalKeyService     types.Bool   `tfsdk:"disable_local_key_service"`
	KeyServiceURIs             types.Set    `tfsdk:"key_service_uris"`
	ConfigFile                 types.String `tfsdk:"config_file"`
	DisableConfigFileDiscovery types.Bool   `tfsdk:"disable_config_file_discovery"`
}

type sopsProviderData struct {
	client.SopsClient
	configFile *string
}

func (p *sopsProvider) Metadata(ctx context.Context, req provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "sops"
	resp.Version = p.version
}

func (p *sopsProvider) Schema(ctx context.Context, req provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"disable_local_key_service": schema.BoolAttribute{
				Optional: true,
				MarkdownDescription: "Disable the local key service. " +
					"Can also be set using a non-empty `SOPS_DISABLE_LOCAL_KEY_SERVICE` environment variable. " +
					"If set, you must provide `key_service_uris` to make the key discovery work.",
			},
			"key_service_uris": schema.SetAttribute{
				ElementType: types.StringType,
				Optional:    true,
				MarkdownDescription: "The URIs of the key service. " +
					"Can also be set using the comma-separated `SOPS_KEY_SERVICE_URIS` environment variable. " +
					"You can start the server-side key service by running `sops keyserver` to enable remote key discovery. " +
					"Examples: `tcp://myserver.com:5000`, `unix:///var/run/sops.sock`.",
				Validators: []validator.Set{
					setvalidator.ValueStringsAre(
						stringvalidator.RegexMatches(
							regexp.MustCompile(`^(tcp|unix)://.+$`),
							"The key service URI must start with `tcp://` or `unix://`.",
						),
					),
				},
			},
			"config_file": schema.StringAttribute{
				Optional: true,
				MarkdownDescription: "The path to the SOPS configuration file. " +
					"Can also be set using the `SOPS_CONFIG_FILE` environment variable. " +
					"The file should follow the `.sops.yaml` format. " +
					"See the `config_file` attribute in the resource documentation for its usage.",
			},
			"disable_config_file_discovery": schema.BoolAttribute{
				Optional: true,
				MarkdownDescription: "Disable the discovery of the SOPS configuration file. " +
					"Can also be set using a non-empty `SOPS_DISABLE_CONFIG_FILE_DISCOVERY` environment variable. " +
					"By default, the provider will recursively search for a `.sops.yaml` file in the current directory and its parents. " +
					"If none is found, the provider will generated a warning. " +
					"To disable this behavior, set this attribute to `true`. " +
					"This option is ignored if `config_file` is set.",
			},
		},
	}
}

func (p *sopsProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	var data sopsProviderModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if data.DisableLocalKeyService.IsUnknown() {
		resp.Diagnostics.AddAttributeError(
			path.Root("disable_local_key_service"),
			"Unknown option for disabling the local key service",
			"Cannot initialize the provider without knowing whether to disable the local key service",
		)
	}
	if data.KeyServiceURIs.IsUnknown() {
		resp.Diagnostics.AddAttributeError(
			path.Root("key_service_uris"),
			"Unknown key service URIs",
			"Cannot initialize the provider without knowing the key service URIs",
		)
	}
	if data.ConfigFile.IsUnknown() {
		resp.Diagnostics.AddAttributeError(
			path.Root("config_file"),
			"Unknown SOPS configuration file",
			"Cannot initialize the provider without knowing the SOPS configuration file",
		)
	}
	if data.DisableConfigFileDiscovery.IsUnknown() {
		resp.Diagnostics.AddAttributeError(
			path.Root("disable_config_file_discovery"),
			"Unknown option for disabling the discovery of the SOPS configuration file",
			"Cannot initialize the provider without knowing whether to disable the discovery of the SOPS configuration file",
		)
	}
	if resp.Diagnostics.HasError() {
		return
	}

	keyServiceBuilder := client.NewKeyServiceBuilder()

	if !data.DisableLocalKeyService.IsNull() {
		if !data.DisableLocalKeyService.ValueBool() {
			keyServiceBuilder.AddLocalKeyService()
		}
	} else if os.Getenv("SOPS_DISABLE_LOCAL_KEY_SERVICE") == "" {
		keyServiceBuilder.AddLocalKeyService()
	}

	if !data.KeyServiceURIs.IsNull() {
		elements := make([]types.String, 0, len(data.KeyServiceURIs.Elements()))
		resp.Diagnostics.Append(data.KeyServiceURIs.ElementsAs(ctx, &elements, false)...)

		for _, elem := range elements {
			if elem.IsUnknown() {
				resp.Diagnostics.AddAttributeError(
					path.Root("key_service_uris").AtSetValue(elem),
					"Unknown key service URI",
					"Cannot initialize the provider without knowing the key service URI",
				)
				continue
			}
			if elem.IsNull() {
				resp.Diagnostics.AddAttributeError(
					path.Root("key_service_uri").AtSetValue(elem),
					"Null key service URI",
					"Cannot initialize the provider with a null key service URI",
				)
				continue
			}
			err := keyServiceBuilder.AddKeyServiceWithURI(ctx, elem.ValueString())
			if err != nil {
				resp.Diagnostics.AddAttributeError(
					path.Root("key_service_uris").AtSetValue(elem),
					"Invalid key service URI",
					err.Error(),
				)
			}
		}
	} else if envKeyServiceURIs := os.Getenv("SOPS_KEY_SERVICE_URIS"); envKeyServiceURIs != "" {
		keyServiceURIs := strings.Split(envKeyServiceURIs, ",")
		for _, keyServiceURI := range keyServiceURIs {
			err := keyServiceBuilder.AddKeyServiceWithURI(ctx, keyServiceURI)
			if err != nil {
				resp.Diagnostics.AddError(
					"Invalid key service URI",
					fmt.Sprintf("Failed to add key service URI %q specified in the SOPS_KEY_SERVICE_URIS environment variable", keyServiceURI),
				)
			}
		}
	}

	if resp.Diagnostics.HasError() {
		return
	}

	var configFile *string
	if !data.ConfigFile.IsNull() {
		fileInfo, err := os.Stat(data.ConfigFile.ValueString())
		if err != nil {
			resp.Diagnostics.AddAttributeError(
				path.Root("config_file"),
				"Failed to access the SOPS configuration file",
				err.Error(),
			)
		} else if !fileInfo.Mode().IsRegular() {
			resp.Diagnostics.AddAttributeError(
				path.Root("config_file"),
				"Invalid SOPS configuration file",
				"The SOPS configuration file must be a regular file",
			)
		}
		configFile = data.ConfigFile.ValueStringPointer()
	} else if envConfigFile := os.Getenv("SOPS_CONFIG_FILE"); envConfigFile != "" {
		fileInfo, err := os.Stat(envConfigFile)
		if err != nil {
			resp.Diagnostics.AddError(
				"Failed to access the SOPS configuration file",
				err.Error(),
			)
		} else if !fileInfo.Mode().IsRegular() {
			resp.Diagnostics.AddError(
				"Invalid SOPS configuration file",
				"The SOPS configuration file must be a regular file",
			)
		}
		configFile = &envConfigFile
	} else {
		var disableConfigFileDiscovery bool
		if !data.DisableConfigFileDiscovery.IsNull() {
			disableConfigFileDiscovery = data.DisableConfigFileDiscovery.ValueBool()
		} else if os.Getenv("SOPS_DISABLE_CONFIG_FILE_DISCOVERY") != "" {
			disableConfigFileDiscovery = true
		}
		if !disableConfigFileDiscovery {
			currentDir, err := os.Getwd()
			if err != nil {
				resp.Diagnostics.AddError("Failed to get the current working directory", err.Error())
			} else {
				for {
					filePath := filepath.Join(currentDir, configFileName)
					fileInfo, err := os.Stat(filePath)
					if !os.IsNotExist(err) {
						if err != nil {
							resp.Diagnostics.AddError("Failed to access the SOPS configuration file", err.Error())
						} else if !fileInfo.Mode().IsRegular() {
							resp.Diagnostics.AddError("Invalid SOPS configuration file",
								"The SOPS configuration file must be a regular file")
						}
						configFile = &filePath
						break
					}
					parentDir := filepath.Dir(currentDir)
					if parentDir == currentDir {
						break
					}
					currentDir = parentDir
				}
				if configFile == nil {
					resp.Diagnostics.AddWarning("Failed to find the SOPS configuration file",
						"The provider could not find a `.sops.yaml` file in the current directory and its parents. "+
							"You can disable this behavior by setting the `disable_config_file_discovery` attribute to `true`.")
				}
			}
		}
	}
	if resp.Diagnostics.HasError() {
		return
	}

	keyServices, err := keyServiceBuilder.Build()
	if err != nil {
		resp.Diagnostics.AddError("Failed to initialize key services", err.Error())
		return
	}

	providerData := sopsProviderData{
		SopsClient: client.NewSopsClient(keyServices),
		configFile: configFile,
	}
	resp.DataSourceData = &providerData
	resp.ResourceData = &providerData
}

func (p *sopsProvider) DataSources(ctx context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{
		NewSopsDecryptDataSource,
	}
}

func (p *sopsProvider) Resources(ctx context.Context) []func() resource.Resource {
	return []func() resource.Resource{
		NewSopsEncryptResource,
	}
}
