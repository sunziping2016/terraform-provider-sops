package provider

import (
	"context"
	"fmt"
	"os"
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
	DisableLocalKeyService types.Bool `tfsdk:"disable_local_key_service"`
	KeyServiceURIs         types.Set  `tfsdk:"key_service_uris"`
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
			err := keyServiceBuilder.AddKeyServiceWithURI(elem.ValueString())
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
			err := keyServiceBuilder.AddKeyServiceWithURI(keyServiceURI)
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

	keyServices, err := keyServiceBuilder.Build()
	if err != nil {
		resp.Diagnostics.AddError("Failed to initialize key services", err.Error())
		return
	}

	sopsClient := client.NewSopsClient(keyServices)
	resp.DataSourceData = sopsClient
	resp.ResourceData = sopsClient
}

func (p *sopsProvider) DataSources(ctx context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{
		NewSopsDecryptDataSource,
	}
}

func (p *sopsProvider) Resources(ctx context.Context) []func() resource.Resource {
	return []func() resource.Resource{
		// NewSopsFileResource,
	}
}
