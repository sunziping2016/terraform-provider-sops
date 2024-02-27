package provider

import (
	"context"
	"os"

	"github.com/getsops/sops/v3/aes"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
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

func (p *sopsProvider) Metadata(ctx context.Context, req provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "sops"
	resp.Version = p.version
}

func (p *sopsProvider) Schema(ctx context.Context, req provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"config": schema.StringAttribute{
				Optional: true,
			},
		},
	}
}

func (p *sopsProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	var model sopsProviderModel
	diags := req.Config.Get(ctx, &model)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	if model.Config.IsUnknown() {
		resp.Diagnostics.AddAttributeError(
			path.Root("config"),
			"Unknown sops configuration file path",
			"The sops cannot be configured with an unknown configuration file path.",
		)
	}

	if resp.Diagnostics.HasError() {
		return
	}

	configPath := os.Getenv("SOPS_CONFIG")
	if !model.Config.IsNull() {
		configPath = model.Config.ValueString()
	}

	if configPath != "" {
		fileInfo, err := os.Stat(configPath)
		if err != nil {
			resp.Diagnostics.AddError(
				"Invalid sops configuration file path",
				err.Error(),
			)
			return
		}
		if !fileInfo.Mode().IsRegular() {
			resp.Diagnostics.AddError(
				"Invalid sops configuration file path",
				"The sops configuration file path must be a regular file.",
			)
			return
		}
	}

	client := &sopsClient{
		configPath: configPath,
		cipher:     aes.NewCipher(),
	}

	resp.DataSourceData = client
	resp.ResourceData = client
}

func (p *sopsProvider) DataSources(ctx context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{
		NewSopsFileDataSource,
	}
}

func (p *sopsProvider) Resources(ctx context.Context) []func() resource.Resource {
	return []func() resource.Resource{
		NewSopsFileResource,
	}
}

type sopsProviderModel struct {
	Config types.String `tfsdk:"config"`
}
