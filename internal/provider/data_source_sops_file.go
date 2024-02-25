package provider

import (
	"context"

	"github.com/getsops/sops/v3/aes"
	"github.com/getsops/sops/v3/cmd/sops/common"
	"github.com/getsops/sops/v3/cmd/sops/formats"
	"github.com/getsops/sops/v3/keyservice"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	_ datasource.DataSource = (*sopsFileDataSource)(nil)
)

func NewSopsFileDataSource() datasource.DataSource {
	return &sopsFileDataSource{}
}

type sopsFileDataSource struct{}

func (n *sopsFileDataSource) Metadata(ctx context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_file"
}

func (n *sopsFileDataSource) Schema(ctx context.Context, req datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Decrypt a sops file from the local filesystem.",
		Attributes: map[string]schema.Attribute{
			"filename": schema.StringAttribute{
				Description: "Path to the sops file that will be read. The data source will return an error if the file does not exist.",
				Required:    true,
			},
			"content": schema.StringAttribute{
				Description: "Raw content of the file that was read, as UTF-8 encoded string.",
				Computed:    true,
				Sensitive:   true,
			},
			"content_json": schema.StringAttribute{
				Description: "The content of the file, parsed as JSON.",
				Computed:    true,
				Sensitive:   true,
			},
		},
	}
}

func (n *sopsFileDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var config sopsFileDataSourceModelV0
	diags := req.Config.Get(ctx, &config)
	resp.Diagnostics.Append(diags...)

	store := common.DefaultStoreForPathOrFormat(config.Filename.ValueString(), "")
	jsonStore := common.StoreForFormat(formats.Json)
	cipher := aes.NewCipher()
	svcs := []keyservice.KeyServiceClient{keyservice.NewLocalClient()}
	tree, err := common.LoadEncryptedFileWithBugFixes(common.GenericDecryptOpts{
		Cipher:      cipher,
		InputStore:  store,
		InputPath:   config.Filename.ValueString(),
		IgnoreMAC:   false,
		KeyServices: svcs,
	})
	if err != nil {
		resp.Diagnostics.AddError("Failed to load encrypted file", err.Error())
		return
	}

	_, err = common.DecryptTree(common.DecryptTreeOpts{
		Cipher:      cipher,
		IgnoreMac:   false,
		Tree:        tree,
		KeyServices: svcs,
	})
	if err != nil {
		resp.Diagnostics.AddError("Failed to decrypt file", err.Error())
		return
	}

	text, err := store.EmitPlainFile(tree.Branches)
	if err != nil {
		resp.Diagnostics.AddError("Failed to emit plain file", err.Error())
		return
	}
	json, err := jsonStore.EmitPlainFile(tree.Branches)
	if err != nil {
		resp.Diagnostics.AddError("Failed to emit json file", err.Error())
		return
	}

	state := sopsFileDataSourceModelV0{
		Filename:    config.Filename,
		Content:     types.StringValue(string(text)),
		ContentJson: types.StringValue(string(json)),
	}
	diags = resp.State.Set(ctx, state)
	resp.Diagnostics.Append(diags...)
}

type sopsFileDataSourceModelV0 struct {
	Filename    types.String `tfsdk:"filename"`
	Content     types.String `tfsdk:"content"`
	ContentJson types.String `tfsdk:"content_json"`
}
