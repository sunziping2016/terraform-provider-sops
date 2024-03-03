package provider

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"

	"github.com/carlpett/terraform-provider-sops/internal/client"
	"github.com/getsops/sops/v3/cmd/sops/formats"
	"github.com/hashicorp/terraform-plugin-framework-validators/datasourcevalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	_ datasource.DataSource                     = (*sopsDecryptDataSource)(nil)
	_ datasource.DataSourceWithConfigure        = (*sopsDecryptDataSource)(nil)
	_ datasource.DataSourceWithConfigValidators = (*sopsDecryptDataSource)(nil)
)

func NewSopsDecryptDataSource() datasource.DataSource {
	return &sopsDecryptDataSource{}
}

type sopsDecryptDataSource struct {
	client *client.SopsClient
}

type sopsDecryptDataSourceModel struct {
	Id                     types.String `tfsdk:"id"`
	Format                 types.String `tfsdk:"format"`
	EncryptedFormat        types.String `tfsdk:"encrypted_format"`
	DecryptedFormat        types.String `tfsdk:"decrypted_format"`
	IgnoreMAC              types.Bool   `tfsdk:"ignore_mac"`
	Source                 types.String `tfsdk:"source"`
	EncryptedContent       types.String `tfsdk:"encrypted_content"`
	EncryptedContentBase64 types.String `tfsdk:"encrypted_content_base64"`
	DecryptedContent       types.String `tfsdk:"decrypted_content"`
	DecryptedContentBase64 types.String `tfsdk:"decrypted_content_base64"`
	// TODO: add key groups and other metadata for the client to read
}

func (n *sopsDecryptDataSource) Metadata(ctx context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_decrypt"
}

func (n *sopsDecryptDataSource) Schema(ctx context.Context, req datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Decrypt an encrypted content or file using SOPS.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				MarkdownDescription: "The id of the data source. This will always be set to `-`",
				Computed:            true,
			},
			"format": schema.StringAttribute{
				MarkdownDescription: "The format of both the encrypted and decrypted content. " +
					"Valid values are `json`, `yaml`, `ini`, `dotenv` and `binary`. " +
					"Conflicts with `encrypted_format` and `decrypted_format`. " +
					"You should specify either `format`, or both `encrypted_format` and `decrypted_format`. " +
					"When none of these are set, if `source` is provided, the format will be inferred from the filename, " +
					"and otherwise it will default to `binary`.",
				Optional: true,
				Validators: []validator.String{
					stringvalidator.OneOf("json", "yaml", "ini", "dotenv", "binary"),
				},
			},
			"encrypted_format": schema.StringAttribute{
				MarkdownDescription: "The format of the encrypted content. " +
					"Valid values are `json`, `yaml`, `ini`, `dotenv` and `binary`. " +
					"Conflicts with `format`. " +
					"`encrypted_format` and `decrypted_format` should be set together. " +
					"This allows you to specify different formats for the encrypted and decrypted content. " +
					"If you want to use the same format for both the encrypted and decrypted content, " +
					"you can use `format` instead.",
				Optional: true,
				Computed: true,
				Validators: []validator.String{
					stringvalidator.OneOf("json", "yaml", "ini", "dotenv", "binary"),
				},
			},
			"decrypted_format": schema.StringAttribute{
				MarkdownDescription: "The format of the decrypted content. " +
					"Valid values are `json`, `yaml`, `ini`, `dotenv` and `binary`. " +
					"See `encrypted_format` for more information.",
				Optional: true,
				Computed: true,
				Validators: []validator.String{
					stringvalidator.OneOf("json", "yaml", "ini", "dotenv", "binary"),
				},
			},
			"ignore_mac": schema.BoolAttribute{
				MarkdownDescription: "Ignore the Message Authentication Code (MAC) during decryption. " +
					"MACs are used to verify the integrity of the encrypted content. " +
					"Setting this to `true` only if you are sure that the encrypted content has not been tampered with.",
				Optional: true,
			},
			"encrypted_content": schema.StringAttribute{
				MarkdownDescription: "The encrypted content that will be decrypted, expected to be UTF-8 encoded. " +
					"Conflicts with `source` and `encrypted_content_base64`. " +
					"Exactly one of `source`, `encrypted_content` or `encrypted_content_base64` must be specified.",
				Optional: true,
			},
			"source": schema.StringAttribute{
				MarkdownDescription: "Path to the file containing the encrypted content that will be decrypted. " +
					"Conflicts with `encrypted_content` and `encrypted_content_base64`. " +
					"Exactly one of `source`, `encrypted_content` or `encrypted_content_base64` must be specified.",
				Optional: true,
			},
			"encrypted_content_base64": schema.StringAttribute{
				MarkdownDescription: "The base64 encoded encrypted content that will be decrypted. " +
					"Conflicts with `encrypted_content` and `source`. " +
					"Exactly one of `source`, `encrypted_content` or `encrypted_content_base64` must be specified.",
				Optional: true,
			},
			"decrypted_content": schema.StringAttribute{
				MarkdownDescription: "The decrypted content, expected to be UTF-8 encoded. " +
					"Invalid UTF-8 sequences will be replaced with the Unicode replacement character.",
				Computed: true,
			},
			"decrypted_content_base64": schema.StringAttribute{
				MarkdownDescription: "The base64 encoded decrypted content. " +
					"Use this when dealing with binary data.",
				Computed: true,
			},
		},
	}
}

func (d *sopsDecryptDataSource) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}

	client, ok := req.ProviderData.(*client.SopsClient)
	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected Data Source Configure Type",
			fmt.Sprintf("Expected *client.SopsClient, got: %T. Please report this issue to the provider developers.", req.ProviderData),
		)
		return
	}
	d.client = client
}

func (d *sopsDecryptDataSource) ConfigValidators(context.Context) []datasource.ConfigValidator {
	return []datasource.ConfigValidator{
		datasourcevalidator.ExactlyOneOf(
			path.MatchRoot("source"),
			path.MatchRoot("encrypted_content"),
			path.MatchRoot("encrypted_content_base64"),
		),
		datasourcevalidator.Conflicting(
			path.MatchRoot("format"),
			path.MatchRoot("encrypted_format"),
		),
		datasourcevalidator.RequiredTogether(
			path.MatchRoot("encrypted_format"),
			path.MatchRoot("decrypted_format"),
		),
	}
}

func (n *sopsDecryptDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var data sopsDecryptDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var storeOpts client.StoreOpts
	if !data.Format.IsNull() && !data.Format.IsUnknown() {
		format := client.StringToFormat[data.Format.ValueString()]
		storeOpts.EncryptedFormat = format
		storeOpts.DecryptedFormat = format
	} else if !data.DecryptedFormat.IsNull() && !data.EncryptedFormat.IsNull() &&
		!data.DecryptedContent.IsUnknown() && !data.EncryptedContent.IsUnknown() {
		storeOpts.EncryptedFormat = client.StringToFormat[data.EncryptedFormat.ValueString()]
		storeOpts.DecryptedFormat = client.StringToFormat[data.DecryptedFormat.ValueString()]
	} else {
		format := formats.FormatForPath(data.Source.ValueString())
		storeOpts.EncryptedFormat = format
		storeOpts.DecryptedFormat = format
	}
	stores := client.NewStores(&storeOpts)
	ignoreMAC := data.IgnoreMAC.ValueBool()
	encryptedContent, err := parseEncryptedContent(data)
	if err != nil {
		resp.Diagnostics.AddError("Failed to load encrypted content", err.Error())
		return
	}

	decrypted, err := n.client.Decrypt(encryptedContent, client.DecryptOpts{
		Stores:    stores,
		IgnoreMAC: ignoreMAC,
	})
	if err != nil {
		resp.Diagnostics.AddError("Failed to decrypt content", err.Error())
		return
	}

	data.Id = types.StringValue("-")
	data.EncryptedFormat = types.StringValue(client.FormatToString[storeOpts.EncryptedFormat])
	data.DecryptedFormat = types.StringValue(client.FormatToString[storeOpts.DecryptedFormat])
	data.DecryptedContent = types.StringValue(string(decrypted.Content))
	data.DecryptedContentBase64 = types.StringValue(base64.StdEncoding.EncodeToString(decrypted.Content))

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func parseEncryptedContent(data sopsDecryptDataSourceModel) ([]byte, error) {
	if !data.EncryptedContentBase64.IsNull() && !data.EncryptedContentBase64.IsUnknown() {
		return base64.StdEncoding.DecodeString(data.EncryptedContentBase64.ValueString())
	}

	if !data.Source.IsNull() && !data.Source.IsUnknown() {
		return os.ReadFile(data.Source.ValueString())
	}

	return []byte(data.EncryptedContent.ValueString()), nil
}
