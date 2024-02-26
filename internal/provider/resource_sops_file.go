package provider

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	"github.com/carlpett/terraform-provider-sops/internal/localtypes"
	"github.com/getsops/sops/v3"
	"github.com/getsops/sops/v3/aes"
	"github.com/getsops/sops/v3/cmd/sops/common"
	"github.com/getsops/sops/v3/config"
	"github.com/getsops/sops/v3/keyservice"
	"github.com/getsops/sops/v3/version"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	_ resource.Resource              = (*sopsFileResource)(nil)
	_ resource.ResourceWithConfigure = (*sopsFileResource)(nil)
)

func NewSopsFileResource() resource.Resource {
	return &sopsFileResource{}
}

type sopsFileResource struct {
	configPath string
}

func (n *sopsFileResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Generates a sops file with the given content.",
		Attributes: map[string]schema.Attribute{
			"filename": schema.StringAttribute{
				Description: "The path to the file that will be created.",
				Required:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"content": schema.StringAttribute{
				Description: "Content to store in the file, expected to be a UTF-8 encoded string.",
				Optional:    true,
				Sensitive:   true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
				Validators: []validator.String{
					stringvalidator.ExactlyOneOf(
						path.MatchRoot("content_base64"),
					),
				},
			},
			"content_base64": schema.StringAttribute{
				Description: "Content to store in the file, expected to be binary encoded as base64 string.\n " +
					"Conflicts with `content`, `sensitive_content` and `source`.\n " +
					"Exactly one of these four arguments must be specified.",
				Optional:  true,
				Sensitive: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
				Validators: []validator.String{
					stringvalidator.ExactlyOneOf(
						path.MatchRoot("content"),
					),
				},
			},
			"file_permission": schema.StringAttribute{
				CustomType: localtypes.NewFilePermissionType(),
				Description: "Permissions to set for the output file (before umask), expressed as string in\n " +
					"[numeric notation](https://en.wikipedia.org/wiki/File-system_permissions#Numeric_notation).\n " +
					"Default value is `\"0777\"`.",
				Optional: true,
				Computed: true,
				Default:  stringdefault.StaticString("0777"),
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
		},
	}
}

func (n *sopsFileResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_file"
}

func (n *sopsFileResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}

	client, ok := req.ProviderData.(*sopsClient)
	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected provider data type",
			fmt.Sprintf("Expected *sopsClient, got %T", req.ProviderData),
		)
		return
	}

	n.configPath = client.configPath
}

func (n *sopsFileResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan sopsFileResourceModelV0
	var filePerm string

	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	content, err := parseLocalFileContent(plan)
	if err != nil {
		resp.Diagnostics.AddError(
			"Create local file error",
			"An unexpected error occurred while parsing local file content\n\n+"+
				fmt.Sprintf("Original Error: %s", err),
		)
		return
	}

	destination := plan.Filename.ValueString()

	inputStore := common.DefaultStoreForPathOrFormat(destination, "")
	outputStore := common.DefaultStoreForPathOrFormat(destination, "")

	configPath := n.configPath
	if configPath == "" {
		configPath, err = config.FindConfigFile(".")
		if err != nil {
			resp.Diagnostics.AddError(
				"Cannot find sops configuration file",
				err.Error(),
			)
			return
		}
	}
	conf, err := config.LoadCreationRuleForFile(configPath, destination, make(map[string]*string))
	if err != nil {
		resp.Diagnostics.AddError(
			"Cannot load creation rule for file",
			err.Error(),
		)
		return
	}

	if conf == nil {
		resp.Diagnostics.AddError(
			"Cannot load creation rule for file",
			"config file not found and no keys provided through command line options",
		)
		return
	}

	branches, err := inputStore.LoadPlainFile(content)
	if err != nil {
		resp.Diagnostics.AddError(
			"Cannot parse content",
			err.Error(),
		)
		return
	}
	if len(branches) < 1 {
		resp.Diagnostics.AddError(
			"Cannot parse content",
			"file cannot be empty",
		)
		return
	}
	path, err := filepath.Abs(destination)
	if err != nil {
		resp.Diagnostics.AddError(
			"Cannot get absolute path",
			err.Error(),
		)
		return
	}

	tree := sops.Tree{
		Branches: branches,
		Metadata: sops.Metadata{
			KeyGroups:         conf.KeyGroups,
			UnencryptedSuffix: sops.DefaultUnencryptedSuffix,
			EncryptedSuffix:   "",
			UnencryptedRegex:  "",
			EncryptedRegex:    "",
			Version:           version.Version,
			ShamirThreshold:   conf.ShamirThreshold,
		},
		FilePath: path,
	}
	svcs := []keyservice.KeyServiceClient{keyservice.NewLocalClient()}
	dataKey, errs := tree.GenerateDataKeyWithKeyServices(svcs)
	if len(errs) > 0 {
		resp.Diagnostics.AddError(
			"Cannot generate data key",
			fmt.Sprintf("%s", errs),
		)
		return
	}

	err = common.EncryptTree(common.EncryptTreeOpts{
		DataKey: dataKey,
		Tree:    &tree,
		Cipher:  aes.NewCipher(),
	})
	if err != nil {
		resp.Diagnostics.AddError(
			"Cannot encrypt tree",
			err.Error(),
		)
		return
	}

	encryptedContent, err := outputStore.EmitEncryptedFile(tree)
	if err != nil {
		resp.Diagnostics.AddError(
			"Cannot emit encrypted file",
			err.Error(),
		)
		return
	}

	filePerm = plan.FilePermission.ValueString()
	fileMode, _ := strconv.ParseInt(filePerm, 8, 64)

	if err := os.WriteFile(destination, encryptedContent, os.FileMode(fileMode)); err != nil {
		resp.Diagnostics.AddError(
			"Create local file error",
			"An unexpected error occurred while writing the file\n\n+"+
				fmt.Sprintf("Original Error: %s", err),
		)
		return
	}

	diags = resp.State.Set(ctx, &plan)
	resp.Diagnostics.Append(diags...)
}

func (n *sopsFileResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
}

func (n *sopsFileResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
}

func (n *sopsFileResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
}

func parseLocalFileContent(plan sopsFileResourceModelV0) ([]byte, error) {
	if !plan.ContentBase64.IsNull() && !plan.ContentBase64.IsUnknown() {
		return base64.StdEncoding.DecodeString(plan.ContentBase64.ValueString())
	}

	content := plan.Content.ValueString()
	return []byte(content), nil
}

type sopsFileResourceModelV0 struct {
	Filename       types.String `tfsdk:"filename"`
	Content        types.String `tfsdk:"content"`
	ContentBase64  types.String `tfsdk:"content_base64"`
	FilePermission types.String `tfsdk:"file_permission"`
}
