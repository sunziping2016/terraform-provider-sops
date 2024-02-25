package provider

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"strconv"

	"github.com/carlpett/terraform-provider-sops/internal/localtypes"
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
	_ resource.Resource = (*sopsFileResource)(nil)
)

func NewSopsFileResource() resource.Resource {
	return &sopsFileResource{}
}

type sopsFileResource struct{}

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

func (n *sopsFileDataSource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
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
	filePerm = plan.FilePermission.ValueString()
	fileMode, _ := strconv.ParseInt(filePerm, 8, 64)

	if err := os.WriteFile(destination, content, os.FileMode(fileMode)); err != nil {
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

func (n *sopsFileResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
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
