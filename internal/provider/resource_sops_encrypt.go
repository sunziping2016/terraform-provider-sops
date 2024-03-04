package provider

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"time"

	"github.com/carlpett/terraform-provider-sops/internal/client"
	"github.com/getsops/sops/v3"
	"github.com/getsops/sops/v3/cmd/sops/formats"
	sopsconfig "github.com/getsops/sops/v3/config"
	"github.com/getsops/sops/v3/keys"
	"github.com/getsops/sops/v3/version"
	"github.com/hashicorp/terraform-plugin-framework-timetypes/timetypes"
	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework-validators/resourcevalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/setvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/setplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
)

var (
	_ resource.Resource                     = (*sopsEncryptResource)(nil)
	_ resource.ResourceWithConfigure        = (*sopsEncryptResource)(nil)
	_ resource.ResourceWithConfigValidators = (*sopsEncryptResource)(nil)
	_ resource.ResourceWithModifyPlan       = (*sopsEncryptResource)(nil)
)

func NewSopsEncryptResource() resource.Resource {
	return &sopsEncryptResource{}
}

type sopsEncryptResource struct {
	client *sopsProviderData
}

type sopsEncryptResourceModel struct {
	Id types.String `tfsdk:"id"`

	Format            types.String `tfsdk:"format"`
	UnencryptedFormat types.String `tfsdk:"unencrypted_format"`
	EncryptedFormat   types.String `tfsdk:"encrypted_format"`

	Source                   types.String `tfsdk:"source"`
	UnencryptedContent       types.String `tfsdk:"unencrypted_content"`
	UnencryptedContentBase64 types.String `tfsdk:"unencrypted_content_base64"`
	Filename                 types.String `tfsdk:"filename"`
	FilePermission           types.String `tfsdk:"file_permission"`
	EncryptedContent         types.String `tfsdk:"encrypted_content"`
	EncryptedContentBase64   types.String `tfsdk:"encrypted_content_base64"`

	UnencryptedSuffix types.String `tfsdk:"unencrypted_suffix"`
	EncryptedSuffix   types.String `tfsdk:"encrypted_suffix"`
	UnencryptedRegex  types.String `tfsdk:"unencrypted_regex"`
	EncryptedRegex    types.String `tfsdk:"encrypted_regex"`

	KeyGroups       types.Set   `tfsdk:"key_groups"`
	ShamirThreshold types.Int64 `tfsdk:"shamir_threshold"`

	ConfigFile     types.String `tfsdk:"config_file"`
	PseudoFilename types.String `tfsdk:"pseudo_filename"`
}

type ageModel struct {
	Recipient types.String `tfsdk:"recipient"`
}

var ageModelAttributeTypes = map[string]attr.Type{
	"recipient": types.StringType,
}

var ageModelType = types.ObjectType{AttrTypes: ageModelAttributeTypes}

type pgpModel struct {
	CreationDate timetypes.RFC3339 `tfsdk:"creation_date"`
	Fingerprint  types.String      `tfsdk:"fingerprint"`
}

var pgpModelAttributeTypes = map[string]attr.Type{
	"creation_date": timetypes.RFC3339Type{},
	"fingerprint":   types.StringType,
}

var pgpModelType = types.ObjectType{AttrTypes: pgpModelAttributeTypes}

type kmsModel struct {
	CreationDate      timetypes.RFC3339 `tfsdk:"creation_date"`
	Arn               types.String      `tfsdk:"arn"`
	Role              types.String      `tfsdk:"role"`
	EncryptionContext types.Map         `tfsdk:"encryption_context"`
	AwsProfile        types.String      `tfsdk:"aws_profile"`
}

var kmsModelAttributeTypes = map[string]attr.Type{
	"creation_date":      timetypes.RFC3339Type{},
	"arn":                types.StringType,
	"role":               types.StringType,
	"encryption_context": types.MapType{ElemType: types.StringType},
	"aws_profile":        types.StringType,
}

var kmsModelType = types.ObjectType{AttrTypes: kmsModelAttributeTypes}

type gcpKmsModel struct {
	CreationDate timetypes.RFC3339 `tfsdk:"creation_date"`
	ResourceId   types.String      `tfsdk:"resource_id"`
}

var gcpKmsModelAttributeTypes = map[string]attr.Type{
	"creation_date": timetypes.RFC3339Type{},
	"resource_id":   types.StringType,
}

var gcpKmsModelType = types.ObjectType{AttrTypes: gcpKmsModelAttributeTypes}

type azureKVModel struct {
	CreationDate timetypes.RFC3339 `tfsdk:"creation_date"`
	VaultUri     types.String      `tfsdk:"vault_uri"`
	KeyName      types.String      `tfsdk:"key_name"`
	KeyVersion   types.String      `tfsdk:"key_version"`
}

var azureKVModelAttributeTypes = map[string]attr.Type{
	"creation_date": timetypes.RFC3339Type{},
	"vault_uri":     types.StringType,
	"key_name":      types.StringType,
	"key_version":   types.StringType,
}

var azureKVModelType = types.ObjectType{AttrTypes: azureKVModelAttributeTypes}

type hcVaultModel struct {
	CreationDate timetypes.RFC3339 `tfsdk:"creation_date"`
	VaultAddress types.String      `tfsdk:"vault_address"`
	EnginePath   types.String      `tfsdk:"engine_path"`
	KeyName      types.String      `tfsdk:"key_name"`
}

var hcVaultModelAttributeTypes = map[string]attr.Type{
	"creation_date": timetypes.RFC3339Type{},
	"vault_address": types.StringType,
	"engine_path":   types.StringType,
	"key_name":      types.StringType,
}

var hcVaultModelType = types.ObjectType{AttrTypes: hcVaultModelAttributeTypes}

type keyModel struct {
	Age     types.Object `tfsdk:"age"`
	Pgp     types.Object `tfsdk:"pgp"`
	Kms     types.Object `tfsdk:"kms"`
	GcpKms  types.Object `tfsdk:"gcp_kms"`
	AzureKV types.Object `tfsdk:"azure_kv"`
	HCVault types.Object `tfsdk:"hc_vault"`
}

var keyModelAttributeTypes = map[string]attr.Type{
	"age":      types.ObjectType{AttrTypes: ageModelAttributeTypes},
	"pgp":      types.ObjectType{AttrTypes: pgpModelAttributeTypes},
	"kms":      types.ObjectType{AttrTypes: kmsModelAttributeTypes},
	"gcp_kms":  types.ObjectType{AttrTypes: gcpKmsModelAttributeTypes},
	"azure_kv": types.ObjectType{AttrTypes: azureKVModelAttributeTypes},
	"hc_vault": types.ObjectType{AttrTypes: hcVaultModelAttributeTypes},
}

var keyModelType = types.ObjectType{AttrTypes: keyModelAttributeTypes}

type keyGroupModel struct {
	Keys types.Set `tfsdk:"keys"`
}

var keyGroupModelAttributeTypes = map[string]attr.Type{
	"keys": types.SetType{ElemType: types.ObjectType{AttrTypes: keyModelAttributeTypes}},
}

var keyGroupModelType = types.ObjectType{AttrTypes: keyGroupModelAttributeTypes}

func (r *sopsEncryptResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Encrypt an unencrypted content or file using SOPS.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				MarkdownDescription: "The id of the resource. This will always be set to `-`",
				Computed:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"format": schema.StringAttribute{
				MarkdownDescription: "The format of both the unencrypted and encrypted content. " +
					"Valid values are `json`, `yaml`, `ini`, `dotenv` and `binary`. " +
					"You should specify either `format`, or both `unencrypted_format` and `encrypted_format`. " +
					"When none of these are set, the format will be inferred from `source` and `filename`. " +
					"Defaults to `binary`.",
				Optional: true,
				Validators: []validator.String{
					stringvalidator.OneOf("json", "yaml", "ini", "dotenv", "binary"),
				},
			},
			"unencrypted_format": schema.StringAttribute{
				MarkdownDescription: "The format of the unencrypted content. " +
					"Valid values are `json`, `yaml`, `ini`, `dotenv` and `binary`. " +
					"Conflicts with `format`. " +
					"`unencrypted_format` and `encrypted_format` must be set together. " +
					"This allows you to specify different formats for the unencrypted and encrypted content. " +
					"If you want to use the same format for both the unencrypted and encrypted content, " +
					"you can use `format` instead.",
				Optional: true,
				Computed: true,
				Validators: []validator.String{
					stringvalidator.OneOf("json", "yaml", "ini", "dotenv", "binary"),
				},
			},
			"encrypted_format": schema.StringAttribute{
				MarkdownDescription: "The format of the encrypted content. " +
					"Valid values are `json`, `yaml`, `ini`, `dotenv` and `binary`. " +
					"See `unencrypted_format` for more information.",
				Optional: true,
				Computed: true,
				Validators: []validator.String{
					stringvalidator.OneOf("json", "yaml", "ini", "dotenv", "binary"),
				},
			},
			"source": schema.StringAttribute{
				MarkdownDescription: "Path to the file containing the unencrypted content that will be encrypted. " +
					"Exactly one of `source`, `unencrypted_content` and `unencrypted_content_base64` must be set.",
				Optional: true,
			},
			"unencrypted_content": schema.StringAttribute{
				MarkdownDescription: "The unencrypted content. " +
					"Exactly one of `source`, `unencrypted_content` and `unencrypted_content_base64` must be set.",
				Optional:  true,
				Sensitive: true,
			},
			"unencrypted_content_base64": schema.StringAttribute{
				MarkdownDescription: "The unencrypted content in base64. " +
					"Exactly one of `source`, `unencrypted_content` and `unencrypted_content_base64` must be set.",
				Optional:  true,
				Sensitive: true,
			},
			"filename": schema.StringAttribute{
				MarkdownDescription: "Path to the file that will be written with the encrypted content. " +
					"An error will be returned if parent directories do not exist. " +
					"If the file already exists, it will be loaded and re-encrypted with the metadata preserved. " +
					"Otherwise, a new file will be created with the specified permissions.",
				Optional: true,
			},
			"file_permission": schema.StringAttribute{
				MarkdownDescription: "Permissions to set for the output file (before umask), " +
					"expressed as string in [numeric notation](https://en.wikipedia.org/wiki/File-system_permissions#Numeric_notation). " +
					"Default value is \"0700\"",
				Optional: true,
				Computed: true,
				Default:  stringdefault.StaticString("0700"),
				Validators: []validator.String{
					stringvalidator.RegexMatches(regexp.MustCompile(`^0?[0-7]{3}$`), "The file permission must be a valid octal number."),
					stringvalidator.AlsoRequires(path.MatchRoot("filename")),
				},
			},
			"encrypted_content": schema.StringAttribute{
				MarkdownDescription: "The encrypted content, expected to be UTF-8 encoded. " +
					"Invalid UTF-8 sequences will be replaced with the Unicode replacement character.",
				Computed: true,
			},
			"encrypted_content_base64": schema.StringAttribute{
				MarkdownDescription: "The base64 encoded encrypted content. " +
					"Use this when dealing with binary data.",
				Computed: true,
			},
			"unencrypted_suffix": schema.StringAttribute{
				MarkdownDescription: "All values ending with this suffix will be left unencrypted. " +
					"At most one of `unencrypted_suffix`, `encrypted_suffix`, `unencrypted_regex` and `encrypted_regex` can be set. " +
					fmt.Sprintf("Defaults to `%s` so as to be compatible with SOPS. ", sops.DefaultUnencryptedSuffix),
				Computed: true,
				Optional: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"encrypted_suffix": schema.StringAttribute{
				MarkdownDescription: "Only values ending with this suffix will be encrypted. " +
					"At most one of `unencrypted_suffix`, `encrypted_suffix`, `unencrypted_regex` and `encrypted_regex` can be set.",
				Computed: true,
				Optional: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"unencrypted_regex": schema.StringAttribute{
				MarkdownDescription: "All values matching this regex will be left unencrypted. " +
					"At most one of `unencrypted_suffix`, `encrypted_suffix`, `unencrypted_regex` and `encrypted_regex` can be set.",
				Computed: true,
				Optional: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"encrypted_regex": schema.StringAttribute{
				MarkdownDescription: "Only values matching this regex will be encrypted. " +
					"At most one of `unencrypted_suffix`, `encrypted_suffix`, `unencrypted_regex` and `encrypted_regex` can be set.",
				Computed: true,
				Optional: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"key_groups": schema.SetNestedAttribute{
				MarkdownDescription: "The key groups for encryption. " +
					"At least one key group must be specified. " +
					"SOPS uses Shamir's Secret Sharing algorithm to split the data key, " +
					"such that each key group has its fragment of the data key. " +
					"Every key in a key group can be used to decrypt the fragment of the data key. " +
					"`shamir_threshold` specifies the number of key groups required to decrypt the data key. ",
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"keys": schema.SetNestedAttribute{
							MarkdownDescription: "The keys in the key group. " +
								"At least one key must be specified. " +
								"Every key in a key group can be used to decrypt the fragment of the data key. " +
								"If there is only one key group, then every key in the key group can be used to decrypt the encrypted content.",
							NestedObject: schema.NestedAttributeObject{
								Attributes: map[string]schema.Attribute{
									"age": schema.SingleNestedAttribute{
										MarkdownDescription: "Encrypting using [age](https://age-encryption.org/).",
										Attributes: map[string]schema.Attribute{
											"recipient": schema.StringAttribute{
												MarkdownDescription: "The Bench32-encoded age public key used to Encrypt.",
												Required:            true,
											},
										},
										Optional: true,
									},
									"pgp": schema.SingleNestedAttribute{
										MarkdownDescription: "Encrypting using PGP.",
										Attributes: map[string]schema.Attribute{
											"creation_date": schema.StringAttribute{
												CustomType: timetypes.RFC3339Type{},
												MarkdownDescription: "The creation date of the PGP key. " +
													"Used for key rotation.",
												Optional: true,
												Computed: true,
											},
											"fingerprint": schema.StringAttribute{
												MarkdownDescription: "The fingerprint of the PGP key.",
												Required:            true,
											},
										},
										Optional: true,
									},
									"kms": schema.SingleNestedAttribute{
										MarkdownDescription: "Encrypting using [AWS KMS](https://docs.aws.amazon.com/kms/latest/developerguide/overview.html).",
										Attributes: map[string]schema.Attribute{
											"creation_date": schema.StringAttribute{
												CustomType: timetypes.RFC3339Type{},
												MarkdownDescription: "The creation date of the KMS key. " +
													"Used for key rotation.",
												Optional: true,
												Computed: true,
											},
											"arn": schema.StringAttribute{
												MarkdownDescription: "The ARN associated with the AWS KMS key.",
												Required:            true,
											},
											"role": schema.StringAttribute{
												MarkdownDescription: "The role ARN to assume a role through AWS STS.",
												Optional:            true,
											},
											"encryption_context": schema.MapAttribute{
												MarkdownDescription: "Additional context about the data key. " +
													"See https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html#encrypt_context.",
												ElementType: types.StringType,
												Optional:    true,
											},
											"aws_profile": schema.StringAttribute{
												MarkdownDescription: "The profile to use for loading configuration and credentials. " +
													"See https://aws.github.io/aws-sdk-go-v2/docs/configuring-sdk/#specifying-profiles.",
												Optional: true,
											},
										},
										Optional: true,
									},
									"gcp_kms": schema.SingleNestedAttribute{
										MarkdownDescription: "Encrypting using [Google Cloud KMS](https://cloud.google.com/kms).",
										Attributes: map[string]schema.Attribute{
											"creation_date": schema.StringAttribute{
												CustomType: timetypes.RFC3339Type{},
												MarkdownDescription: "The creation date of the KMS key. " +
													"Used for key rotation.",
												Optional: true,
												Computed: true,
											},
											"resource_id": schema.StringAttribute{
												MarkdownDescription: "The resource ID used to refer to the GCP KMS key. " +
													"It can be retrieved using the `gcloud` command.",
												Required: true,
											},
										},
										Optional: true,
									},
									"azure_kv": schema.SingleNestedAttribute{
										MarkdownDescription: "Encrypting using [Azure Key Vault](https://azure.microsoft.com/en-us/services/key-vault/).",
										Attributes: map[string]schema.Attribute{
											"creation_date": schema.StringAttribute{
												CustomType: timetypes.RFC3339Type{},
												MarkdownDescription: "The creation date of the Key Vault key. " +
													"Used for key rotation.",
												Optional: true,
												Computed: true,
											},
											"vault_uri": schema.StringAttribute{
												MarkdownDescription: "The URI of the Azure Key Vault. " +
													"Example: `https://myvault.vault.azure.net/`.",
												Required: true,
											},
											"key_name": schema.StringAttribute{
												MarkdownDescription: "The name of the Azure Key Vault key.",
												Required:            true,
											},
											"key_version": schema.StringAttribute{
												MarkdownDescription: "The version of the Azure Key Vault key. " +
													"Can be empty.",
												Optional: true,
											},
										},
										Optional: true,
									},
									"hc_vault": schema.SingleNestedAttribute{
										MarkdownDescription: "Encrypting using [HashiCorp Vault](https://www.vaultproject.io/).",
										Attributes: map[string]schema.Attribute{
											"creation_date": schema.StringAttribute{
												CustomType: timetypes.RFC3339Type{},
												MarkdownDescription: "The creation date of the Vault key. " +
													"Used for key rotation.",
												Optional: true,
												Computed: true,
											},
											"vault_address": schema.StringAttribute{
												MarkdownDescription: "The address of the Vault server.",
												Required:            true,
											},
											"engine_path": schema.StringAttribute{
												MarkdownDescription: "The path to the Vault Transit Secret engine relative to the address of the Vault server.",
												Required:            true,
											},
											"key_name": schema.StringAttribute{
												MarkdownDescription: "The name of the Vault key.",
												Required:            true,
											},
										},
										Optional: true,
									},
								},
							},
							Validators: []validator.Set{
								setvalidator.SizeAtLeast(1),
							},
							Required: true,
						},
					},
				},
				Optional: true,
				Computed: true,
				Validators: []validator.Set{
					setvalidator.SizeAtLeast(1),
				},
				PlanModifiers: []planmodifier.Set{
					setplanmodifier.RequiresReplace(),
				},
			},
			"shamir_threshold": schema.Int64Attribute{
				MarkdownDescription: "The threshold for the Shamir secret sharing algorithm. " +
					"Defaults to the number of key groups.",
				Optional: true,
				Computed: true,
				Validators: []validator.Int64{
					int64validator.AlsoRequires(path.MatchRoot("key_groups")),
				},
				PlanModifiers: []planmodifier.Int64{
					int64planmodifier.RequiresReplace(),
				},
			},
			"config_file": schema.StringAttribute{
				MarkdownDescription: "The path to the SOPS configuration file. " +
					"Overrides the `config_file` in the provider configuration. " +
					"If `key_groups` is not set and a valid `config_file` is found, " +
					"SOPS provider will load the creation rules from the configuration file so as to " +
					"determine the `key_groups` and `shamir_threshold` options. " +
					"The file path of `pseudo_filename` or `filename` (if `pseudo_filename` is not set) " +
					"relative to the file path of `config_file` will be used to match against the creation rules. " +
					"See [SOPS README](https://github.com/getsops/sops/blob/main/README.rst) for more information.",
				Optional: true,
			},
			"pseudo_filename": schema.StringAttribute{
				MarkdownDescription: "The filename to use for the unencrypted content when it is not a file. " +
					"See `config_file` for more information.",
				Optional: true,
			},
		},
	}
}

func (r *sopsEncryptResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_encrypt"
}

func (r *sopsEncryptResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}

	client, ok := req.ProviderData.(*sopsProviderData)
	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected Data Source Configure Type",
			fmt.Sprintf("Expected *sopsProviderData, got: %T. Please report this issue to the provider developers.", req.ProviderData),
		)
		return
	}
	r.client = client
}

func (r *sopsEncryptResource) ConfigValidators(context.Context) []resource.ConfigValidator {
	return []resource.ConfigValidator{
		resourcevalidator.Conflicting(
			path.MatchRoot("format"),
			path.MatchRoot("unencrypted_format"),
		),
		resourcevalidator.Conflicting(
			path.MatchRoot("format"),
			path.MatchRoot("encrypted_format"),
		),
		resourcevalidator.AtLeastOneOf(
			path.MatchRoot("format"),
			path.MatchRoot("unencrypted_format"),
			path.MatchRoot("source"),
		),
		resourcevalidator.AtLeastOneOf(
			path.MatchRoot("format"),
			path.MatchRoot("encrypted_format"),
			path.MatchRoot("filename"),
		),
		resourcevalidator.ExactlyOneOf(
			path.MatchRoot("source"),
			path.MatchRoot("unencrypted_content"),
			path.MatchRoot("unencrypted_content_base64"),
		),
		resourcevalidator.Conflicting(
			path.MatchRoot("unencrypted_suffix"),
			path.MatchRoot("encrypted_suffix"),
			path.MatchRoot("unencrypted_regex"),
			path.MatchRoot("encrypted_regex"),
		),
		resourcevalidator.Conflicting(
			path.MatchRoot("key_groups"),
			path.MatchRoot("config_file"),
		),
		resourcevalidator.Conflicting(
			path.MatchRoot("key_groups"),
			path.MatchRoot("pseudo_filename"),
		),
	}
}

func (r *sopsEncryptResource) completePlan(ctx context.Context, config, plan, state *sopsEncryptResourceModel, diagnostics *diag.Diagnostics) {
	// Compute the default format for the unencrypted and encrypted content if not set
	if plan.UnencryptedFormat.IsUnknown() && config.UnencryptedFormat.IsNull() {
		if !plan.Format.IsNull() {
			plan.UnencryptedFormat = plan.Format
		} else {
			format := formats.FormatForPath(plan.Source.ValueString())
			plan.UnencryptedFormat = types.StringValue(client.FormatToString[format])
		}
	}
	if plan.EncryptedFormat.IsUnknown() && config.EncryptedFormat.IsNull() {
		if !plan.Format.IsNull() {
			plan.EncryptedFormat = plan.Format
		} else {
			format := formats.FormatForPath(plan.Filename.ValueString())
			plan.EncryptedFormat = types.StringValue(client.FormatToString[format])
		}
	}

	// Compute the crypto rules if not set
	if plan.UnencryptedSuffix.IsUnknown() && config.UnencryptedSuffix.IsNull() {
		plan.UnencryptedSuffix = types.StringNull()
	}
	if plan.EncryptedSuffix.IsUnknown() && config.EncryptedSuffix.IsNull() {
		plan.EncryptedSuffix = types.StringNull()
	}
	if plan.UnencryptedRegex.IsUnknown() && config.UnencryptedRegex.IsNull() {
		plan.UnencryptedRegex = types.StringNull()
	}
	if plan.EncryptedRegex.IsUnknown() && config.EncryptedRegex.IsNull() {
		plan.EncryptedRegex = types.StringNull()
	}
	cryptRulesUnknown := plan.UnencryptedSuffix.IsNull() && plan.EncryptedSuffix.IsNull() &&
		plan.UnencryptedRegex.IsNull() && plan.EncryptedRegex.IsNull()

	// Load the key groups from the configuration file
	if plan.KeyGroups.IsUnknown() && config.KeyGroups.IsNull() {
		var configFile string
		if !plan.ConfigFile.IsNull() {
			configFile = plan.ConfigFile.ValueString()
		} else if r.client.configFile != nil {
			configFile = *r.client.configFile
		} else {
			diagnostics.AddAttributeError(path.Root("key_groups"),
				"Cannot determine encryption settings",
				"Either `key_groups` or `config_file` must be set.")
			return
		}
		var filename string
		var err error
		if !plan.PseudoFilename.IsNull() {
			filename, err = filepath.Abs(plan.PseudoFilename.ValueString())
			if err != nil {
				diagnostics.AddAttributeError(path.Root("pseudo_filename"),
					"Cannot determine absolute path", err.Error())
				return
			}
		} else if !plan.Filename.IsNull() {
			filename, err = filepath.Abs(plan.Filename.ValueString())
			if err != nil {
				diagnostics.AddAttributeError(path.Root("filename"),
					"Cannot determine absolute path", err.Error())
				return
			}
		}
		// TODO: add KMS encryption context
		config, err := sopsconfig.LoadCreationRuleForFile(configFile, filename, make(map[string]*string))
		if err != nil {
			diagnostics.AddError(fmt.Sprintf("Failed to load creation rule from %q", configFile), err.Error())
			return
		}

		if config == nil {
			diagnostics.AddError(fmt.Sprintf("Creation rule not found in %q", configFile),
				"No creation rule in the configuration file")
			return
		}

		if cryptRulesUnknown {
			cryptRulesUnknown = false
			switch {
			case config.UnencryptedSuffix != "":
				plan.UnencryptedSuffix = types.StringValue(config.UnencryptedSuffix)
			case config.EncryptedSuffix != "":
				plan.EncryptedSuffix = types.StringValue(config.EncryptedSuffix)
			case config.UnencryptedRegex != "":
				plan.UnencryptedRegex = types.StringValue(config.UnencryptedRegex)
			case config.EncryptedRegex != "":
				plan.EncryptedRegex = types.StringValue(config.EncryptedRegex)
			default:
				cryptRulesUnknown = true
			}
		}

		keyGroupsOpts := client.RecoverKeyGroupsOpts(client.KeyGroups{
			Groups:          config.KeyGroups,
			ShamirThreshold: config.ShamirThreshold,
		})
		if keyGroupsOpts.ShamirThreshold == 0 {
			keyGroupsOpts.ShamirThreshold = len(keyGroupsOpts.Groups)
		}
		if err := keyGroupsOpts.Validate(); err != nil {
			diagnostics.AddError(
				fmt.Sprintf("Invalid encryption settings in %q", configFile),
				err.Error(),
			)
			return
		}
		plan.ShamirThreshold = types.Int64Value(int64(keyGroupsOpts.ShamirThreshold))

		var diags diag.Diagnostics
		keyGroups := make([]attr.Value, len(keyGroupsOpts.Groups))
		for i, group := range keyGroupsOpts.Groups {
			keys := make([]attr.Value, len(group))
			for j, key := range group {
				keyModel := keyModel{
					Age:     types.ObjectNull(ageModelAttributeTypes),
					Pgp:     types.ObjectNull(pgpModelAttributeTypes),
					Kms:     types.ObjectNull(kmsModelAttributeTypes),
					GcpKms:  types.ObjectNull(gcpKmsModelAttributeTypes),
					AzureKV: types.ObjectNull(azureKVModelAttributeTypes),
					HCVault: types.ObjectNull(hcVaultModelAttributeTypes),
				}
				switch {
				case key.AgeKeyOpts != nil:
					keyModel.Age, diags = types.ObjectValueFrom(ctx, ageModelAttributeTypes, ageModel{
						Recipient: types.StringValue(key.AgeKeyOpts.Recipient),
					})
				case key.PgpKeyOpts != nil:
					keyModel.Pgp, diags = types.ObjectValueFrom(ctx, pgpModelAttributeTypes, pgpModel{
						CreationDate: timetypes.NewRFC3339Unknown(),
						Fingerprint:  types.StringValue(key.PgpKeyOpts.Fingerprint),
					})
				case key.KmsKeyOpts != nil:
					encryptionContext := make(map[string]attr.Value)
					for k, v := range key.KmsKeyOpts.EncryptionContext {
						encryptionContext[k] = types.StringPointerValue(v)
					}
					var encryptionContextAttribute types.Map
					encryptionContextAttribute, diags = types.MapValue(types.StringType, encryptionContext)
					diagnostics.Append(diags...)
					if diagnostics.HasError() {
						return
					}

					keyModel.Kms, diags = types.ObjectValueFrom(ctx, kmsModelAttributeTypes, kmsModel{
						CreationDate:      timetypes.NewRFC3339Unknown(),
						Arn:               types.StringValue(key.KmsKeyOpts.Arn),
						Role:              types.StringValue(key.KmsKeyOpts.Role),
						EncryptionContext: encryptionContextAttribute,
						AwsProfile:        types.StringValue(key.KmsKeyOpts.AwsProfile),
					})
				case key.GcpKmsKeyOpts != nil:
					keyModel.GcpKms, diags = types.ObjectValueFrom(ctx, gcpKmsModelAttributeTypes, gcpKmsModel{
						CreationDate: timetypes.NewRFC3339Unknown(),
						ResourceId:   types.StringValue(key.GcpKmsKeyOpts.ResourceID),
					})
				case key.AzureKVKeyOpts != nil:
					keyModel.AzureKV, diags = types.ObjectValueFrom(ctx, azureKVModelAttributeTypes, azureKVModel{
						CreationDate: timetypes.NewRFC3339Unknown(),
						VaultUri:     types.StringValue(key.AzureKVKeyOpts.VaultURI),
						KeyName:      types.StringValue(key.AzureKVKeyOpts.KeyName),
						KeyVersion:   types.StringValue(key.AzureKVKeyOpts.KeyVersion),
					})
				case key.HCVaultKeyOpts != nil:
					keyModel.HCVault, diags = types.ObjectValueFrom(ctx, hcVaultModelAttributeTypes, hcVaultModel{
						CreationDate: timetypes.NewRFC3339Unknown(),
						VaultAddress: types.StringValue(key.HCVaultKeyOpts.VaultAddress),
						EnginePath:   types.StringValue(key.HCVaultKeyOpts.EnginePath),
						KeyName:      types.StringValue(key.HCVaultKeyOpts.KeyName),
					})
				}
				diagnostics.Append(diags...)
				if diagnostics.HasError() {
					return
				}
				keys[j], diags = types.ObjectValueFrom(ctx, keyModelAttributeTypes, keyModel)
				diagnostics.Append(diags...)
				if diagnostics.HasError() {
					return
				}
			}
			var keyGroupModel keyGroupModel
			keyGroupModel.Keys, diags = types.SetValueFrom(ctx, keyModelType, keys)
			diagnostics.Append(diags...)
			if diagnostics.HasError() {
				return
			}

			keyGroups[i], diags = types.ObjectValueFrom(ctx, keyGroupModelAttributeTypes, keyGroupModel)
			diagnostics.Append(diags...)
			if diagnostics.HasError() {
				return
			}
		}

		plan.KeyGroups, diags = types.SetValueFrom(ctx, keyGroupModelType, keyGroups)
		diagnostics.Append(diags...)
		if diagnostics.HasError() {
			return
		}
	}

	// Check whether key groups has changed
	if state != nil {
		stateKeyGroups := make([]keyGroupModel, len(plan.KeyGroups.Elements()))
		diagnostics.Append(state.KeyGroups.ElementsAs(ctx, &stateKeyGroups, false)...)
		if diagnostics.HasError() {
			return
		}
		var diags diag.Diagnostics
		for i := range stateKeyGroups {
			stateKeyGroup := &stateKeyGroups[i]
			stateKeys := make([]keyModel, len(stateKeyGroup.Keys.Elements()))
			diagnostics.Append(stateKeyGroup.Keys.ElementsAs(ctx, &stateKeys, false)...)
			if diagnostics.HasError() {
				return
			}
			for j := range stateKeys {
				stateKey := &stateKeys[j]
				switch {
				case !stateKey.Age.IsNull():
				case !stateKey.Pgp.IsNull():
					var pgpKey pgpModel
					stateKey.Pgp.As(ctx, &pgpKey, basetypes.ObjectAsOptions{})
					pgpKey.CreationDate = timetypes.NewRFC3339Unknown()
					stateKey.Pgp, diags = types.ObjectValueFrom(ctx, pgpModelAttributeTypes, pgpKey)
					diagnostics.Append(diags...)
				case !stateKey.Kms.IsNull():
					var kmsKey kmsModel
					stateKey.Kms.As(ctx, &kmsKey, basetypes.ObjectAsOptions{})
					kmsKey.CreationDate = timetypes.NewRFC3339Unknown()
					stateKey.Kms, diags = types.ObjectValueFrom(ctx, kmsModelAttributeTypes, kmsKey)
					diagnostics.Append(diags...)
				case !stateKey.GcpKms.IsNull():
					var gcpKmsKey gcpKmsModel
					stateKey.GcpKms.As(ctx, &gcpKmsKey, basetypes.ObjectAsOptions{})
					gcpKmsKey.CreationDate = timetypes.NewRFC3339Unknown()
					stateKey.GcpKms, diags = types.ObjectValueFrom(ctx, gcpKmsModelAttributeTypes, gcpKmsKey)
					diagnostics.Append(diags...)
				case !stateKey.AzureKV.IsNull():
					var azureKVKey azureKVModel
					stateKey.AzureKV.As(ctx, &azureKVKey, basetypes.ObjectAsOptions{})
					azureKVKey.CreationDate = timetypes.NewRFC3339Unknown()
					stateKey.AzureKV, diags = types.ObjectValueFrom(ctx, azureKVModelAttributeTypes, azureKVKey)
					diagnostics.Append(diags...)
				case !stateKey.HCVault.IsNull():
					var hcVaultKey hcVaultModel
					stateKey.HCVault.As(ctx, &hcVaultKey, basetypes.ObjectAsOptions{})
					hcVaultKey.CreationDate = timetypes.NewRFC3339Unknown()
					stateKey.HCVault, diags = types.ObjectValueFrom(ctx, hcVaultModelAttributeTypes, hcVaultKey)
					diagnostics.Append(diags...)
				}
				if diagnostics.HasError() {
					return
				}
			}
			stateKeyGroup.Keys, diags = types.SetValueFrom(ctx, keyModelType, stateKeys)
			diagnostics.Append(diags...)
			if diagnostics.HasError() {
				return
			}
		}
		var keyGroups types.Set
		keyGroups, diags = types.SetValueFrom(ctx, keyGroupModelType, stateKeyGroups)
		diagnostics.Append(diags...)
		if diagnostics.HasError() {
			return
		}

		if keyGroups.Equal(plan.KeyGroups) {
			plan.KeyGroups = state.KeyGroups
		}
	}

	if cryptRulesUnknown {
		plan.UnencryptedSuffix = types.StringValue(sops.DefaultUnencryptedSuffix)
	}

	if plan.ShamirThreshold.IsUnknown() && config.ShamirThreshold.IsNull() {
		plan.ShamirThreshold = types.Int64Value(int64(len(plan.KeyGroups.Elements())))
	}

	plan.Id = types.StringValue("-")
}

func (r *sopsEncryptResource) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	if req.Plan.Raw.IsNull() {
		return
	}

	var config, plan sopsEncryptResourceModel
	var state *sopsEncryptResourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if !req.State.Raw.IsNull() {
		state = new(sopsEncryptResourceModel)
		resp.Diagnostics.Append(req.State.Get(ctx, state)...)
	}
	if resp.Diagnostics.HasError() {
		return
	}

	r.completePlan(ctx, &config, &plan, state, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.Plan.Set(ctx, plan)...)
}

func (r *sopsEncryptResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var config, plan sopsEncryptResourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	r.completePlan(ctx, &config, &plan, nil, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	stores := client.NewStores(client.StoreOpts{
		DecryptedFormat: client.StringToFormat[plan.UnencryptedFormat.ValueString()],
		EncryptedFormat: client.StringToFormat[plan.EncryptedFormat.ValueString()],
	})

	// build key group options and filled the creation date if not set
	keyGroups := client.KeyGroups{
		Groups:          make([]sops.KeyGroup, len(plan.KeyGroups.Elements())),
		ShamirThreshold: int(plan.ShamirThreshold.ValueInt64()),
	}
	planKeyGroups := make([]keyGroupModel, len(plan.KeyGroups.Elements()))
	resp.Diagnostics.Append(plan.KeyGroups.ElementsAs(ctx, &planKeyGroups, false)...)
	if resp.Diagnostics.HasError() {
		return
	}
	var diags diag.Diagnostics
	for i := range planKeyGroups {
		planKeyGroup := &planKeyGroups[i]
		keyGroups.Groups[i] = make([]keys.MasterKey, len(planKeyGroup.Keys.Elements()))
		planKeys := make([]keyModel, len(planKeyGroup.Keys.Elements()))
		resp.Diagnostics.Append(planKeyGroup.Keys.ElementsAs(ctx, &planKeys, false)...)
		if resp.Diagnostics.HasError() {
			return
		}
		for j := range planKeys {
			planKey := &planKeys[j]
			var keyOpts client.KeyOpts
			switch {
			case !planKey.Age.IsNull():
				var ageKey ageModel
				resp.Diagnostics.Append(planKey.Age.As(ctx, &ageKey, basetypes.ObjectAsOptions{})...)
				keyOpts.AgeKeyOpts = &client.AgeKeyOpts{
					Recipient: ageKey.Recipient.ValueString(),
				}
			case !planKey.Pgp.IsNull():
				var pgpKey pgpModel
				resp.Diagnostics.Append(planKey.Pgp.As(ctx, &pgpKey, basetypes.ObjectAsOptions{})...)
				var creationDate time.Time
				if pgpKey.CreationDate.IsUnknown() {
					creationDate = time.Now().UTC()
					pgpKey.CreationDate = timetypes.NewRFC3339TimeValue(creationDate)
					planKey.Pgp, diags = types.ObjectValueFrom(ctx, pgpModelAttributeTypes, pgpKey)
					resp.Diagnostics.Append(diags...)
				} else {
					creationDate, diags = pgpKey.CreationDate.ValueRFC3339Time()
					resp.Diagnostics.Append(diags...)
				}
				keyOpts.PgpKeyOpts = &client.PgpKeyOpts{
					CreationDate: creationDate,
					Fingerprint:  pgpKey.Fingerprint.ValueString(),
				}
			case !planKey.Kms.IsNull():
				var kmsKey kmsModel
				resp.Diagnostics.Append(planKey.Kms.As(ctx, &kmsKey, basetypes.ObjectAsOptions{})...)
				var creationDate time.Time
				if kmsKey.CreationDate.IsUnknown() {
					creationDate = time.Now().UTC()
					kmsKey.CreationDate = timetypes.NewRFC3339TimeValue(creationDate)
					planKey.Kms, diags = types.ObjectValueFrom(ctx, kmsModelAttributeTypes, kmsKey)
					resp.Diagnostics.Append(diags...)
				} else {
					creationDate, diags = kmsKey.CreationDate.ValueRFC3339Time()
					resp.Diagnostics.Append(diags...)
				}
				planEncryptionContext := make(map[string]types.String)
				resp.Diagnostics.Append(kmsKey.EncryptionContext.ElementsAs(ctx, &planEncryptionContext, false)...)
				encryptionContext := make(map[string]*string)
				for k, v := range planEncryptionContext {
					if v.IsNull() {
						resp.Diagnostics.AddAttributeError(
							path.Root("key_groups").AtSetValue(plan.KeyGroups.Elements()[i]).AtName("keys").
								AtSetValue(planKeyGroup.Keys.Elements()[j]).AtName("kms").AtName("encryption_context").AtName(k),
							"Encryption context value cannot be null",
							"Please provide a valid string value",
						)
					}
					encryptionContext[k] = v.ValueStringPointer()
				}
				keyOpts.KmsKeyOpts = &client.KmsKeyOpts{
					CreationDate:      creationDate,
					Arn:               kmsKey.Arn.ValueString(),
					Role:              kmsKey.Role.ValueString(),
					EncryptionContext: encryptionContext,
					AwsProfile:        kmsKey.AwsProfile.ValueString(),
				}
			case !planKey.GcpKms.IsNull():
				var gcpKmsKey gcpKmsModel
				resp.Diagnostics.Append(planKey.GcpKms.As(ctx, &gcpKmsKey, basetypes.ObjectAsOptions{})...)
				var creationDate time.Time
				if gcpKmsKey.CreationDate.IsUnknown() {
					creationDate = time.Now().UTC()
					gcpKmsKey.CreationDate = timetypes.NewRFC3339TimeValue(creationDate)
					planKey.GcpKms, diags = types.ObjectValueFrom(ctx, gcpKmsModelAttributeTypes, gcpKmsKey)
					resp.Diagnostics.Append(diags...)
				} else {
					creationDate, diags = gcpKmsKey.CreationDate.ValueRFC3339Time()
					resp.Diagnostics.Append(diags...)
				}
				keyOpts.GcpKmsKeyOpts = &client.GcpKmsKeyOpts{
					CreationDate: creationDate,
					ResourceID:   gcpKmsKey.ResourceId.ValueString(),
				}
			case !planKey.AzureKV.IsNull():
				var azureKVKey azureKVModel
				resp.Diagnostics.Append(planKey.AzureKV.As(ctx, &azureKVKey, basetypes.ObjectAsOptions{})...)
				var creationDate time.Time
				if azureKVKey.CreationDate.IsUnknown() {
					creationDate = time.Now().UTC()
					azureKVKey.CreationDate = timetypes.NewRFC3339TimeValue(creationDate)
					planKey.AzureKV, diags = types.ObjectValueFrom(ctx, azureKVModelAttributeTypes, azureKVKey)
					resp.Diagnostics.Append(diags...)
				} else {
					creationDate, diags = azureKVKey.CreationDate.ValueRFC3339Time()
					resp.Diagnostics.Append(diags...)
				}
				keyOpts.AzureKVKeyOpts = &client.AzureKVKeyOpts{
					CreationDate: creationDate,
					VaultURI:     azureKVKey.VaultUri.ValueString(),
					KeyName:      azureKVKey.KeyName.ValueString(),
					KeyVersion:   azureKVKey.KeyVersion.ValueString(),
				}
			case !planKey.HCVault.IsNull():
				var hcVaultKey hcVaultModel
				resp.Diagnostics.Append(planKey.HCVault.As(ctx, &hcVaultKey, basetypes.ObjectAsOptions{})...)
				var creationDate time.Time
				if hcVaultKey.CreationDate.IsUnknown() {
					creationDate = time.Now().UTC()
					hcVaultKey.CreationDate = timetypes.NewRFC3339TimeValue(creationDate)
					planKey.HCVault, diags = types.ObjectValueFrom(ctx, hcVaultModelAttributeTypes, hcVaultKey)
					resp.Diagnostics.Append(diags...)
				} else {
					creationDate, diags = hcVaultKey.CreationDate.ValueRFC3339Time()
					resp.Diagnostics.Append(diags...)
				}
				keyOpts.HCVaultKeyOpts = &client.HCVaultKeyOpts{
					CreationDate: creationDate,
					VaultAddress: hcVaultKey.VaultAddress.ValueString(),
					EnginePath:   hcVaultKey.EnginePath.ValueString(),
					KeyName:      hcVaultKey.KeyName.ValueString(),
				}
			}
			if resp.Diagnostics.HasError() {
				return
			}
			if err := keyOpts.Validate(); err != nil {
				resp.Diagnostics.AddAttributeError(
					path.Root("key_groups").AtSetValue(plan.KeyGroups.Elements()[i]).AtName("keys").AtSetValue(planKeyGroup.Keys.Elements()[j]),
					"Invalid key",
					err.Error(),
				)
				return
			}
			keyGroups.Groups[i][j] = client.NewKey(&keyOpts)
		}
		planKeyGroup.Keys, diags = types.SetValueFrom(ctx, keyModelType, planKeys)
		resp.Diagnostics.Append(diags...)
		if resp.Diagnostics.HasError() {
			return
		}
	}
	plan.KeyGroups, diags = types.SetValueFrom(ctx, keyGroupModelType, planKeyGroups)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// load the content
	var content []byte
	if !plan.Source.IsNull() {
		var err error
		content, err = os.ReadFile(plan.Source.ValueString())
		if err != nil {
			resp.Diagnostics.AddAttributeError(
				path.Root("source"),
				"Failed to read the file",
				err.Error(),
			)
			return
		}
	} else if !plan.UnencryptedContent.IsNull() {
		content = []byte(plan.UnencryptedContent.ValueString())
	} else {
		var err error
		content, err = base64.StdEncoding.DecodeString(plan.UnencryptedContentBase64.ValueString())
		if err != nil {
			resp.Diagnostics.AddAttributeError(
				path.Root("unencrypted_content_base64"),
				"Failed to decode the base64 string",
				err.Error(),
			)
			return
		}
	}

	result, err := r.client.Encrypt(content, client.EncryptOpts{
		Stores: stores,
		Metadata: sops.Metadata{
			Version:           version.Version,
			UnencryptedSuffix: plan.UnencryptedSuffix.ValueString(),
			EncryptedSuffix:   plan.EncryptedSuffix.ValueString(),
			UnencryptedRegex:  plan.UnencryptedRegex.ValueString(),
			EncryptedRegex:    plan.EncryptedRegex.ValueString(),
			KeyGroups:         keyGroups.Groups,
			ShamirThreshold:   keyGroups.ShamirThreshold,
		},
	})
	if err != nil {
		resp.Diagnostics.AddError(
			"Failed to encrypt the content",
			err.Error(),
		)
		return
	}

	if !plan.Filename.IsNull() {
		plannedFilePermission := plan.FilePermission.ValueString()
		filePermission, err := strconv.ParseUint(plannedFilePermission, 8, 32)
		if err != nil {
			resp.Diagnostics.AddError(
				"Failed to parse the file permission",
				err.Error(),
			)
			return
		}

		if err := os.WriteFile(plan.Filename.ValueString(), result.Content, os.FileMode(filePermission)); err != nil {
			resp.Diagnostics.AddError(
				"Failed to write the encrypted content to the file",
				err.Error(),
			)
			return
		}

	}

	plan.EncryptedContent = types.StringValue(string(result.Content))
	plan.EncryptedContentBase64 = types.StringValue(base64.StdEncoding.EncodeToString(result.Content))
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *sopsEncryptResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state sopsEncryptResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	// TODO: read the file
	resp.Diagnostics.Append(req.State.Set(ctx, &state)...)
}

func (r *sopsEncryptResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var config, plan, state sopsEncryptResourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	r.completePlan(ctx, &config, &plan, &state, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

func (r *sopsEncryptResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	panic("delete")
}
