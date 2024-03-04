{
  description = "A Terraform provider for reading Mozilla sops files";
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-23.11";
  outputs = { self, nixpkgs }:
    let
      lastModifiedDate = self.lastModifiedDate or self.lastModified or "19700101";
      version = builtins.substring 0 8 lastModifiedDate;
      supportedSystems = [ "x86_64-linux" "x86_64-darwin" "aarch64-linux" "aarch64-darwin" ];
      forAllSystems = nixpkgs.lib.genAttrs supportedSystems;
      nixpkgsFor = forAllSystems (system: import nixpkgs { inherit system; config.allowUnfree = true; });
    in
    {
      packages = forAllSystems (system:
        let
          pkgs = nixpkgsFor.${system};
        in
        {
          terraform-provider-sops = pkgs.buildGoModule {
            pname = "terraform-provider-sops";
            inherit version;
            src = ./.;
            doCheck = false;
            vendorHash = "sha256-dpxGEuR+QkA1iqHsHNAr2Jcc1WYodQrECoxvjhrRrk0=";
          };
        });
      devShells = forAllSystems (system:
        let
          pkgs = nixpkgsFor.${system};
          my-terraform = pkgs.terraform.withPlugins (ps: with ps; [ random ]);
        in
        {
          default = pkgs.mkShell {
            buildInputs = with pkgs; [ go gopls gotools go-tools gox delve sops tfplugindocs terraform watchexec ];
            shellHook = ''
              cat <<EOF > local.tfrc
              provider_installation {
                dev_overrides {
                  "sunziping2016/sops" = "$(pwd)"
                }
                filesystem_mirror {
                  path    = "$(pwd)/binaries"
                  include = [ "*/*" ]
                }
                filesystem_mirror {
                  path    = "${my-terraform}/libexec/terraform-providers"
                  include = [ "*/*" ]
                }
              }
              EOF

              export TF_CLI_CONFIG_FILE="$(pwd)/local.tfrc"
            '';
            hardeningDisable = [ "fortify" ];
          };
        });
      defaultPackage = forAllSystems (system: self.packages.${system}.terraform-provider-sops);
    };
}
