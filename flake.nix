{
  description = "A Terraform provider for reading Mozilla sops files";
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-23.11";
  outputs = { self, nixpkgs }:
    let
      lastModifiedDate = self.lastModifiedDate or self.lastModified or "19700101";
      version = builtins.substring 0 8 lastModifiedDate;
      supportedSystems = [ "x86_64-linux" "x86_64-darwin" "aarch64-linux" "aarch64-darwin" ];
      forAllSystems = nixpkgs.lib.genAttrs supportedSystems;
      nixpkgsFor = forAllSystems (system: import nixpkgs { inherit system; });
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
            vendorHash = "sha256-8W1PK4T98iK1N6EB6AVjvr1P9Ja51+kSOmYAEosxrh8=";
          };
        });
      devShells = forAllSystems (system:
        let
          pkgs = nixpkgsFor.${system};
        in
        {
          default = pkgs.mkShell {
            buildInputs = with pkgs; [ go gopls gotools go-tools ];
          };
        });
      defaultPackage = forAllSystems (system: self.packages.${system}.terraform-provider-sops);
    };
}
