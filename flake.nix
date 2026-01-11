{
  description = "A flake to cook Windows images, unattended, without Internet, without bloat.";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-parts.url = "github:hercules-ci/flake-parts";
  };

  outputs =
    inputs@{
      self,
      nixpkgs,
      flake-parts,
    }:
    flake-parts.lib.mkFlake { inherit inputs; } (
      top@{
        config,
        withSystem,
        moduleWithSystem,
        ...
      }:
      {
        imports = [
        ];
        systems = [
          "x86_64-linux"
        ];
        perSystem =
          {
            config,
            pkgs,
            system,
            ...
          }:
          let
            mkWindowsImage = (import ./mkWindowsImage/entry.nix) { inherit pkgs; };
          in
          {
            _module.args.pkgs = import inputs.nixpkgs {
              inherit system;
              config = {
                allowUnfree = true;
              };
            };

            packages.windows-11-23h2 = mkWindowsImage {
              name = "windows-11-23h2";
              version = "windows-11-23h2";
            };

            packages.windows-11-25h2 = mkWindowsImage {
              name = "windows-11-25h2";
              version = "windows-11-25h2";
            };

            packages.default = self.packages.${pkgs.system}.windows-11-25h2;
          };
      }
    );
}
