{
  inputs.nixpkgs.url = "github:nixos/nixpkgs?ref=nixos-unstable";
  outputs =
    { self, nixpkgs }:
    let
      pkgs = nixpkgs.legacyPackages.x86_64-linux;
    in
    {
      packages.x86_64-linux.default =
        pkgs.runCommand "website"
          {
            buildInputs = [ pkgs.hugo ];
            src = pkgs.lib.cleanSource ./.;
            preferLocalBuild = true;
          }
          ''
            TEMP_DIR=$(mktemp -d)
            cp -r $src/* $TEMP_DIR
            cd $TEMP_DIR
            hugo --destination $out
          '';
      devShells.x86_64-linux.default = pkgs.mkShell {
        packages = with pkgs; [ hugo ];
      };
    };
}
