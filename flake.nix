{
  description = "zone-sequencer-rs — FFI cdylib for logos-blockchain v0.2 zone inscriptions";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/e9f00bd893984bc8ce46c895c3bf7cac95331127";
    nixpkgs-rust.url = "github:NixOS/nixpkgs/bfc1b8a4574108ceef22f02bafcf6611380c100d";
  };

  outputs = { self, nixpkgs, nixpkgs-rust, ... }:
    let
      systems = [ "x86_64-linux" ];
      forAll = f: nixpkgs.lib.genAttrs systems (system: f {
        pkgs = import nixpkgs { inherit system; };
        pkgsRust = import nixpkgs-rust { inherit system; };
      });
    in
    {
      packages = forAll ({ pkgs, pkgsRust }:
        let
          # v0.2 build-time downloads the nix sandbox blocks — provide pinned artifacts
          # (mirrors each repo's own flake). See machines/sneg/docs/logos-v0.2-sequencer-port.md.
          circuits = builtins.fetchTarball {
            url = "https://github.com/logos-blockchain/logos-blockchain/releases/download/0.1.1/logos-blockchain-circuits-v0.4.1-linux-x86_64.tar.gz";
            sha256 = "1xnhl4y2zpxvcgm0xx95v0v6av2amp5isfi0s92cxrjg7dqmp5z8";
          };
          rapidsnarkLib = pkgs.fetchzip {
            url = "https://github.com/logos-blockchain/logos-blockchain-rust-rapidsnark/releases/download/rapidsnark-pic-v0.0.8/rapidsnark-linux-x86_64-pic-v0.0.8.zip";
            hash = "sha256-88+TkECQYCKBN0WbYLRB+qi6TEhbjVfrpCqlSgm0DR8=";
          };
          lbcRoot = builtins.fetchTarball {
            url = "https://github.com/logos-blockchain/logos-blockchain-circuits/releases/download/v0.5.3/logos-blockchain-circuits-v0.5.3-linux-x86_64.tar.gz";
            sha256 = "1mwy3g9dyjvlwykzs62gzf79rrnm20sy7c587nv26c1y9bm71wfv";
          };

          # NOTE: outputHashes are the v0.2 git-dep set, harvested via fakeHash build.
          # Kept in sync with the module flake; regenerate if Cargo.lock changes.
          outputHashes = import ./nix/output-hashes.nix;

          zone_sequencer_rs = pkgsRust.rustPlatform.buildRustPackage {
            pname = "zone-sequencer-rs";
            version = "0.2.0";
            src = ./.;
            cargoLock = { lockFile = ./Cargo.lock; inherit outputHashes; };
            LOGOS_BLOCKCHAIN_CIRCUITS = circuits;
            RAPIDSNARK_LIB_DIR = "${rapidsnarkLib}/lib";
            LBC_ROOT_DIR = "${lbcRoot}";
            nativeBuildInputs = [ pkgsRust.pkg-config pkgsRust.perl ];
            buildInputs = [ pkgsRust.openssl ];
            installPhase = ''
              runHook preInstall
              mkdir -p $out/lib
              find target -name 'libzone_sequencer_rs.so' -path '*/release/*' -exec install -m755 {} $out/lib/ \;
              runHook postInstall
            '';
          };
        in
        {
          inherit zone_sequencer_rs;
          default = zone_sequencer_rs;
        });
    };
}
