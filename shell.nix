let 
   pkgs = import (fetchTarball("channel:nixpkgs-unstable")) {};
in pkgs.mkShell {
   buildInputs = [ pkgs.cargo pkgs.rustc pkgs.rustfmt pkgs.wireshark ];
   RUST_SRC_PATH = "${pkgs.rust.packages.stable.rustPlatform.rustLibSrc}";
}
