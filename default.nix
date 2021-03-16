with import <nixpkgs> {};

llvmPackages_latest.stdenv.mkDerivation {
  name = "rust-http";
}
