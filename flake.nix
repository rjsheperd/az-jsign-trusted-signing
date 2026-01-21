{
  description = "Nix Flake for Azure CLI.";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    nixpkgs-python.url = "github:cachix/nixpkgs-python";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, nixpkgs-python, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs { inherit system; };
        python = nixpkgs-python.packages.${system};
        azure-cli-with-extensions = (pkgs.azure-cli.withExtensions [ pkgs.azure-cli-extensions.trustedsigning ]);

        # Create a custom CA bundle that includes the Microsoft cert
        customCaBundle = pkgs.cacert.override {
          extraCertificateFiles = [ ./microsoft_root_ca_2020.pem ];
        };

        # Create a Java truststore from the custom CA bundle
        javaTrustStore = pkgs.runCommand "java-truststore" {
          buildInputs = [ pkgs.jdk21_headless ];
        } ''
          mkdir -p $out

          # Split the CA bundle into individual certificates and import each one
          ${pkgs.jdk21_headless}/bin/keytool -importcert \
            -noprompt \
            -trustcacerts \
            -alias custom-ca-bundle \
            -file ${customCaBundle}/etc/ssl/certs/ca-bundle.crt \
            -keystore $out/truststore.jks \
            -storepass changeit \
            -storetype JKS || true

          # Alternative: Use the awk script to split and import individual certs
          awk 'BEGIN {c=0} /BEGIN CERT/{c++} {print > ("cert" c ".pem")}' ${customCaBundle}/etc/ssl/certs/ca-bundle.crt

          for cert in cert*.pem; do
            if [ -f "$cert" ]; then
              ${pkgs.jdk21_headless}/bin/keytool -importcert \
                -noprompt \
                -trustcacerts \
                -alias "cert-$cert" \
                -file "$cert" \
                -keystore $out/truststore.jks \
                -storepass changeit \
                -storetype JKS || true
            fi
          done
        '';
      in
      {
        devShell = pkgs.mkShell {
          buildInputs = [
            python."3.7"
            azure-cli-with-extensions
            pkgs.jdk21_headless
          ];

          # Set environment variables to use the custom CA bundle
          SSL_CERT_FILE = "${customCaBundle}/etc/ssl/certs/ca-bundle.crt";
          REQUESTS_CA_BUNDLE = "${customCaBundle}/etc/ssl/certs/ca-bundle.crt";
          NIX_SSL_CERT_FILE = "${customCaBundle}/etc/ssl/certs/ca-bundle.crt";

          # Set Java truststore environment variables
          JAVAX_NET_SSL_TRUSTSTORE = "${javaTrustStore}/truststore.jks";
          JAVAX_NET_SSL_TRUSTSTOREPASSWORD = "changeit";
          JAVAX_NET_SSL_TRUSTSTORETYPE = "JKS";

          shellHook = ''
            echo "Custom CA bundle loaded with Microsoft Identity Verification Root CA"
            echo "SSL_CERT_FILE: $SSL_CERT_FILE"
            echo "JAVAX_NET_SSL_TRUSTSTORE: $JAVAX_NET_SSL_TRUSTSTORE"
          '';
        };
      });
}
