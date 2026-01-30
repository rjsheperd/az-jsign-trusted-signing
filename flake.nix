{
  description = "Azure Trusted Signing with JSign";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs { inherit system; };

        # JSign JAR derivation - cached separately
        jsign = pkgs.fetchurl {
          url = "https://github.com/ebourg/jsign/releases/download/7.4/jsign-7.4.jar";
          sha256 = "2abf2ade9ea322acc2d60c24794eadc465ff9380938fca4c932d09e0b25f1c28";
        };

        # Custom CA bundle with Microsoft cert - cached separately
        customCaBundle = pkgs.cacert.override {
          extraCertificateFiles = [ ./microsoft_root_ca_2020.pem ];
        };

        # Java truststore derivation - cached separately
        javaTrustStore = pkgs.runCommand "java-truststore" {
          nativeBuildInputs = [ pkgs.jdk21_headless ];
        } ''
          mkdir -p $out

          # Split the CA bundle into individual certificates and import each one
          awk 'BEGIN {c=0} /BEGIN CERT/{c++} {print > ("cert" c ".pem")}' \
            ${customCaBundle}/etc/ssl/certs/ca-bundle.crt

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

        # Azure CLI with trusted signing extension
        azureCli = pkgs.azure-cli.withExtensions [
          pkgs.azure-cli-extensions.trustedsigning
        ];

        # Wrapper script that sets up environment and copies JSign
        signingEnvSetup = pkgs.writeShellScriptBin "setup-signing-env" ''
          # Copy JSign JAR to current directory if not present
          if [ ! -f "jsign-7.4.jar" ]; then
            cp ${jsign} jsign-7.4.jar
            echo "Copied JSign JAR to current directory"
          fi
        '';

      in
      {
        # Export individual packages for better caching
        packages = {
          inherit jsign customCaBundle javaTrustStore azureCli;
          default = signingEnvSetup;
        };

        devShells.default = pkgs.mkShell {
          buildInputs = [
            azureCli
            pkgs.jdk21_headless
            pkgs.unzip
            pkgs.zip
            signingEnvSetup
          ];

          # Set environment variables for custom CA bundle
          SSL_CERT_FILE = "${customCaBundle}/etc/ssl/certs/ca-bundle.crt";
          REQUESTS_CA_BUNDLE = "${customCaBundle}/etc/ssl/certs/ca-bundle.crt";
          NIX_SSL_CERT_FILE = "${customCaBundle}/etc/ssl/certs/ca-bundle.crt";

          # Set Java truststore environment variables
          JAVAX_NET_SSL_TRUSTSTORE = "${javaTrustStore}/truststore.jks";
          JAVAX_NET_SSL_TRUSTSTOREPASSWORD = "changeit";
          JAVAX_NET_SSL_TRUSTSTORETYPE = "JKS";

          # Make JSign available
          JSIGN_JAR = "${jsign}";

          shellHook = ''
            # Copy JSign JAR to current directory for the signing script
            if [ ! -f "jsign-7.4.jar" ]; then
              cp ${jsign} jsign-7.4.jar
            fi

            echo "Azure Trusted Signing environment ready"
            echo "  JSign: ${jsign}"
            echo "  CA Bundle: ${customCaBundle}"
            echo "  Java Truststore: ${javaTrustStore}"
          '';
        };
      });
}
