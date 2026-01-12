{ pkgs }:
{
  fetchIso =
    {
      fileName,
      hash,
      productId,
      backupUrl,
    }:
    pkgs.stdenv.mkDerivation {
      name = fileName;
      src = ./.;

      outputHashMode = "flat";
      outputHashAlgo = "sha256";
      outputHash = hash;

      buildPhase =
        let
          jq = "${pkgs.jq}/bin/jq";
          curl = ''${pkgs.curl}/bin/curl --disable --silent --fail-with-body --user-agent "Mozilla/5.0 (X11; Linux x86_64; rv:100.0) Gecko/20100101 Firefox/100.0" --proto =https --tlsv1.2 --http1.1'';
          userFriendlyHash = builtins.convertHash {
            hash = hash;
            hashAlgo = "sha256";
            toHashFormat = "base16";
          };
        in
        ''
          (
            set -euo pipefail
            export SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt

            function log() {
              echo "$1" > /dev/stderr
            }

            function fetch_from_ms() {
              log "Attempting to fetch from Microsoft"
              I18N="English International"
              PROFILE="606624d44113"
              SESSION_ID="$(${pkgs.util-linux}/bin/uuidgen)"
              PRODUCT_ID=${builtins.toString productId}

              ${curl} --header "Accept:" -- "https://vlscppe.microsoft.com/tags?org_id=y6jn8c31&SESSION_ID=$SESSION_ID" > /dev/null

              SKU_ID=$(
                ${curl} \
                  "https://www.microsoft.com/software-download-connector/api/getskuinformationbyproductedition?profile=$PROFILE&ProductEditionId=$PRODUCT_ID&SKU=undefined&friendlyFileName=undefined&Locale=en-US&sessionID=$SESSION_ID" | \
                  ${jq} -r '.Skus[] | select(.LocalizedLanguage=="'"$I18N"'" or .Language=="'"$I18N"'").Id'
              )

              log "Response from Microsoft server:"
              log ""

              CDN_URL=$(
                ${curl} \
                  --referer "https://www.microsoft.com/en-us/software-download/windows11" \
                  "https://www.microsoft.com/software-download-connector/api/GetProductDownloadLinksBySku?profile=$PROFILE&productEditionId=undefined&SKU=$SKU_ID&friendlyFileName=undefined&Locale=en-US&sessionID=$SESSION_ID" | \
                  ${jq} | \
                  tee /dev/stderr | \
                  ${jq} -r '.ProductDownloadOptions[0].Uri'
              )

              log ""

              if test "$CDN_URL" == "null"; then
                return 1
              fi

              log "Starting download"

              ${curl} "$CDN_URL" > ${fileName};

              log "Success!"
            }

            if ! fetch_from_ms; then

              log "Fetching from Microsoft, trying fall back URL, which might be slow."
              log "Alternatively, obtain the file with the following sha256sum:"
              log ""
              log "    ${userFriendlyHash}  ${fileName}"
              log ""
              log "Then do and run the command again:"
              log ""
              log "    nix-store --add-fixed sha256 ${fileName}"
              log ""
              log "Now downloading from backup URL:"
              log ""
              log "    ${backupUrl}"
              log ""

              ${curl} -L "${backupUrl}" > ${fileName};

              log "${fileName} successfully fetched from backup URL."
            fi
          )
        '';

      installPhase = ''
        mv ${fileName} "$out"
      '';

      dontFixup = true;
    };
}
