{ pkgs }:
{
  # Not the nicest to have it her but...
  virtioIso = pkgs.fetchurl {
    url = "https://fedorapeople.org/groups/virt/virtio-win/direct-downloads/archive-virtio/virtio-win-0.1.285-1/virtio-win-0.1.285.iso";
    sha256 = "sha256-4UzyuUSSw+kl8AcLp/3+3rIEjJHuqcWlr7MCMqOXYzE=";
  };
  windowsVersionName =
    version:
    let
      versionGreaterThanOrEqual = version1: version2: (builtins.compareVersions version1 version2) >= 0;
      versionGTE = versionGreaterThanOrEqual version;
    in
    if versionGTE "10.0.22000" then
      "11"
    else if versionGTE "10" then
      "10"
    else if versionGTE "6.3" then
      "8.1"
    else if versionGTE "6.2" then
      "8"
    else if versionGTE "6.1" then
      "7"
    else if versionGTE "6.0" then
      "vista"
    else if versionGTE "5.1" then
      "xp"
    else if versionGTE "5.0" then
      "2000"
    else if versionGTE "4.90.3000" then
      "me"
    else if versionGTE "4.10.1998" then
      "98"
    else if versionGTE "4.00.950" then
      "95"
    else if versionGTE "3.11" then
      "3.11"
    else
      "";

  extractWith7z =
    {
      name,
      archive,
      paths,
    }:
    pkgs.stdenv.mkDerivation {
      name = name;
      src = null;

      dontUnpack = true;

      nativeBuildInputs = with pkgs; [
        p7zip
      ];

      buildPhase = ''
        function quiet() {
          QUIET_OUTPUT=$(mktemp)
          if ! "$@" >& "$QUIET_OUTPUT"; then
            log "The following command failed: $*"
            cat "$QUIET_OUTPUT"
            rm -f "$QUIET_OUTPUT"
            return 1
          fi

          rm -f "$QUIET_OUTPUT"
          return 0
        }

        quiet 7z x ${archive} ${pkgs.lib.escapeShellArgs paths}
      '';

      installPhase =
        if (builtins.length paths) == 1 then
          "mv ${builtins.elemAt paths 0} $out"
        else
          ''
            mkdir $out
            mv * "$out"
          '';

      dontFixup = true;
    };
  fetchWindowsIso =
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

      nativeBuildInputs = with pkgs; [
        jq
        curl
      ];

      buildPhase =
        let
          curl = ''curl --disable --silent --fail-with-body --user-agent "Mozilla/5.0 (X11; Linux x86_64; rv:100.0) Gecko/20100101 Firefox/100.0" --proto =https --tlsv1.2 --http1.1'';
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
                  jq -r '.Skus[] | select(.LocalizedLanguage=="'"$I18N"'" or .Language=="'"$I18N"'").Id'
              )

              log "Response from Microsoft server:"
              log ""

              CDN_URL=$(
                ${curl} \
                  --referer "https://www.microsoft.com/en-us/software-download/windows11" \
                  "https://www.microsoft.com/software-download-connector/api/GetProductDownloadLinksBySku?profile=$PROFILE&productEditionId=undefined&SKU=$SKU_ID&friendlyFileName=undefined&Locale=en-US&sessionID=$SESSION_ID" | \
                  jq | \
                  tee /dev/stderr | \
                  jq -r '.ProductDownloadOptions[0].Uri'
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
