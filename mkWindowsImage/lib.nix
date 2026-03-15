{ pkgs }:
{
  # Not the nicest to have it her but...
  virtioIso = pkgs.fetchurl {
    url = "https://fedorapeople.org/groups/virt/virtio-win/direct-downloads/archive-virtio/virtio-win-0.1.285-1/virtio-win-0.1.285.iso";
    sha256 = "sha256-4UzyuUSSw+kl8AcLp/3+3rIEjJHuqcWlr7MCMqOXYzE=";
  };

  mapLines =
    handler: inputList:
    builtins.concatStringsSep "\n" (
      builtins.filter (line: line != "") (builtins.map handler inputList)
    );

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
}
