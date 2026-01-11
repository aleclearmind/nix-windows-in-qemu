{ pkgs, ... }:
{
  systems."windows-11-25h2" = {
    useEFI = true;
    iso =
      let
        hash = "sha256-uq62yQ3VFkgVS2TEDJ4MFNk6Qn9hGhu0nIB3+i/3M2Q=";
        fileName = "Win11_25H2_EnglishInternational_x64.iso";
      in
      pkgs.stdenv.mkDerivation {
        name = fileName;
        src = ./.;

        outputHashMode = "flat";
        outputHashAlgo = "sha256";
        outputHash = hash;

        buildPhase = ''
          export SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt
          ${pkgs.quickemu}/bin/quickget windows 11
          if test -e windows-11/${fileName}; then
            mv windows-11/${fileName} .
          else
            echo "quickget failed, downloading from archive.org." > /dev/stderr
            echo "This will be slow due to archive.org's bandwidth limits." > /dev/stderr
            echo "Alternatively, you can download the file manually from the browser:" > /dev/stderr
            echo "" > /dev/stderr
            echo "    https://www.microsoft.com/en-us/software-download/windows11" > /dev/stderr
            echo "" > /dev/stderr
            echo "Then do:" > /dev/stderr
            echo "" > /dev/stderr
            echo "    nix-store --add-fixed sha256 ${fileName}" > /dev/stderr
            echo "" > /dev/stderr

            ${pkgs.curl}/bin/curl -L 'https://archive.org/download/win-11-25-h-2-english-international-x-64/${fileName}' > ${fileName}
          fi
        '';

        installPhase = ''
          mv ${fileName} "$out"
        '';

        dontFixup = true;
      };
    packerBootSteps = ''
      boot_steps = [
        ["<enter>", "Boot into CD"],
        # Unfortunately, for some reason, specifying the language and keyboard layout does not work with Winodws 11 25H2.
        # This is a hack to accept the language proposed by the setup.
        # If we want to have a more reliable alternative than using a timeout, we can do the same in e:\windowsPE.bat
        # using AutoHotkey or a similar tool.
        ["<wait60><leftAltOn>n<leftAltOff>", "Accept language and locale"],
        ["<wait1><leftAltOn>n<leftAltOff>", "Accept keyboard layout"],
      ]
    '';
    autounattendXml = {
      imageName = "Windows 11 Pro";
      diskConfiguration = ''
        <DiskConfiguration>
          <Disk wcm:action="add">
            <DiskID>0</DiskID>
            <WillWipeDisk>true</WillWipeDisk>
            <CreatePartitions>
              <!-- Windows RE Tools partition -->
              <CreatePartition wcm:action="add">
                <Order>1</Order>
                <Type>Primary</Type>
                <Size>256</Size>
              </CreatePartition>
              <!-- System partition (ESP) -->
              <CreatePartition wcm:action="add">
                <Order>2</Order>
                <Type>EFI</Type>
                <Size>128</Size>
              </CreatePartition>
              <!-- Microsoft reserved partition (MSR) -->
              <CreatePartition wcm:action="add">
                <Order>3</Order>
                <Type>MSR</Type>
                <Size>128</Size>
              </CreatePartition>
              <!-- Windows partition -->
              <CreatePartition wcm:action="add">
                <Order>4</Order>
                <Type>Primary</Type>
                <Extend>true</Extend>
              </CreatePartition>
            </CreatePartitions>
            <ModifyPartitions>
              <!-- Windows RE Tools partition -->
              <ModifyPartition wcm:action="add">
                <Order>1</Order>
                <PartitionID>1</PartitionID>
                <Label>WINRE</Label>
                <Format>NTFS</Format>
                <TypeID>DE94BBA4-06D1-4D40-A16A-BFD50179D6AC</TypeID>
              </ModifyPartition>
              <!-- System partition (ESP) -->
              <ModifyPartition wcm:action="add">
                <Order>2</Order>
                <PartitionID>2</PartitionID>
                <Label>System</Label>
                <Format>FAT32</Format>
              </ModifyPartition>
              <!-- MSR partition does not need to be modified -->
              <ModifyPartition wcm:action="add">
                <Order>3</Order>
                <PartitionID>3</PartitionID>
              </ModifyPartition>
              <!-- Windows partition -->
                <ModifyPartition wcm:action="add">
                <Order>4</Order>
                <PartitionID>4</PartitionID>
                <Label>Windows</Label>
                <Letter>C</Letter>
                <Format>NTFS</Format>
              </ModifyPartition>
            </ModifyPartitions>
          </Disk>
        </DiskConfiguration>
      '';
      installPartition = 4;
      productKey = ''
        <ProductKey>
          <Key>W269N-WFGWX-YVC9B-4J6C9-T83GX</Key>
          <WillShowUI>Never</WillShowUI>
        </ProductKey>
      '';
      servicesToDisable = [
        "Sense"
        "WdBoot"
        "WdFilter"
        "WdNisDrv"
        "WdNisSvc"
        "WinDefend"
        "webthreatdefsvc"
      ];
    };
  };
}
