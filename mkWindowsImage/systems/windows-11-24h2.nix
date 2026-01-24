{
  pkgs,
  fetchIso,
  userConfiguration,
  ...
}:
let
  windows11Post24h2 = buildNumber: iso: {
    operatingSystem = {
      name = "windows";
      version = "10.0.${builtins.toString buildNumber}";
    };
    useEFI = true;
    iso = iso;
    commands = [
      {
        type = "wait-for";
        text = "Press any key to boot from CD or DVD..";
      }
      {
        description = "Confirm booting from CD";
        type = "vncdo";
        arguments = "key enter";
      }
      {
        type = "wait-for";
        text = "Select language settings";
      }
      {
        description = "Accept language and locale";
        type = "vncdo";
        arguments = "key alt-n";
      }
      {
        type = "wait-for";
        text = "Select keyboard settings";
      }
      {
        description = "Accept keyboard layout";
        type = "vncdo";
        arguments = "key alt-n";
      }
    ];
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
        "WSearch"
      ]
      ++ (pkgs.lib.optionals userConfiguration.disableWindowsDefender [
        "Sense"
        "WdBoot"
        "WdFilter"
        "WdNisDrv"
        "WdNisSvc"
        "WinDefend"
        "webthreatdefsvc"
      ]);
    };
  };
in
{
  systems."windows-11-24h2" = windows11Post24h2 26100 (fetchIso {
    fileName = "Win11_24H2_EnglishInternational_x64.iso";
    hash = "sha256-1aTJfD6DXEOxuaMZMzJ8ABdmzjFGCLqRLy//yHYEQwk=";
    productId = 3113;
    backupUrl = "https://archive.org/download/Win11_24H2_EnglishInternational_x64/Win11_24H2_EnglishInternational_x64.iso";
  });
  systems."windows-11-25h2" = windows11Post24h2 26200 (fetchIso {
    fileName = "Win11_25H2_EnglishInternational_x64.iso";
    hash = "sha256-uq62yQ3VFkgVS2TEDJ4MFNk6Qn9hGhu0nIB3+i/3M2Q=";
    productId = 3262;
    backupUrl = "https://archive.org/download/win-11-25-h-2-english-international-x-64/Win11_25H2_EnglishInternational_x64.iso";
  });
}
