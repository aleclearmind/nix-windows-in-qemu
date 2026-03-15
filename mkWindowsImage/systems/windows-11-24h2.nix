{
  pkgs,
  common,
  userConfiguration,
  ...
}:
let
  windows11Post24h2 = buildNumber: iso: {
    operatingSystem = {
      name = "windows";
      version = "10.0.${builtins.toString buildNumber}";
    };
    vm.useEFI = true;

    installation = {
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
      ];
      autounattendXml = {
        imageName = "Windows 11 Enterprise Evaluation";
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
            <!-- If you *do* set a key, ensure it's for the right platform: -->
            <!-- otherwise you will get the dreaded "No images are available" -->
            <!-- which actually means "No images are available for this ProductKey! -->
            <!-- <Key>SET_KEY_HERE</Key> -->
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
  };
in
{
  systems."windows-11-24h2" = windows11Post24h2 26100 (
    pkgs.fetchurl {
      url = "https://software-static.download.prss.microsoft.com/dbazure/888969d5-f34g-4e03-ac9d-1f9786c66749/26100.1742.240906-0331.ge_release_svc_refresh_CLIENTENTERPRISEEVAL_OEMRET_x64FRE_en-us.iso";
      sha256 = "sha256-dVqQ1D6CanS54ZMqNHiLiY4CgnJDm3d+VZPe6NU2Iq4=";
    }
  );
  systems."windows-11-25h2" = windows11Post24h2 26200 (
    pkgs.fetchurl {
      url = "https://software-static.download.prss.microsoft.com/dbazure/888969d5-f34g-4e03-ac9d-1f9786c66749/26200.6584.250915-1905.25h2_ge_release_svc_refresh_CLIENTENTERPRISEEVAL_OEMRET_x64FRE_en-us.iso";
      sha256 = "sha256-phreq4le9aTbQ24KcBHJKi/xe7A1f1ixO7xAYuU157k=";
    }
  );
}
