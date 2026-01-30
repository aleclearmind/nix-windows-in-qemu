{ pkgs, userConfiguration, ... }:
{
  systems."windows-11-23h2" = {
    operatingSystem = {
      name = "windows";
      version = "10.0.22631";
    };

    installation = {
      iso = pkgs.fetchurl {
        url = "https://software-static.download.prss.microsoft.com/dbazure/888969d5-f34g-4e03-ac9d-1f9786c66749/22631.2428.231001-0608.23H2_NI_RELEASE_SVC_REFRESH_CLIENTENTERPRISEEVAL_OEMRET_x64FRE_en-us.iso";
        sha256 = "sha256-yNvJa2HQTIsB+vbOB5T98zllx7NQ6qPrHmaXAZkClFw=";
      };
      autounattendXml = {
        imageName = "Windows 11 Enterprise Evaluation";
        diskConfiguration = ''
          <DiskConfiguration>
            <Disk wcm:action="add">
              <CreatePartitions>
                <CreatePartition wcm:action="add">
                  <Order>1</Order>
                  <Type>Primary</Type>
                  <Extend>true</Extend>
                </CreatePartition>
              </CreatePartitions>
              <ModifyPartitions>
                <ModifyPartition wcm:action="add">
                  <Extend>false</Extend>
                  <Format>NTFS</Format>
                  <Letter>C</Letter>
                  <Order>1</Order>
                  <PartitionID>1</PartitionID>
                  <Label>System</Label>
                </ModifyPartition>
              </ModifyPartitions>
              <DiskID>0</DiskID>
              <WillWipeDisk>true</WillWipeDisk>
            </Disk>
            <WillShowUI>OnError</WillShowUI>
          </DiskConfiguration>
        '';
        installPartition = 1;
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
}
