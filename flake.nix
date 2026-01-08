{
  description = "A flake to cook Windows images, unattended, without Internet, without bloat.";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-parts.url = "github:hercules-ci/flake-parts";
  };

  outputs =
    inputs@{
      self,
      nixpkgs,
      flake-parts,
    }:
    flake-parts.lib.mkFlake { inherit inputs; } (
      top@{
        config,
        withSystem,
        moduleWithSystem,
        ...
      }:
      {
        imports = [
        ];
        systems = [
          "x86_64-linux"
        ];
        perSystem =
          {
            config,
            pkgs,
            system,
            ...
          }:
          let
            typeSafeFunction =
              { options, implementation }:
              # Return a function that accepts some arguments
              arguments:
              # and invokes the implementation
              implementation
                # Passing as arguments the result of evaluating the module
                (pkgs.lib.evalModules {
                  modules = [
                    (
                      { ... }:
                      {
                        options = options;
                        config = arguments;
                      }
                    )
                  ];
                }).config;
            mkWindowsImage = typeSafeFunction {
              options = with pkgs.lib; {
                name = mkOption {
                  type = types.str;
                  example = "windows";
                  description = "Name for the image.";
                };

                version = mkOption {
                  type = types.enum [ "windows-11-23h2" ];
                  example = "windows-11-23h2";
                  description = "The Windows version identifier (e.g., windows-11-23h2).";
                };

                cpus = mkOption {
                  type = types.int;
                  default = 4;
                  description = "Number of CPUs to assign to the VM.";
                };

                diskSize = mkOption {
                  type = types.int;
                  default = 61440;
                  description = "Virtual disk size for the VM in MB.";
                };

                memory = mkOption {
                  type = types.int;
                  default = 4096;
                  description = "Memory for the VM in MB.";
                };

                disableWindowsUpdates = mkOption {
                  type = types.bool;
                  default = true;
                  description = "Disable Windows Update.";
                };

                disableWindowsDefender = mkOption {
                  type = types.bool;
                  default = true;
                  description = "Disable Windows Defender.";
                };

                zeroOutFreeSpace = mkOption {
                  type = types.bool;
                  default = true;
                  description = "Zero out unused disk space to reduce the size of the final image.";
                };

                debloat = mkOption {
                  type = types.bool;
                  default = true;
                  description = "Debloat using Raphire/Win11Debloat.";
                };

                timeZone = mkOption {
                  type = types.str;
                  default = "W. Europe Standard Time";
                  example = "W. Europe Standard Time";
                  description = "The name of the time zone.";
                };

                computerName = mkOption {
                  type = types.str;
                  default = "pc";
                  example = "pc";
                  description = "The name of the computer.";
                };

                username = mkOption {
                  type = types.str;
                  default = "user";
                  example = "user";
                  description = "The local administrator username to create.";
                };

                password = mkOption {
                  type = types.str;
                  default = "password";
                  example = "password";
                  description = "The password for the local administrator account.";
                };
              };
              implementation =
                {
                  name,
                  version,
                  cpus,
                  diskSize,
                  memory,
                  disableWindowsUpdates,
                  disableWindowsDefender,
                  zeroOutFreeSpace,
                  debloat,
                  timeZone,
                  computerName,
                  username,
                  password,
                  ...
                }:
                pkgs.stdenv.mkDerivation {
                  pname = "windows-image";
                  version = "1.0";

                  src = ./.;

                  buildInputs = [
                    pkgs.qemu
                  ];

                  buildPhase =
                    let
                      isoUrls = {
                        "windows-11-23h2" = {
                          url = "https://software-static.download.prss.microsoft.com/dbazure/888969d5-f34g-4e03-ac9d-1f9786c66749/22631.2428.231001-0608.23H2_NI_RELEASE_SVC_REFRESH_CLIENTENTERPRISEEVAL_OEMRET_x64FRE_en-us.iso";
                          sha256 = "sha256-yNvJa2HQTIsB+vbOB5T98zllx7NQ6qPrHmaXAZkClFw=";
                        };
                      };
                      isoPath = pkgs.fetchurl isoUrls."${version}";
                      packerConfiguration = pkgs.writeTextFile {
                        name = "windows.pkr.hcl";
                        text = ''
                          packer {
                            required_plugins {
                              qemu = {
                                source = "github.com/hashicorp/qemu"
                                version = "1.1.4"
                              }
                            }
                          }

                          source "qemu" "windows" {
                            communicator = "none"

                            accelerator = "kvm"
                            cpus = "${builtins.toString cpus}"

                            disk_size = "${builtins.toString diskSize}"
                            format = "qcow2"
                            disk_compression = "true"
                            disk_interface = "virtio"

                            headless = "true"

                            # Note: this not actually used, we specify the device by hand
                            iso_url = "${isoPath}"
                            iso_checksum = "none"

                            memory = "${builtins.toString memory}"
                            net_device = "virtio-net"

                            output_directory = "output"

                            vnc_port_min = 5900
                            vnc_port_max = 5900

                            qemu_img_args {
                              create = ["-o", "compat=1.1"]
                              convert = ["-o", "compat=1.1"]
                              resize  = ["-o", "compat=1.1"]
                            }

                            qemuargs = [
                              ["-drive", "file=output/packer-windows,if=virtio,cache=writeback,discard=unmap,detect-zeroes=unmap,format=qcow2"],
                              ["-drive", "media=cdrom,index=0,file=${isoPath}"],
                              ["-drive", "media=cdrom,index=2,file=unattended.iso"],
                              ["-net", "none"],
                              ["-name", "qemu-windows-install,process=qemu-windows-install"]
                            ]

                            boot_wait = "20s"
                            shutdown_timeout = "30m"
                          }

                          build {
                            sources = ["source.qemu.windows"]
                          }
                        '';
                      };
                      passes = {
                        "windowsPE.bat" = ''
                          rem Disable TPM check
                          reg add "HKLM\SYSTEM\Setup\LabConfig" /v "BypassTPMCheck" /t REG_DWORD /d 1
                          rem Disable Secure Boot check
                          reg add "HKLM\SYSTEM\Setup\LabConfig" /v "BypassSecureBootCheck" /t REG_DWORD /d 1
                        '';
                        "specialize.bat" = pkgs.lib.optionalString disableWindowsDefender ''
                          rem Disable Windows Defender
                          reg add HKLM\SYSTEM\ControlSet001\Services\Sense /v Start /t REG_DWORD /d 4 /f
                          reg add HKLM\SYSTEM\ControlSet001\Services\WdBoot /v Start /t REG_DWORD /d 4 /f
                          reg add HKLM\SYSTEM\ControlSet001\Services\WdFilter /v Start /t REG_DWORD /d 4 /f
                          reg add HKLM\SYSTEM\ControlSet001\Services\WdNisDrv /v Start /t REG_DWORD /d 4 /f
                          reg add HKLM\SYSTEM\ControlSet001\Services\WdNisSvc /v Start /t REG_DWORD /d 4 /f
                          reg add HKLM\SYSTEM\ControlSet001\Services\WinDefend /v Start /t REG_DWORD /d 4 /f

                          rem Disable Web Threat Defense Service
                          reg add HKLM\SYSTEM\ControlSet001\Services\webthreatdefsvc /v Start /t REG_DWORD /d 4 /f
                        '';
                        "oobeSystem.bat" = builtins.concatStringsSep "\n" [
                          ''
                            rem Set high performance mode
                            powercfg /SETACTIVE 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c

                            rem Set PowerShell Execution Policy
                            powershell -Command "Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Force"

                            rem Zero the hiberfile
                            reg add HKLM\SYSTEM\CurrentControlSet\Control\Power\ /v HibernateFileSizePercent /t REG_DWORD /d 0 /f

                            rem Disable hibernation support
                            reg add HKLM\SYSTEM\CurrentControlSet\Control\Power\ /v HibernateEnabled /t REG_DWORD /d 0 /f

                            rem Remove hibernation file
                            powercfg /h off

                            rem Disable password expiration for user
                            wmic useraccount where "name='${username}'" set PasswordExpires=FALSE

                            rem Installs the code signing cert for RedHat for drivers embedded in spice-guest-tools
                            certutil -addstore -f "TrustedPublisher" e:/drivers/redhat-certificate.der

                            rem WSUS / Updates
                            rem When upgrading packages, we'd normally have to wait for Tiworker to exit
                            rem This will not exit if sharing is enabled, as it will be waiting for connections
                            reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" /v DODownloadMode /t REG_DWORD /d 0 /f
                            rem https://github.com/rgl/packer-plugin-windows-update/issues/49#issuecomment-1295325179
                            reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config\" /v DODownloadMode /t REG_DWORD /d 0 /f
                            rem Also disable auto updates, make them on-demand so our update step has an easy "Tiworker no longer executing" case
                            reg add "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" /v NoAutoUpdate /t REG_DWORD /d 1 /f
                            reg add "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" /v AUOptions /t REG_DWORD /d 2 /f
                            rem Disable a bunch of other things
                            rem Stop AppX packages from auto-updating from the store (see https://blogs.technet.microsoft.com/swisspfe/2018/04/13/win10-updates-store-gpos-dualscandisabled-sup-wsus/)
                            reg add "HKLM\SOFTWARE\Policies\Microsoft\WindowsStore" /v AutoDownload /t REG_DWORD /d 2
                            reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsStore\WindowsUpdate" /v AutoDownload /t REG_DWORD /d 2
                            rem Stop third-party "promoted" apps from installing in the current user (see https://blogs.technet.microsoft.com/mniehaus/2015/11/23/seeing-extra-apps-turn-them-off/)
                            reg add "HKLM\Software\Policies\Microsoft\Windows\CloudContent /v DisableWindowsConsumerFeatures" /t REG_DWORD /d 1

                            rem Enable RDP / Create FW rules
                            netsh advfirewall firewall add rule name="Open Port 3389" dir=in action=allow protocol=TCP localport=3389
                            reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f

                            rem Install spice guest tools
                            e:\extra\spice-guest-tools.exe /S

                            rem Install QEMU Guest Additions
                            msiexec /i e:\extra\qemu-ga-x86_64.msi /quiet /passive /qn

                            rem Install some other software
                            e:\extra\Git-64-bit.exe /VERYSILENT /NORESTART /NOCANCEL /SP- /CLOSEAPPLICATIONS /RESTARTAPPLICATIONS /COMPONENTS="icons,ext\reg\shellhere,assoc,assoc_sh"
                            e:\extra\systeminformer-release-setup.exe -silent
                            e:\extra\firefox-installer.exe /S
                            e:\extra\chrome-installer.exe /silent /install
                            msiexec /i e:\extra\npp.Installer.x64.msi /quiet /passive /qn
                            msiexec /i e:\extra\chocolatey.msi /quiet /passive /qn
                            msiexec /i e:\extra\Everything.x64.msi /quiet /passive /qn

                            rem Uninstall OneDrive stuff
                            OneDriveSetup.exe /uninstall

                            rem Disable SearchIndexer
                            sc config wsearch start=disabled

                            rem ngen
                            if exist %windir%\microsoft.net\framework\v4.0.30319\ngen.exe (
                                    %windir%\microsoft.net\framework\v4.0.30319\ngen.exe update /force /queue
                                    %windir%\microsoft.net\framework\v4.0.30319\ngen.exe executequeueditems
                            )
                            if exist %windir%\microsoft.net\framework64\v4.0.30319\ngen.exe (
                                    %windir%\microsoft.net\framework64\v4.0.30319\ngen.exe update /force /queue
                                    %windir%\microsoft.net\framework64\v4.0.30319\ngen.exe executequeueditems
                            )
                          ''
                          (pkgs.lib.optionalString disableWindowsUpdates ''
                            rem Disable Windows Updates by setting update server to 127.6.6.6
                            reg import e:\passes\oobeSystem\fake-windows-update-server.reg
                            gpupdate /force
                          '')
                          ''
                            rem Shrink the image
                            dism.exe /online /Cleanup-Image /StartComponentCleanup /ResetBase

                            rem Continue in PowerShell
                            powershell -ExecutionPolicy Bypass -File e:\passes\oobeSystem\oobeSystem.ps1

                          ''
                          (pkgs.lib.optionalString zeroOutFreeSpace ''
                            rem Zero out free space to better compress the final image
                            rem Make sure this is the last significant thing we do
                            cd %USERPROFILE%\Desktop
                            cd SysinternalsSuite
                            sdelete.exe /accepteula -z c:
                          '')
                          ''
                            shutdown /s /t 0
                          ''
                        ];
                        "oobeSystem/fake-windows-update-server.reg" = ''
                          REGEDIT4

                          [HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate]
                          "WUServer"="127.6.6.6"
                          "WUStatusServer"="127.6.6.6"
                          "UpdateServiceUrlAlternate"=""
                          "SetProxyBehaviorForUpdateDetection"=dword:00000000

                          [HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU]
                          "NoAutoUpdate"=dword:00000001
                          "AUOptions"=dword:00000002
                          "UseWUServer"=dword:00000001
                        '';
                        "oobeSystem/oobeSystem.ps1" = builtins.concatStringsSep "\n" [
                          ''
                            function Extract-ZipToDesktop {
                                param(
                                    [string]$zipFilePath
                                )

                                # Check if the file exists
                                if (-Not (Test-Path -Path $zipFilePath)) {
                                    Write-Host "The file does not exist: $zipFilePath"
                                    return
                                }

                                # Get the file name without the .zip extension
                                $fileName = [System.IO.Path]::GetFileNameWithoutExtension($zipFilePath)

                                # Set the destination folder on the desktop
                                $desktopPath = [System.Environment]::GetFolderPath('Desktop')
                                $destinationFolder = Join-Path -Path $desktopPath -ChildPath $fileName

                                # Create the destination folder if it does not exist
                                if (-Not (Test-Path -Path $destinationFolder)) {
                                    New-Item -ItemType Directory -Path $destinationFolder
                                }

                                # Extract the zip file to the destination folder
                                Write-Host "Extracting '$zipFilePath' to '$destinationFolder'"
                                Expand-Archive -Path $zipFilePath -DestinationPath $destinationFolder

                                Write-Host "Extraction complete."
                            }

                            # Extract zips to the desktop
                            Extract-ZipToDesktop -zipFilePath "e:\extra\depends_x64.zip"
                            Extract-ZipToDesktop -zipFilePath "e:\extra\SysinternalsSuite.zip"
                            Extract-ZipToDesktop -zipFilePath "e:\extra\Dependencies_x64_Release.zip"

                          ''
                          (pkgs.lib.optionalString debloat ''
                            Extract-ZipToDesktop -zipFilePath "e:\extra\Win11Debloat.zip"
                            $desktop = [System.Environment]::GetFolderPath('Desktop')
                            cd $desktop
                            cd .\Win11Debloat*
                            cd .\Win11Debloat*
                            # Do not create a restore point
                            $filePath = "Win11Debloat.ps1"
                            $lines = Get-Content $filePath
                            $lines | Where-Object { $_ -notmatch "Checkpoint-Computer" } | Set-Content $filePath
                            .\Win11Debloat.ps1 -RunDefaults -Silent

                            cd $desktop
                            Remove-Item -Recurse .\Win11Debloat*
                          '')
                        ];
                      };
                      autounattendXML = pkgs.writeTextFile {
                        name = "";
                        text = ''
                          <?xml version="1.0" encoding="utf-8"?>
                          <unattend xmlns="urn:schemas-microsoft-com:unattend">
                            <servicing />
                            <settings pass="windowsPE">
                              <component xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State"
                                         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
                                         name="Microsoft-Windows-Setup"
                                         processorArchitecture="amd64"
                                         publicKeyToken="31bf3856ad364e35"
                                         language="neutral"
                                         versionScope="nonSxS">
                                <RunSynchronous>
                                  <RunSynchronousCommand wcm:action="add">
                                    <Order>1</Order>
                                    <Description>windowsPE</Description>
                                    <Path>cmd /c e:\passes\windowsPE.bat</Path>
                                  </RunSynchronousCommand>
                                </RunSynchronous>
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
                                <UserData>
                                  <AcceptEula>true</AcceptEula>
                                  <FullName>${username}</FullName>
                                  <Organization>Organization</Organization>
                                  <ProductKey>
                                    <!-- If you *do* set a key, ensure it's for the right platform: -->
                                    <!-- otherwise you will get the dreaded "No images are available" -->
                                    <!-- which actually means "No images are available for this ProductKey! -->
                                    <!-- <Key>SET_KEY_HERE</Key> -->
                                  </ProductKey>
                                </UserData>
                                <ImageInstall>
                                  <OSImage>
                                    <InstallTo>
                                      <DiskID>0</DiskID>
                                      <PartitionID>1</PartitionID>
                                    </InstallTo>
                                    <WillShowUI>OnError</WillShowUI>
                                    <InstallToAvailablePartition>false</InstallToAvailablePartition>
                                    <InstallFrom>
                                      <MetaData wcm:action="add">
                                        <Key>/IMAGE/NAME</Key>
                                        <Value>Windows 11 Enterprise Evaluation</Value>
                                      </MetaData>
                                    </InstallFrom>
                                  </OSImage>
                                </ImageInstall>
                              </component>
                              <component xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State"
                                         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
                                         language="neutral"
                                         name="Microsoft-Windows-PnpCustomizationsWinPE"
                                         processorArchitecture="amd64"
                                         publicKeyToken="31bf3856ad364e35"
                                         versionScope="nonSxS">
                                <DriverPaths>
                                  <PathAndCredentials wcm:action="add"
                                                      wcm:keyValue="1">
                                    <Path>e:\drivers</Path>
                                  </PathAndCredentials>
                                </DriverPaths>
                              </component>
                              <component xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State"
                                         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
                                         name="Microsoft-Windows-International-Core-WinPE"
                                         processorArchitecture="amd64"
                                         publicKeyToken="31bf3856ad364e35"
                                         language="neutral"
                                         versionScope="nonSxS">
                                <SetupUILanguage>
                                  <UILanguage>en-US</UILanguage>
                                </SetupUILanguage>
                                <InputLocale>0409:00000409</InputLocale>
                                <SystemLocale>en-US</SystemLocale>
                                <UILanguage>en-US</UILanguage>
                                <UILanguageFallback>en-US</UILanguageFallback>
                                <UserLocale>en-US</UserLocale>
                              </component>
                            </settings>
                            <settings pass="offlineServicing">
                              <component name="Microsoft-Windows-LUA-Settings"
                                         processorArchitecture="amd64"
                                         publicKeyToken="31bf3856ad364e35"
                                         language="neutral"
                                         versionScope="nonSxS">
                                <EnableLUA>false</EnableLUA>
                              </component>
                            </settings>
                            <settings pass="specialize">
                              <component name="Microsoft-Windows-Shell-Setup"
                                         processorArchitecture="amd64"
                                         publicKeyToken="31bf3856ad364e35"
                                         language="neutral"
                                         versionScope="nonSxS">
                                <OEMInformation>
                                  <HelpCustomized>false</HelpCustomized>
                                </OEMInformation>
                                <ComputerName>${computerName}</ComputerName>
                                <TimeZone>${timeZone}</TimeZone>
                                <RegisteredOwner />
                              </component>
                              <component xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State"
                                         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
                                         name="Microsoft-Windows-Security-SPP-UX"
                                         processorArchitecture="amd64"
                                         publicKeyToken="31bf3856ad364e35"
                                         language="neutral"
                                         versionScope="nonSxS">
                                <SkipAutoActivation>true</SkipAutoActivation>
                              </component>
                              <component xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State"
                                         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
                                         name="Microsoft-Windows-Deployment"
                                         processorArchitecture="amd64"
                                         publicKeyToken="31bf3856ad364e35"
                                         language="neutral"
                                         versionScope="nonSxS">
                                <RunSynchronous>
                                  <RunSynchronousCommand wcm:action="add">
                                    <Order>1</Order>
                                    <Description>specialize</Description>
                                    <Path>cmd /c e:\passes\specialize.bat</Path>
                                  </RunSynchronousCommand>
                                </RunSynchronous>
                              </component>
                            </settings>
                            <settings pass="oobeSystem">
                              <component xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State"
                                         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
                                         name="Microsoft-Windows-Shell-Setup"
                                         processorArchitecture="amd64"
                                         publicKeyToken="31bf3856ad364e35"
                                         language="neutral"
                                         versionScope="nonSxS">
                                <UserAccounts>
                                  <AdministratorPassword>
                                    <Value>${username}</Value>
                                    <PlainText>true</PlainText>
                                  </AdministratorPassword>
                                  <LocalAccounts>
                                    <LocalAccount wcm:action="add">
                                      <Password>
                                        <Value>${password}</Value>
                                        <PlainText>true</PlainText>
                                      </Password>
                                      <Description>${username}</Description>
                                      <DisplayName>${username}</DisplayName>
                                      <Group>administrators</Group>
                                      <Name>${username}</Name>
                                    </LocalAccount>
                                  </LocalAccounts>
                                </UserAccounts>
                                <OOBE>
                                  <HideEULAPage>true</HideEULAPage>
                                  <HideOEMRegistrationScreen>true</HideOEMRegistrationScreen>
                                  <HideOnlineAccountScreens>true</HideOnlineAccountScreens>
                                  <HideWirelessSetupInOOBE>true</HideWirelessSetupInOOBE>
                                  <NetworkLocation>Work</NetworkLocation>
                                  <SkipUserOOBE>true</SkipUserOOBE>
                                  <SkipMachineOOBE>true</SkipMachineOOBE>
                                  <ProtectYourPC>1</ProtectYourPC>
                                </OOBE>
                                <AutoLogon>
                                  <Password>
                                    <Value>${password}</Value>
                                    <PlainText>true</PlainText>
                                  </Password>
                                  <Username>${username}</Username>
                                  <Enabled>true</Enabled>
                                </AutoLogon>
                                <FirstLogonCommands>
                                  <SynchronousCommand wcm:action="add">
                                    <CommandLine>cmd.exe /c e:\passes\oobeSystem.bat</CommandLine>
                                    <Order>1</Order>
                                    <Description>Bootstrap everything</Description>
                                    <RequiresUserInput>true</RequiresUserInput>
                                  </SynchronousCommand>
                                </FirstLogonCommands>
                                <ShowWindowsLive>false</ShowWindowsLive>
                              </component>
                            </settings>
                          </unattend>
                        '';
                      };
                      virtioIsoPath = pkgs.fetchurl {
                        url = "https://fedorapeople.org/groups/virt/virtio-win/direct-downloads/archive-virtio/virtio-win-0.1.285-1/virtio-win-0.1.285.iso";
                        sha256 = "sha256-4UzyuUSSw+kl8AcLp/3+3rIEjJHuqcWlr7MCMqOXYzE=";
                      };
                      extraFiles = [
                        {
                          url = "https://www.spice-space.org/download/windows/spice-guest-tools/spice-guest-tools-0.141/spice-guest-tools-0.141.exe";
                          sha256 = "sha256-tb4HVIArzX9/4Mzbh3+KYiS6E6KvfYTrCHqJs7AjfaI=";
                          name = "spice-guest-tools.exe";
                        }
                        {
                          url = "https://github.com/notepad-plus-plus/notepad-plus-plus/releases/download/v8.9/npp.8.9.Installer.x64.msi";
                          sha256 = "sha256-LeTdpx0AcwhEl0d0wsZMzHyqV6Nd5O7D2Cq99+UGyNI=";
                          name = "npp.Installer.x64.msi";
                        }
                        {
                          url = "https://github.com/chocolatey/choco/releases/download/2.6.0/chocolatey-2.6.0.0.msi";
                          sha256 = "sha256-UP7K8R0LqJzxbdQeZTzaQJzclNKaeS9wDZ3EWrUxPi0=";
                          name = "chocolatey.msi";
                        }
                        {
                          url = "https://www.dependencywalker.com/depends22_x64.zip";
                          sha256 = "sha256-NdtophOHSi6MFCLrDqeGH4JfxxcX1G2r8fJJzpY0tPE=";
                          name = "depends_x64.zip";
                        }
                        {
                          # Unfortunately, Sysinternals does not release versioned installers
                          url = "https://download.sysinternals.com/files/SysinternalsSuite.zip";
                          sha256 = "sha256-oOzkxS7pxxw8AgOCRdPgs8YVD/8OJr1734gvx+5Uz2k=";
                          name = "SysinternalsSuite.zip";
                        }
                        {
                          url = "https://github.com/lucasg/Dependencies/releases/download/v1.11.1/Dependencies_x64_Release.zip";
                          sha256 = "sha256-fSLcAPHAn9RBXUitdNHPgBiT6DuaOZRLD85t6nzq6pk=";
                          name = "Dependencies_x64_Release.zip";
                        }
                        {
                          url = "https://codeload.github.com/Raphire/Win11Debloat/zip/refs/tags/2025.12.29";
                          sha256 = "sha256-moOrldUaZMP55zhubxX2kP5KRuAzWGU/cXYSkp48OS8=";
                          name = "Win11Debloat.zip";
                        }
                        {
                          url = "https://github.com/git-for-windows/git/releases/download/v2.52.0.windows.1/Git-2.52.0-64-bit.exe";
                          sha256 = "sha256-2N56MVImbIuxNXfquFDqHfbcz4wqpIvltKHFi3GQ1iw=";
                          name = "Git-64-bit.exe";
                        }
                        {
                          url = "https://github.com/winsiderss/systeminformer/releases/download/v3.2.25011.2103/systeminformer-3.2.25011-release-setup.exe";
                          sha256 = "sha256-dhLV5EpaOSq58NG1uKeb2jzb4ZhI6O6ewjkJqvParUU=";
                          name = "systeminformer-release-setup.exe";
                        }
                        {
                          url = "https://download-installer.cdn.mozilla.net/pub/firefox/releases/146.0.1/win64/en-US/Firefox%20Setup%20146.0.1.exe";
                          sha256 = "sha256-TjKTXQueQj5xjCwxBm+gloYHca/KSpiHCay0SONx3iI=";
                          name = "firefox-installer.exe";
                        }
                        {
                          url = "https://dl.google.com/tag/s/appguid%3D%7B8A69D345-D564-463C-AFF1-A69D9E530F96%7D%26iid%3D%7B69E1383A-15F0-16D1-5896-8867623813A4%7D%26lang%3Den%26browser%3D4%26usagestats%3D0%26appname%3DGoogle%2520Chrome%26needsadmin%3Dprefers%26ap%3D-arch_x64-statsdef_1%26installdataindex%3Dempty/chrome/install/ChromeStandaloneSetup64.exe";
                          sha256 = "sha256-HBq7qLfkiIH8cNd8uQw0lByDTI98DSZ2SWJwjZvJLGE=";
                          name = "chrome-installer.exe";
                        }
                        {
                          url = "https://www.voidtools.com/Everything-1.4.1.1030.x64.msi";
                          sha256 = "sha256-W/8tukbHGDi4lm00C6NqGB+wDM1cvaRZADcR64B2jIk=";
                          name = "Everything.x64.msi";
                        }
                      ];
                      copyUrls =
                        list:
                        let
                          fetchUrls = map (
                            entry:
                            let
                              fetched = pkgs.fetchurl {
                                url = entry.url;
                                sha256 = entry.sha256;
                              };
                            in
                            "cp -a ${fetched} ${entry.name}"
                          ) list;
                        in
                        pkgs.lib.concatStringsSep "\n" fetchUrls;
                      openssl = "${pkgs.openssl}/bin/openssl";
                      p7zip = "${pkgs.p7zip}/bin/7z";
                      createFiles = (
                        files:
                        let
                          dirs = builtins.map builtins.dirOf (builtins.attrNames files);
                          mkdirs = builtins.concatStringsSep "\n" (builtins.map (d: "mkdir -p ${d}/") dirs);

                          fileDeriv =
                            path: content:
                            pkgs.writeTextFile {
                              name = builtins.baseNameOf path;
                              text = content;
                            };

                          cps = pkgs.lib.concatStringsSep "\n" (
                            pkgs.lib.mapAttrsToList (path: content: "cp ${fileDeriv path content} ${path}") files
                          );

                        in
                        pkgs.lib.strings.concatStringsSep "\n" [
                          mkdirs
                          cps
                        ]
                      );
                    in
                    ''
                      # Do not contact hashicorp servers
                      export CHECKPOINT_DISABLE=1

                      # Verbose logging
                      export PACKER_LOG=1

                      mkdir -p fake-home/.config fake-home/.cache/packer
                      export HOME="$PWD/fake-home"

                      # Prepare plugins.
                      # This should be a no-op, we already fetched them in a previous
                      # derivation. If it isn't, it will fail due to no internet
                      # connection.
                      cp -ar ${self.packages.${pkgs.system}.plugins}/packer fake-home/.config
                      ${pkgs.packer}/bin/packer init ${packerConfiguration}

                      # Prepare unattended.iso
                      mkdir unattended
                      pushd unattended > /dev/null

                      cp -a ${autounattendXML} Autounattend.xml
                      cat Autounattend.xml

                      mkdir extra
                      pushd extra > /dev/null
                      ${copyUrls extraFiles}
                      popd > /dev/null

                      mkdir passes
                      pushd passes > /dev/null
                      ${createFiles passes}
                      popd > /dev/null

                      # Extract in drivers all the w11 drivers.
                      # Autounattend.xml will direct the Windows setup to recursively
                      # scan e:\drivers
                      mkdir drivers
                      pushd drivers > /dev/null
                      ${p7zip} x ${virtioIsoPath} $(${p7zip} l ${virtioIsoPath}  | grep w11 | grep -i amd64 | grep -F D.... | awk '{ print $4 }')
                      popd > /dev/null

                      ${p7zip} x ${virtioIsoPath} guest-agent/qemu-ga-x86_64.msi
                      mv guest-agent/qemu-ga-x86_64.msi extra/
                      rmdir guest-agent

                      mkdir spice-drivers
                      pushd spice-drivers > /dev/null
                      ${p7zip} x ../extra/spice-guest-tools.exe drivers/vioserial/w10/amd64/vioser.cat
                      ${openssl} pkcs7 -inform der -in drivers/vioserial/w10/amd64/vioser.cat -print_certs | grep Red -A1000 | grep -m1 'END CERTIFICATE' -B 10000 | ${openssl} x509 -inform pem -outform der > ../drivers/redhat-certificate.der || true
                      popd > /dev/null
                      rm -rf spice-drivers

                      echo "Files in unattended.iso:"
                      find

                      popd > /dev/null

                      ${pkgs.cdrtools}/bin/mkisofs -quiet -J -o "unattended.iso" "unattended/"

                      ${pkgs.packer}/bin/packer build ${packerConfiguration}

                      mkdir -p output/share/windows-vm

                      cat > output/share/windows-vm/windows.conf <<EOF
                      guest_os="windows"
                      boot="legacy"
                      disk_img="image.qcow2"
                      tpm="off"
                      secureboot="off"
                      EOF

                      cp -a ${pkgs.writeShellScript "start" ''
                        SCRIPT_DIR=$( cd -- "$( dirname -- "''${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
                        set -euo pipefail
                        cd "$SCRIPT_DIR"
                        ${pkgs.quickemu}/bin/quickemu --vm windows.conf --display spice
                      ''} output/share/windows-vm/start

                      cp -a ${pkgs.writeShellScript "stop" ''
                        SCRIPT_DIR=$( cd -- "$( dirname -- "''${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
                        set -euo pipefail
                        cd "$SCRIPT_DIR"
                        ${pkgs.quickemu}/bin/quickemu --vm windows.conf --kill
                      ''} output/share/windows-vm/stop

                      mv output/packer-windows output/share/windows-vm/image.qcow2

                      mkdir -p output/bin
                      cp -a ${pkgs.writeShellScript "prepare-windows-vm" ''
                        SCRIPT_DIR=$( cd -- "$( dirname -- "''${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
                        set -euo pipefail
                        cp -ar --reflink=auto "$SCRIPT_DIR/../share/windows-vm" .
                        chmod u+w --recursive windows-vm
                      ''} output/bin/prepare-windows-vm
                    '';

                  installPhase = ''
                    mkdir -p "$out"
                    mv output/* "$out/"
                  '';
                };
            };
          in
          {
            _module.args.pkgs = import inputs.nixpkgs {
              inherit system;
              config = {
                allowUnfree = true;
              };
            };

            packages.plugins = pkgs.stdenv.mkDerivation {
              pname = "packer-plugins";
              version = "1.0";
              src = ./.;

              outputHashMode = "recursive";
              outputHashAlgo = "sha256";
              outputHash = "sha256-z4PrpKCrn+1c10O5shDz0vv8xqA9bHQR093iIh0XbSM=";

              buildPhase = ''
                export HOME="$PWD"
                ${pkgs.packer}/bin/packer plugins install github.com/hashicorp/qemu
              '';

              installPhase = ''
                rm .config/packer/checkpoint_signature
                mkdir -p "$out"
                cp -ar .config/packer "$out"
              '';
            };
            packages.default = mkWindowsImage {
              name = "windows-11-23h2";
              version = "windows-11-23h2";
            };
          };
      }
    );
}
