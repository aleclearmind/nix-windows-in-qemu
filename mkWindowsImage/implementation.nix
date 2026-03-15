{
  pkgs,
  config,
  userConfiguration,
  common,
  ...
}:
let
  lib = pkgs.lib;
  windowsImage =
    {
      name,
      version,
      cpus,
      diskSize,
      memory,
      disableWindowsUpdate,
      disableWindowsDefender,
      zeroOutFreeSpace,
      compressDiskImage,
      timeZone,
      computerName,
      username,
      password,
      recordInstallation,
      testInstallation,
      runNgen,
      preinstall,
    }:
    let
      configuration = config.systems."${version}";

      hasAutounattendXml = !(builtins.isNull configuration.installation.autounattendXml);

      needsSamba = configuration.installation.emitsSummary;

      isCompatible =
        operatingSystem:
        (operatingSystem.name == configuration.operatingSystem.name)
        && (
          (builtins.isNull operatingSystem.minimumVersion)
          || (
            (builtins.compareVersions operatingSystem.minimumVersion configuration.operatingSystem.version) <= 0
          )
        )
        && (
          (builtins.isNull operatingSystem.maximumVersion)
          || (
            (builtins.compareVersions operatingSystem.maximumVersion configuration.operatingSystem.version) >= 0
          )
        );

      compatiblePreinstall = lib.lists.sort (lhs: rhs: lhs.installer.priority > rhs.installer.priority) (
        builtins.filter (package: isCompatible package.operatingSystem) preinstall
      );

      installerType =
        package:
        let
          installer = package.installer;
          hasExtension = extension: (lib.strings.hasSuffix extension (lib.strings.toLower installer.name));
        in
        if (!(builtins.isNull installer.arguments)) then
          "arguments"
        else if (!(builtins.isNull installer.bat)) then
          "bat"
        else if (!(builtins.isNull installer.ps1)) then
          "ps1"
        else if hasExtension ".msi" then
          "msi"
        else if hasExtension ".zip" then
          "zip"
        else
          throw "Unknown installer type for for ${installer.name}";

      installersByType =
        type:
        if builtins.isNull type then
          compatiblePreinstall
        else
          builtins.filter (package: (installerType package) == type) compatiblePreinstall;

      handleInstallersByType =
        handlers:
        common.mapLines (
          installer:
          let
            type = installerType installer;
          in
          if builtins.hasAttr type handlers then handlers."${type}" installer else ""
        ) compatiblePreinstall;

      handleInstallers = handler: common.mapLines handler compatiblePreinstall;

      operatingSystem = configuration.operatingSystem;

      driverPaths =
        if operatingSystem.name == "windows" then
          let
            versionName = common.windowsVersionName operatingSystem.version;
            directory =
              if versionName == "11" then
                "w11"
              else if versionName == "10" then
                "w10"
              else if versionName == "7" then
                "w7"
              else if versionName == "8" then
                "w8"
              else if versionName == "8.1" then
                "w8.1"
              else if versionName == "xp" then
                "xp"
              else
                null;
          in
          if !builtins.isNull directory then
            [
              "fwcfg/${directory}/amd64"
              "vioinput/${directory}/amd64"
              "vioscsi/${directory}/amd64"
              "viostor/${directory}/amd64"
              "vioserial/${directory}/amd64"
              "viorng/${directory}/amd64"
              "NetKVM/${directory}/amd64"
              "viofs/${directory}/amd64"
              "Balloon/${directory}/amd64"
            ]
          else
            [ ]
        else
          [ ];

      drivers = common.extractWith7z {
        name = "qemu-ga-x86_64.msi";
        archive = common.virtioIso;
        paths = driverPaths;
      };

    in
    pkgs.stdenv.mkDerivation {
      pname = "windows-image";
      version = "1.0";
      src = null;
      dontUnpack = true;

      nativeBuildInputs =
        with pkgs;
        [
          qemu
          p7zip
          openssl
          socat
          vncdo
          tesseract
          cdrtools
          jq
          time
          python3
          util-linux
        ]
        ++ (lib.optionals needsSamba [
          samba
          libressl.nc
        ])
        ++ (lib.optionals testInstallation [
          unzip
          procps
        ])
        ++ (lib.optionals recordInstallation [
          ffmpeg-full
          xvfb-run
          tigervnc
          xwininfo
          gawk
          procps
        ]);

      buildPhase =
        let
          min = value: upperBound: if (builtins.isNull upperBound) then value else (lib.min value upperBound);
          passes = {
            "windowsPE.bat" = ''

              ${lib.optionalString
                ((builtins.length configuration.installation.autounattendXml.servicesToDisable) > 0)
                ''
                  start /min cmd.exe /c ">x:\windowsPE.log 2>&1 ( cscript.exe //E:vbscript e:\passes\windowsPE\disable-services.vbs )"
                ''
              }

              rem Disable TPM check
              reg add "HKLM\SYSTEM\Setup\LabConfig" /v "BypassTPMCheck" /t REG_DWORD /d 1
              rem Disable Secure Boot check
              reg add "HKLM\SYSTEM\Setup\LabConfig" /v "BypassSecureBootCheck" /t REG_DWORD /d 1
            '';

            # The following script spins indefinitely during the windowsPE phase looking for hives and tampering with them.
            # This is not super elegant, but this is the only phase in which these services (in particular, Windows Defender)
            # are not running yet and self-protecting themselves from being disabled.
            # In particular, Windows Defender is already running during the specialize phase.
            "windowsPE/disable-services.vbs" = ''
              On Error Resume Next

              WScript.Echo "Scanning for newly created SYSTEM and SOFTWARE registry hive files..."

              Set fso = CreateObject("Scripting.FileSystemObject")

              Set existing = CreateObject("Scripting.Dictionary")

              Function Execute(command)
                  WScript.Echo "Running command '" + command + "'"
                  Set shell = CreateObject("WScript.Shell")
                  Set exec = shell.Exec(command)
                  Do While exec.Status = 0
                      WScript.Sleep 100
                  Loop
                  WScript.Echo exec.StdOut.ReadAll
                  WScript.Echo exec.StdErr.ReadAll
                  Execute = exec.ExitCode
              End Function

              Function FindHiveDirectories()
                  Set FindHiveDirectories = CreateObject("Scripting.Dictionary")
                  For Each drive In fso.Drives
                      If drive.IsReady And drive.DriveLetter <> "X" Then
                          For Each folder In Array("$Windows.~BT\NewOS\Windows", "Windows")
                              directory = fso.BuildPath(fso.BuildPath(drive.RootFolder, folder), "System32\config\")
                              If fso.FileExists(directory + "SYSTEM") And fso.FileExists(directory + "SYSTEM.LOG1") And fso.FileExists(directory + "SYSTEM.LOG2") And _
                                 fso.FileExists(directory + "SOFTWARE") And fso.FileExists(directory + "SOFTWARE.LOG1") And fso.FileExists(directory + "SOFTWARE.LOG2") Then
                                  WScript.Echo "Hive directory found: " + directory
                                  FindHiveDirectories.Add directory, Nothing
                              End If
                          Next
                      End If
                  Next
              End Function

              For Each directory In FindHiveDirectories
                  WScript.Echo "Will ignore files at '" + directory + "' because it was already present when Windows Setup started."
                  existing.Add directory, Nothing
              Next

              Do
                  For Each directory In FindHiveDirectories
                      If directory = "" Then
                          WScript.Echo "Something wrong"
                      End If
                      If Not existing.Exists(directory) And directory <> "" Then
                          WScript.Echo "Mounting " + directory
                          ret = 1
                          While ret > 0
                              WScript.Sleep 500
                              ret = Execute("reg load HKLM\new-SYSTEM """ + directory + "SYSTEM""")
                          Wend

                          ret = 1
                          While ret > 0
                              WScript.Sleep 500
                              ret = Execute("reg load HKLM\new-SOFTWARE """ + directory + "SOFTWARE""")
                          Wend

                          ret = Execute("reg import e:\passes\windowsPE\early-registry-patches.reg")
                          If ret <> 0 Then
                            WScript.Echo "Command failed"
                            Exit Do
                          End If

                          WScript.Echo "Unmounting"
                          ret = Execute("reg unload HKLM\new-SYSTEM")
                          If ret <> 0 Then
                            WScript.Echo "Command failed"
                            Exit Do
                          End If

                          ret = Execute("reg unload HKLM\new-SOFTWARE")
                          If ret <> 0 Then
                            WScript.Echo "Command failed"
                            Exit Do
                          End If


                          WScript.Echo "All done!"

                          ret = Execute("cmd /c copy x:\windowsPE.log """ + directory + """")
                          WScript.Echo "Copy result: " + CStr(ret)

                          Exit Do
                      End If
                      WScript.Sleep 1000
                  Next
              Loop
            '';
            # Make sure you only use HKLM\new-SYSTEM and HKLM\new-SOFTWARE only
            "windowsPE/early-registry-patches.reg" = ''
              REGEDIT4

              ${common.mapLines (serviceName: ''
                [HKEY_LOCAL_MACHINE\new-SYSTEM\ControlSet001\Services\${serviceName}]
                "Start"=dword:00000004
              '') configuration.installation.autounattendXml.servicesToDisable}

              [HKEY_LOCAL_MACHINE\new-SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System]
              "EnableFirstLogonAnimation"=dword:00000000

              [HKEY_LOCAL_MACHINE\new-SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon]
              "EnableFirstLogonAnimation"=dword:00000000

              [HKEY_LOCAL_MACHINE\new-SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate]
              "WUServer"="127.6.6.6"
              "WUStatusServer"="127.6.6.6"
              "UpdateServiceUrlAlternate"=""
              "SetProxyBehaviorForUpdateDetection"=dword:00000000
              "DoNotConnectToWindowsUpdateInternetLocations"=dword:00000001

              [HKEY_LOCAL_MACHINE\new-SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU]
              "NoAutoUpdate"=dword:00000001
              "AUOptions"=dword:00000002
              "UseWUServer"=dword:00000001
            '';
            "oobeSystem.bat" = builtins.concatStringsSep "\n" [
              ''
                cd %USERPROFILE%\Desktop

                >oobeSystem.log 2>&1 (
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

                # Enable guest logon on smb
                powershell -Command "Set-SmbClientConfiguration -EnableInsecureGuestLogons $true -Force"
                powershell -Command "Set-SmbClientConfiguration -RequireSecuritySignature $false -Force"

                net use z: \\10.0.2.4\host

                echo > z:\share-works
              ''
              (lib.optionalString (testInstallation && disableWindowsUpdate) ''
                rem Ask Windows Updates to detect new updates
                net start wuauserv
                wuauclt.exe /detectnow
                net stop wuauserv
                net start wuauserv
                wuauclt.exe /detectnow
              '')
              ''
                cd %USERPROFILE%\Desktop

                ${handleInstallersByType {
                  arguments = package: "e:\\extra\\${package.installer.name} ${package.installer.arguments}";
                  bat = package: package.installer.bat "e:\\extra\\${package.installer.name}";
                  msi = package: "msiexec /i e:\\extra\\${package.installer.name} /quiet /passive /qn";
                  zip =
                    package:
                    ''"e:\tools\7-zip\7za.exe" x -y e:\\extra\\${package.installer.name} -o%USERPROFILE%\Desktop\${lib.strings.removeSuffix ".zip" package.installer.name}'';
                }}

                rem Uninstall OneDrive stuff
                OneDriveSetup.exe /uninstall

              ''
              (lib.optionalString runNgen ''
                rem ngen
                if exist %windir%\microsoft.net\framework\v4.0.30319\ngen.exe (
                        %windir%\microsoft.net\framework\v4.0.30319\ngen.exe update /force /queue
                        %windir%\microsoft.net\framework\v4.0.30319\ngen.exe executequeueditems
                )
                if exist %windir%\microsoft.net\framework64\v4.0.30319\ngen.exe (
                        %windir%\microsoft.net\framework64\v4.0.30319\ngen.exe update /force /queue
                        %windir%\microsoft.net\framework64\v4.0.30319\ngen.exe executequeueditems
                )
              '')
              ''
                rem Shrink the image
                dism.exe /online /Cleanup-Image /StartComponentCleanup /ResetBase

                rem Continue in PowerShell
                powershell -ExecutionPolicy Bypass -File e:\passes\oobeSystem\oobeSystem.ps1

              ''
              (lib.optionalString zeroOutFreeSpace ''
                rem Zero out free space to better compress the final image
                rem Make sure this is the last significant thing we do
                cd %USERPROFILE%\Desktop
                cd SysinternalsSuite
                sdelete.exe /accepteula -z c:
              '')
              ''
                cd %USERPROFILE%\Desktop

                mkdir summary
                cd summary

                mkdir file-lists
                cd file-lists
                cmd /c e:\passes\oobeSystem\list-all-drives.bat
                cd ..

                rem Export relevant parts of the registry
                mkdir registry
                cd registry
                reg export HKLM\SYSTEM\CurrentControlSet\Services services.reg
                reg export HKLM\SYSTEM\CurrentControlSet\Control\Power power.reg
                cd ..

                rem List all services
                sc query type= all state= all > services.txt 2>&1

                rem List running processes
                tasklist /FO CSV > processes.csv 2>&1
                tasklist /FO CSV /SVC > processes-with-services.csv 2>&1

                rem Dump all events
                mkdir events
                cd events
                rem Use a different cmd or it might terminate the parent script
                cmd /c e:\passes\oobeSystem\dump-all-events.bat
                cd ..

                rem "Dump Windows Update logs"
                powershell -Command "Get-WindowsUpdateLog -ForceFlush -LogPath .\windows-update.log -Confirm:$false"

                vssadmin list shadows > system-restore-points.txt

                cd ..
                )

                cd %USERPROFILE%\Desktop

                move c:\windows\system32\config\windowsPE.log summary\
                move oobeSystem.log summary\

                "e:\tools\7-zip\7za.exe" a summary.zip summary\

                move summary.zip z:\

                shutdown /s /t 0
              ''
            ];
            "oobeSystem/dump-all-events.bat" = ''
              @echo off
              setlocal EnableDelayedExpansion

              for /f "tokens=*" %%i in ('wevtutil el') do (
                set "log=%%i"
                set "file=!log:/=-!"
                wevtutil epl "!log!" "!file!.evtx"
              )

              endlocal
            '';
            "oobeSystem/list-all-drives.bat" = ''
              @echo off
              setlocal EnableDelayedExpansion

              REM Get list of drives (e.g., "Drives: C:\ D:\ E:\")
              for /f "tokens=1,*" %%A in ('fsutil fsinfo drives') do (
                  set DRIVES=%%B
              )

              REM Loop through each drive
              for %%D in (%DRIVES%) do (
                  set DRIVE=%%~D
                  set LETTER=!DRIVE:~0,1!
                  echo Listing !DRIVE! ...
                  dir /s /b !DRIVE! > !LETTER!.txt 2>nul
              )

              echo Done.
            '';
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
              # TODO: create file for each one of this and handle this with msi, bat and the others.
              ''
                ${handleInstallersByType {
                  ps1 = package: package.installer.ps1 "e:\\extra\\${package.installer.name}";
                }}
              ''
            ];
          };
          autounattendXML = pkgs.writeTextFile (
            let
              config = configuration.installation.autounattendXml;
            in
            {
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
                      ${config.diskConfiguration}
                      <UserData>
                        <AcceptEula>true</AcceptEula>
                        <FullName>${username}</FullName>
                        <Organization>Organization</Organization>
                        ${config.productKey}
                      </UserData>
                      <ImageInstall>
                        <OSImage>
                          <InstallTo>
                            <DiskID>0</DiskID>
                            <PartitionID>${builtins.toString config.installPartition}</PartitionID>
                          </InstallTo>
                          <WillShowUI>OnError</WillShowUI>
                          <InstallToAvailablePartition>false</InstallToAvailablePartition>
                          <InstallFrom>
                            <MetaData wcm:action="add">
                              <Key>/IMAGE/NAME</Key>
                              <Value>${config.imageName}</Value>
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
                        ${common.mapLines
                          (
                            { index, path }:
                            ''
                              <PathAndCredentials wcm:action="add" wcm:keyValue="${builtins.toString index}">
                                <Path>e:\drivers\${lib.replaceString "/" "\\" path}</Path>
                              </PathAndCredentials>
                            ''
                          )
                          (
                            lib.imap1 (index: path: {
                              index = index;
                              path = path;
                            }) driverPaths
                          )
                        }
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
            }
          );
          createFiles = (
            files:
            let
              dirs = builtins.map builtins.dirOf (builtins.attrNames files);
              mkdirs = common.mapLines (d: "mkdir -p ${d}/") dirs;

              fileDeriv =
                path: content:
                pkgs.writeTextFile {
                  name = builtins.baseNameOf path;
                  text = content;
                };

              cps = lib.concatStringsSep "\n" (
                lib.mapAttrsToList (path: content: "cp ${fileDeriv path content} ${path}") files
              );

            in
            lib.strings.concatStringsSep "\n" [
              mkdirs
              cps
            ]
          );
          expandCommand =
            action:
            (
              if action ? description && (builtins.stringLength action.description) > 0 then
                ''
                  echo "${action.description}"
                ''
              else
                ""
            )
            + (
              let
                qemuCommand = command: ''
                  echo "${command}" | socat - unix-connect:vm-working-directory/qemu-monitor.socket >& /dev/null
                '';
                vncDo = command: "vncdo --server 127.0.0.1::5900 ${command} >& /dev/null";
              in
              (
                if action.type == "sleep" then
                  ''
                    echo "Waiting for ${builtins.toString action.time} seconds"
                    sleep ${builtins.toString action.time}
                  ''
                else if action.type == "vncdo" then
                  ''
                    echo "Running vncdo ${action.arguments}"
                    ${vncDo action.arguments}
                  ''
                else if action.type == "change-floppy" then
                  ''
                    echo "Setting floppy to ${action.path}"
                    ${qemuCommand "change floppy0 ${action.path}"}
                    sleep 3
                  ''
                else if action.type == "quit" then
                  ''
                    echo "Quitting"
                    ${qemuCommand "quit"}
                  ''
                else if action.type == "wait-for" then
                  ''
                    echo 'Waiting for "${action.text}"'
                    (
                        while ! grep --quiet -i "${action.text}" image.txt >& /dev/null; do
                            rm -f image.txt image.png
                            if ${vncDo "capture image.png"}; then
                                tesseract image.png image >& /dev/null
                            fi
                        done
                        rm image.txt
                    )
                  ''
                else
                  (throw "Unknown command ${action.type}")
              )
            );
          installDrives = [
            "file=image${lib.optionalString configuration.vm.useVirtio ",if=virtio"},cache=writeback,discard=unmap,detect-zeroes=unmap,format=qcow2"
          ]
          ++ (lib.optionals (!(builtins.isNull configuration.installation.iso)) [
            "media=cdrom,index=2,file=unattended.iso"
            "media=cdrom,index=0,file=${configuration.installation.iso}"
          ])
          ++ (lib.optionals (!(builtins.isNull configuration.installation.floppy)) [
            "format=raw,if=floppy,file=${configuration.installation.floppy},readonly=on"
          ]);
          runQemuScript =
            {
              drives,
              extraArguments ? [ ],
              useSpice ? false,
              background ? false,
            }:
            let
              allDrives =
                drives
                ++ (lib.optionals configuration.vm.useEFI [
                  "if=pflash,format=raw,unit=0,file=$SCRIPT_DIR/efi/OVMF_CODE.fd,readonly=on"
                  "if=pflash,format=raw,unit=1,file=$SCRIPT_DIR/efi/OVMF_VARS.fd"
                ]);
            in
            ''
              SCRIPT_DIR=$( cd -- "$( dirname -- "''${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

              set -euo pipefail

              WORKING_DIRECTORY="$SCRIPT_DIR/vm-working-directory"

              SHARE="$SCRIPT_DIR/share"

              function log() {
                echo "$1" > /dev/stderr
              }

              function fail() {
                log "$1"
                exit 1
              }

              function ensure-command() {
                COMMAND="$1"
                shift
                if ! command -v "$COMMAND" > /dev/null; then
                  fail "$COMMAND not available"
                fi
              }

              function wait-for() {
                while ! "$@" >& /dev/null; do
                  sleep 0.5
                done
              }

              function available-port() {
                python -c 'import socket; s = socket.socket(); s.bind(("", 0)); print(s.getsockname()[1]); s.close()'
              }

              if test -e "$WORKING_DIRECTORY"; then
                PID_FILE="$WORKING_DIRECTORY/qemu.pid"
                if test -e "$PID_FILE" && test -e /proc/"$(cat $PID_FILE)"; then
                  fail "The VM seems to be already running"
                else
                  fail "It seems like $WORKING_DIRECTORY is stale"
                fi
              fi

              mkdir -p "$WORKING_DIRECTORY"

              ensure-command qemu-system-${configuration.vm.architecture}

              ${lib.optionalString useSpice ''
                ensure-command spicy
                ensure-command nc
              ''}

              ${lib.optionalString (needsSamba || useSpice) ''
                ensure-command python
              ''}

              ${lib.optionalString needsSamba ''
                SAMBA_PORT1=$(available-port)
                SAMBA_PORT2=$(available-port)

                if ! command -v smbd > /dev/null; then
                  log "Warning: smbd not available, disabling the share"
                else
                  log "Launching samba"

                  (
                    # We need to cd or samba will complain about file names too long
                    SHARE=$(realpath "$SHARE")
                    mkdir -p "$SHARE"
                    cd "$WORKING_DIRECTORY"
                    mkdir -p smb
                    mkdir -p smb/private

                    cat > smb/smb.conf <<EOF
                [global]
                interfaces=127.0.0.1
                bind interfaces only=yes
                pid directory=smb
                lock directory=smb
                state directory=smb
                cache directory=smb
                ncalrpc dir=smb/ncalrpc
                smb passwd file=smb/smbpasswd
                private dir=smb/private
                log file=smb/smbd.log
                security = user
                map to guest = Bad User
                load printers = no
                printing = bsd
                disable spoolss = yes
                usershare max shares = 0
                smb ports = $SAMBA_PORT1, $SAMBA_PORT2

                [host]
                path=$SHARE
                read only=no
                guest ok=yes
                force user=''${USER:-nixbld}
                EOF

                    smbd --daemon --debuglevel 1 --configfile="smb/smb.conf" >& /dev/null
                  )
                fi
              ''}

              ${lib.optionalString useSpice ''
                SPICE_PORT=$(available-port)
                echo "$SPICE_PORT" > "$WORKING_DIRECTORY"/spice-port

                (
                  wait-for nc -z -w 1 127.0.0.1 "$SPICE_PORT"

                  spicy \
                    --title "VM" \
                    --port "$SPICE_PORT" \
                    --spice-shared-dir "$SHARE" >& /dev/null
                ) &
              ''}

              log "Launching QEMU"
              ${lib.optionalString (!background) ''
                # We exec so `time` collects data about the correct process

                TO_WAIT="$$"
                (
                  cd /
                  waitpid "$TO_WAIT"
                  rm -rf "$WORKING_DIRECTORY"
                ) &

                exec \
              ''}
                qemu-system-${configuration.vm.architecture} \
                -name qemu-windows-install,process=qemu-windows-install \
                -machine ${configuration.vm.machine},hpet=off,smm=on,vmport=off,accel=kvm \
                -global kvm-pit.lost_tick_policy=discard \
                -global ICH9-LPC.disable_s3=1 \
                -cpu host,+hypervisor,+invtsc,l3-cache=on,migratable=no,hv_passthrough \
                ${lib.optionalString configuration.vm.useVirtio "-device virtio-balloon"} \
                -rtc base=localtime,clock=host,driftfix=slew \
                -cpu ${configuration.vm.cpu} \
                -smp ${builtins.toString (min cpus configuration.vm.maxCpus)} \
                -m ${builtins.toString (min memory configuration.vm.maxMemory)}M \
                -monitor unix:"$(realpath --relative-to="$PWD" "$WORKING_DIRECTORY/qemu-monitor.socket")",server,nowait \
                -pidfile "$WORKING_DIRECTORY/qemu.pid" \
                \
                -netdev "user,id=user.0${lib.optionalString needsSamba ",guestfwd=tcp:10.0.2.4:445-cmd:nc 127.0.0.1 $SAMBA_PORT1,guestfwd=tcp:10.0.2.4:139-cmd:nc 127.0.0.1 $SAMBA_PORT2"}${lib.optionalString configuration.vm.network.useIPv6 ",ipv6=off"}" \
                -device ${configuration.vm.network.model},netdev=user.0 \
                ${lib.optionalString useSpice ''
                  -vga none \
                  -display none \
                  -device qxl-vga,xres=1280,yres=800,ram_size=65536,vram_size=65536,vgamem_mb=64 \
                  ${lib.optionalString configuration.vm.useVirtio ''
                    -device virtio-serial-pci \
                    \
                    -chardev socket,id=agent0,path="$(realpath --relative-to="$PWD" "$WORKING_DIRECTORY/qemu-agent.socket")",server=on,wait=off \
                    -device virtserialport,chardev=agent0,name=org.qemu.guest_agent.0 \
                    \
                    -chardev spicevmc,id=vdagent0,name=vdagent \
                    -device virtserialport,chardev=vdagent0,name=com.redhat.spice.0 \
                    \
                    -chardev spiceport,id=webdav0,name=org.spice-space.webdav.0 \
                    -device virtserialport,chardev=webdav0,name=org.spice-space.webdav.0 \
                  ''} \
                  -spice disable-ticketing=on,port="$SPICE_PORT",addr=127.0.0.1 \
                  -device qemu-xhci,id=spicepass \
                  \
                  -chardev spicevmc,id=usbredirchardev1,name=usbredir \
                  -device usb-redir,chardev=usbredirchardev1,id=usbredirdev1 \
                  \
                  -chardev spicevmc,id=usbredirchardev2,name=usbredir \
                  -device usb-redir,chardev=usbredirchardev2,id=usbredirdev2 \
                  \
                  -chardev spicevmc,id=usbredirchardev3,name=usbredir \
                  -device usb-redir,chardev=usbredirchardev3,id=usbredirdev3 \
                  \
                  -device pci-ohci,id=smartpass \
                  -device usb-ccid \
                  \
                  -chardev spicevmc,id=ccid,name=smartcard \
                  -device ccid-card-passthru,chardev=ccid \
                  \
                  -device usb-ehci,id=input \
                  -k en-us \
                  ${lib.optionalString configuration.vm.useUSBKeyboard ''
                    -device usb-kbd,bus=input.0 \
                    -device usb-tablet,bus=input.0 \
                  ''} \
                ''} \
                ${lib.escapeShellArgs extraArguments} \
                ${
                  builtins.concatStringsSep " \\\n" (
                    builtins.map (
                      # Do not escape, we want to use $SCRIPT_DIR
                      entry: ''-drive "${entry}"''
                    ) allDrives
                  )
                } \
                "$@" \
              ${lib.optionalString background ''
                &

                TO_WAIT="$!"
                (
                  cd /
                  waitpid "$TO_WAIT"
                  rm -rf "$WORKING_DIRECTORY"
                ) &
              ''}

              # Do not do anything here! We exec'd!
            '';
          vmCommandBuilder =
            options:
            let
              mapCommands =
                handler: common.mapLines (name: handler name options.${name}) (builtins.attrNames options);
            in
            pkgs.writeTextFile {
              name = name;
              executable = true;
              text = ''
                #!/usr/bin/env bash

                SCRIPT_DIR=$( cd -- "$( dirname -- "''${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
                set -euo pipefail

                PID_FILE="$SCRIPT_DIR/vm-working-directory/qemu.pid"

                function log() {
                  echo "$1" > /dev/stderr
                }

                function fail() {
                  log "$1"
                  exit 1
                }

                function qemu-monitor() {
                  (
                    # Socket names have a maximum length of 108 bytes
                    cd "$SCRIPT_DIR/vm-working-directory"
                    socat - unix-connect:./qemu-monitor.socket
                  )
                }

                usage() {
                  cat <<EOF
                Usage: $0 <command> [options]

                Commands:

                ${mapCommands (
                  name: command:
                  name + (lib.strings.replicate (12 - (builtins.stringLength name)) " ") + command.description
                )}
                EOF
                }

                ${mapCommands (
                  name: command:
                  let
                    waitForExit = if builtins.hasAttr "waitForExit" command then command.waitForExit else false;
                    mustBeRunning =
                      if builtins.hasAttr "mustBeRunning" command then
                        command.mustBeRunning
                      else if waitForExit then
                        "yes"
                      else
                        "dontcare";
                    requirements = command.requirements ++ (lib.optionals waitForExit [ "waitpid" ]);
                  in
                  ''
                    function ${name}() {
                    ${common.mapLines (requirement: ''
                      if ! command -v "${requirement}" > /dev/null; then
                        fail "${requirement} not available"
                      fi
                    '') requirements}

                    ${lib.optionalString (mustBeRunning == "yes") ''
                      if ! test -e "$PID_FILE"; then
                        log "No PID file found"
                        fail "The VM is not running."
                      fi

                      PID=$(cat "$PID_FILE")
                      if ! test -e /proc/"$PID"; then
                        fail "PID $PID does not exist. The VM is not running."
                      fi
                    ''}

                    ${lib.optionalString (mustBeRunning == "no") ''
                      if test -e "$PID_FILE"; then
                        PID=$(cat "$PID_FILE")
                        if test -e /proc/"$PID"; then
                          fail "PID $PID is running. The VM is running."
                        else
                          fail "Stale PID file found."
                        fi
                      fi
                    ''}

                    ${command.body}

                    ${lib.optionalString waitForExit ''
                      log "Waiting for QEMU process to terminate ($PID)"
                      waitpid "$PID"
                    ''}
                    }
                  ''
                )}

                function main() {

                  if test "$#" -lt 1; then
                    usage
                    exit
                  fi

                  local command="$1"
                  shift

                  case "$command" in
                  ${mapCommands (
                    name: command: ''
                      ${name})
                        ${name} "$@"
                        exit 0
                        ;;
                    ''
                  )}
                    *)
                      echo "Unknown command: $command" >&2
                      usage
                      exit 1
                      ;;
                  esac
                }

                main "$@"
              '';
            };
          vmCommand = vmCommandBuilder {

            start = {
              description = "Start the VM.";
              mustBeRunning = "no";
              requirements = [ "kill" ];
              body =
                "(\n"
                + (runQemuScript {
                  drives = [
                    "file=$SCRIPT_DIR/image.qcow2${lib.optionalString configuration.vm.useVirtio ",if=virtio"},cache=writeback,discard=unmap,detect-zeroes=unmap,format=qcow2"
                  ];
                  useSpice = true;
                  background = true;
                })
                + "\n)";
            };

            kill = {
              description = "Kill the QEMU process.";
              waitForExit = true;
              requirements = [ "kill" ];
              body = ''
                log "Killing $PID"
                $(which kill) "$@" "$PID"
              '';
            };

            poweroff = {
              description = "Send the VM a request for shutdown (QEMU's system_powerdown command).";
              waitForExit = true;
              requirements = [ "socat" ];
              body = ''
                log "Sending system_powerdown command to QEMU"
                echo "system_powerdown" | qemu-monitor >& /dev/null
              '';
            };

            quit = {
              description = "Ask QEMU to quit now (QEMU's quit command).";
              waitForExit = true;
              requirements = [ "socat" ];
              body = ''
                log "Sending quit command to QEMU"
                echo "quit" | qemu-monitor >& /dev/null
              '';
            };

            reset = {
              description = "Reset the VM (QEMU's reset command).";
              mustBeRunning = "yes";
              requirements = [ "socat" ];
              body = ''
                log "Sending system_powerdown command to QEMU"
                echo "system_reset" | qemu-monitor >& /dev/null
              '';
            };

            monitor = {
              description = "Connect to the QEMU monitor";
              mustBeRunning = "yes";
              requirements = [ "socat" ];
              body = ''
                qemu-monitor
              '';
            };

            status = {
              description = "Shows the status of the vm";
              mustBeRunning = "yes";
              requirements = [ ];
              body = ''
                log "The VM is running"
              '';
            };

            ui = {
              description = "Connect to the VM via spice.";
              mustBeRunning = "yes";
              requirements = [ "spicy" ];
              body = ''
                spicy \
                  --title "VM" \
                  --port "$(cat "$SCRIPT_DIR/vm-working-directory/spice-port")" \
                  --spice-shared-dir "$SCRIPT_DIR/share" \
                  "$@" \
                  >& /dev/null &
              '';
            };

            mount = {
              description = "Mount the VM image";
              mustBeRunning = "no";
              requirements = [
                "modprobe"
                "qemu-nbd"
                "mount"
                "mountpoint"
                "umount"
                "sed"
                "file"
                "ls"
              ];
              body = ''
                function find_free_nbd_device() {
                    for INDEX in $(seq 0 15); do
                        if ! test -e /sys/class/block/nbd"$INDEX"/pid; then
                            echo "$INDEX"
                            return
                        fi
                    done

                    fail "No /dev/nbd device available!"
                }

                if test "$(id -u)" -ne 0; then
                    fail "Run this command as root"
                fi

                if ! test -e /dev/nbd0; then
                    log ""
                    modprobe nbd
                fi

                NBD_DEVICE="/dev/nbd$(find_free_nbd_device)"
                log "Exposing image.qcow2 to $NBD_DEVICE"
                qemu-nbd --connect "$NBD_DEVICE" -f qcow2 "image.qcow2"

                log "Waiting for partitions to be recognized"
                sleep 1

                shopt -s nullglob

                for PARTITION in "$NBD_DEVICE"p*; do
                    SUFFIX=$(echo "$PARTITION" | sed 's|'"$NBD_DEVICE"'||')
                    mkdir -p "$SUFFIX"
                    log "Mounting read-only $PARTITION to $SUFFIX"
                    if ! $(which mount) -o ro "$PARTITION" "$SUFFIX" >& /dev/null; then
                        log "Couldn't mount $PARTITION: $(file -s "$PARTITION")"
                    fi
                done

                log "Press any key to unmount"
                read

                qemu-nbd --disconnect "$NBD_DEVICE" >& /dev/null

                for PARTITION in "$NBD_DEVICE"p*; do
                    SUFFIX=$(echo "$PARTITION" | sed 's|'"$NBD_DEVICE"'||')
                    log "Removing $SUFFIX"
                    if mountpoint "$SUFFIX" >& /dev/null; then
                        umount "$SUFFIX"
                    fi
                    rmdir "$SUFFIX"
                done

                log "All done"
              '';

            };

          };

        in
        ''
          set -euo pipefail

          function log() {
            echo "$1" > /dev/stderr
          }

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

          function time-task() {
            OUTPUT_FILE="$1"
            shift

            "time" \
              -f '{"exit_code": %x, "time_user_seconds": %U, "time_system_seconds": %S, "time_wall_clock_seconds": %e, "rss_max_kbytes": %M, "rss_avg_kbytes": %t, "page_faults_major": %F, "page_faults_minor": %R, "io_inputs": %I, "io_outputs": %O, "context_switches_voluntary": %w, "context_switches_involuntary": %c, "cpu_percentage": "%P", "signals_received": %k}' \
              --output >(jq > "$OUTPUT_FILE") \
              "$@"

          }

          ${
            # Do not prepare the ISO, if we're not installing from an ISO
            lib.optionalString (!builtins.isNull configuration.installation.iso) ''
              log "Preparing unattended.iso file"
              mkdir unattended
              pushd unattended > /dev/null

              ${lib.optionalString hasAutounattendXml ''
                cp -a ${autounattendXML} Autounattend.xml
              ''}

              mkdir extra
              pushd extra > /dev/null
              ${handleInstallers (package: "cp -a ${package.installer.package} ${package.installer.name}")}
              popd > /dev/null

              ${lib.optionalString hasAutounattendXml ''
                mkdir passes
                pushd passes > /dev/null
                ${createFiles passes}
                popd > /dev/null
              ''}

              # Extract in drivers all the w11 drivers.
              # Autounattend.xml will direct the Windows setup to recursively
              # scan e:\drivers
              mkdir drivers
              pushd drivers > /dev/null
              cp -ar "${drivers}/"* .
              popd > /dev/null

              mkdir tools
              pushd tools > /dev/null

              mkdir 7-zip > /dev/null
              pushd 7-zip > /dev/null
              quiet 7z x ${
                pkgs.fetchurl {
                  url = "https://www.7-zip.org/a/7z2501-extra.7z";
                  sha256 = "sha256-zTzzgIXCzGg5z3Jxba+zF1rkJfT9NPqvxsC2TWGNMH8=";
                }
              } x64
              mv x64/* .
              popd > /dev/null

              popd > /dev/null

              popd > /dev/null

              log "Assembling unattended.iso"
              mkisofs -quiet -R -J -o "unattended.iso" "unattended/"
            ''
          }

          ${lib.optionalString configuration.vm.useEFI ''
            log "Creating EFI variables file"
            mkdir efi
            cp ${pkgs.OVMF.fd}/FV/OVMF_VARS.fd efi/
            cp ${pkgs.OVMF.fd}/FV/OVMF_CODE.fd efi/
            chmod u+w efi/OVMF_VARS.fd
          ''}

          TO_WAIT=()

          ${lib.optionalString recordInstallation (''
            log "Launching a virtual X instance with VNC and ffmpeg recording from it"
            (
              xvfb-run --server-args='-screen 0 1920x1080x24' ${pkgs.writeShellScript "record" ''
                set -euo pipefail

                function wait-for() {
                  while ! "$@" >& /dev/null; do
                    sleep 0.5
                  done
                }

                # Wait for QEMU to start before connecting to VNC
                wait-for nc -z -w 1 127.0.0.1 5900

                (
                  # Wait for vncviewer to start, before querying the features of its window
                  WINDOW_NAME="QEMU (qemu-windows-install) - TigerVNC"
                  wait-for xwininfo -name "$WINDOW_NAME"

                  WINDOW_POSITION=$(
                    xwininfo -name "$WINDOW_NAME" | \
                      gawk 'match($0, /-geometry ([0-9]+x[0-9]+).([0-9]+).([0-9]+)/, a) { print "-video_size " a[1] " -i +" a[2] "," a[3] }'
                  )

                  # Record VNC output, convert it to YUV4MPEG2 and then use ffmpeg to produce a lossless AV1 video
                  ffmpeg \
                    -f x11grab \
                    -framerate 25 \
                    $WINDOW_POSITION \
                    recording.mkv
                ) &
                FFMPEG_JOB="$!"

                vncviewer -Shared 127.0.0.1:5900

                # Stop recording with ffmpeg
                pkill -INT ffmpeg

                wait "$FFMPEG_JOB"
              ''}
            ) &
            # We must wait for ffmpeg to be done
            TO_WAIT+=( "$!" )
          '')}


          ${lib.optionalString ((builtins.length configuration.installation.commands) > 0) ''
            log "Launching script to interact with the VM via VNC"
            (
              ${common.mapLines expandCommand configuration.installation.commands}
            ) &
            # No need to wait for this to terminate
          ''}

          mkdir -p output/share/vm
          mkdir summary

          mkdir timing

          cp ${vmCommand} asdf

          log "Preparing disk image"
          quiet \
            time-task "timing/image-creation.json" \
            qemu-img \
            create \
            -f qcow2 \
            -o compat=1.1 \
            image \
            ${builtins.toString (min diskSize configuration.vm.maxDiskSize)}M

          # The script does things relative to its path, it's important to copy it
          cp -a ${
            pkgs.writeShellScript "run-qemu" (runQemuScript {
              drives = installDrives;
              extraArguments = [
                "-vnc"
                "127.0.0.1:0"
                "-boot"
                "once=d"
              ];
            })
          } install

          time-task "timing/install.json" bash ./install

          if test "''${#TO_WAIT[@]}" -gt 0; then
            log "Waiting for ''${#TO_WAIT[@]} jobs"
            wait "''${TO_WAIT[@]}"
          fi

          ${lib.optionalString configuration.installation.emitsSummary ''
            log "Collecting installation summary"
            mv share/summary.zip .
            rm -rf share

            unzip -q summary.zip

            mv timing summary/

            cd summary

            ${lib.optionalString testInstallation ''
              log "Running tests"
              ${pkgs.writeShellScript "run-tests" ''
                set -euo pipefail

                RESULT=0

                function log() {
                  echo "$1" > /dev/stderr
                }

                function test_check() {
                  MESSAGE="$1"
                  shift

                  if "$@"; then
                    echo "✅ $MESSAGE" > /dev/stderr
                  else
                    echo "❌ $MESSAGE" > /dev/stderr
                    RESULT=1
                  fi
                }

                function test_service_state() {
                  SERVICE_NAME="$1"
                  shift
                  EXPECTED_STATE="$1"
                  shift

                  test_check \
                    "Service $SERVICE_NAME is in state $EXPECTED_STATE" \
                    test "$(grep -i -A10 'SERVICE_NAME: '"$SERVICE_NAME" services.txt  | grep STATE | head -n1 | grep "$EXPECTED_STATE" | wc -l)" -eq 1
                }

                function test_service_available() {
                  SERVICE_NAME="$1"
                  shift

                  test_check \
                    "Service $SERVICE_NAME is available" \
                    test "$(grep -i 'SERVICE_NAME: '"$SERVICE_NAME" services.txt | wc -l)" -eq 1
                }

                function test_log_contains() {
                  WHERE="$1"
                  shift

                  WHAT="$1"
                  shift

                  test_check \
                    "Checking $WHERE contains \"$WHAT\"" \
                    test "$(grep "$WHAT" "$WHERE" | wc -l)" -ge 1
                }

                function file_exists() {
                  DRIVE="$1"
                  shift
                  TARGET_PATH="$1"
                  shift

                  test_check \
                    "Checking if $TARGET_PATH exists in $DRIVE" \
                    test "$(grep -i "$TARGET_PATH" file-lists/"$DRIVE".txt | wc -l)" -ge 1
                }

                test_log_contains windowsPE.log "All done!"

                ${lib.optionalString hasAutounattendXml ''
                  for SERVICE_NAME in ${lib.escapeShellArgs configuration.installation.autounattendXml.servicesToDisable}; do
                    test_service_state "$SERVICE_NAME" "STOPPED"
                  done
                ''}

                ${handleInstallers (
                  package: if !builtins.isNull package.installer.test then package.installer.test else ""
                )}

                ${lib.optionalString disableWindowsUpdate ''
                  test_log_contains windows-update.log "127.6.6.6"
                ''}

                test_log_contains system-restore-points.txt "No items found"

                exit "$RESULT"
              ''}  |& tee test-results.log''}

            cd ..

            mv summary output/share/vm/

            du -hs . >> output/share/vm/summary/disk-space.txt
            du -hs image >> output/share/vm/summary/disk-space.txt
          ''}

          ${
            if compressDiskImage then
              ''
                log "Rewriting disk image to compress it"
                time-task "timing/compress.json" \
                  qemu-img \
                  convert \
                  -c \
                  -o compat=1.1 \
                  -O qcow2 \
                  image \
                  output/share/vm/image.qcow2
              ''
            else
              ''
                mv image output/share/vm/image.qcow2
              ''
          }

          ${lib.optionalString configuration.installation.emitsSummary ''
            du -hs output/share/vm/image.qcow2 >> output/share/vm/summary/disk-space.txt
          ''}

          ${lib.optionalString recordInstallation ''
            ${lib.optionalString configuration.installation.emitsSummary ''
              du -hs recording.mkv >> output/share/vm/summary/disk-space.txt
            ''}
              mv recording.mkv output/share/vm
          ''}

          mkdir output/share/vm/share
          touch output/share/vm/share/THIS-DIRECTORY-IS-SHARED-WITH-THE-HOST

          ${lib.optionalString configuration.vm.useEFI ''
            mv efi/ output/share/vm/
          ''}

          cp -a ${vmCommand} output/share/vm/vm

          mkdir -p output/bin
          cp -a ${pkgs.writeShellScript "prepare-vm" ''
            SCRIPT_DIR=$( cd -- "$( dirname -- "''${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
            set -euo pipefail
            cp -ar --reflink=auto "$SCRIPT_DIR/../share/vm" .
            chmod u+w --recursive vm
          ''} output/bin/prepare-vm

          log "All done!"
        '';

      installPhase = ''
        mkdir -p "$out"
        mv output/* "$out/"
      '';

      dontFixup = true;
    };
in
{
  options = with lib; {
    output = mkOption {
      type = types.package;
      description = "The output Windows image";
    };
  };
  config.output = windowsImage userConfiguration;
}
