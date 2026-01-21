{
  pkgs,
  config,
  userConfiguration,
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
      debloat,
      timeZone,
      computerName,
      username,
      password,
      recordInstallation,
      testInstallation,
      runNgen,
    }:
    let
      configuration = config.systems."${version}";
      needsSamba = configuration.emitsSummary;
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

              ${lib.optionalString ((builtins.length configuration.autounattendXml.servicesToDisable) > 0) ''
                start /min cmd.exe /c ">x:\windowsPE.log 2>&1 ( cscript.exe //E:vbscript e:\passes\windowsPE\disable-services.vbs )"
              ''}

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

              ${builtins.concatStringsSep "\n" (
                builtins.map (serviceName: ''
                  [HKEY_LOCAL_MACHINE\new-SYSTEM\ControlSet001\Services\${serviceName}]
                  "Start"=dword:00000004
                '') configuration.autounattendXml.servicesToDisable
              )}

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

                cd %USERPROFILE%\Desktop

                e:\extra\Git-64-bit.exe /VERYSILENT /NORESTART /NOCANCEL /SP- /CLOSEAPPLICATIONS /RESTARTAPPLICATIONS /COMPONENTS="icons,ext\reg\shellhere,assoc,assoc_sh"
                e:\extra\systeminformer-release-setup.exe -silent
                e:\extra\firefox-installer.exe /S

                rem Chromium installer needs to write things in the installer directory
                copy e:\extra\chromium-installer.exe .
                start /wait chromium-installer.exe
                del chromium-installer.exe

                msiexec /i e:\extra\npp.Installer.x64.msi /quiet /passive /qn
                msiexec /i e:\extra\chocolatey.msi /quiet /passive /qn
                msiexec /i e:\extra\Everything.x64.msi /quiet /passive /qn
                msiexec /i e:\extra\7z-x64.msi /quiet /passive /qn

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
              (lib.optionalString (testInstallation && disableWindowsUpdate) ''
                rem Ask Windows Updates to detect new updates
                wuauclt.exe /detectnow
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

                cd ..
                )

                cd %USERPROFILE%\Desktop

                move c:\windows\system32\config\windowsPE.log summary\
                move oobeSystem.log summary\

                "C:\Program Files\7-Zip\7z.exe" a summary.zip summary\

                net use z: \\10.0.2.4\host

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
              ''
                # Enable guest logon on smb
                Set-SmbClientConfiguration -EnableInsecureGuestLogons $true -Force
                Set-SmbClientConfiguration -RequireSecuritySignature $false -Force
              ''
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
              (lib.optionalString debloat ''
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
          autounattendXML = pkgs.writeTextFile (
            let
              config = configuration.autounattendXml;
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
                        <PathAndCredentials wcm:action="add" wcm:keyValue="1">
                          <Path>e:\drivers\fwcfg\w11\amd64</Path>
                        </PathAndCredentials>
                        <PathAndCredentials wcm:action="add" wcm:keyValue="2">
                          <Path>e:\drivers\vioinput\w11\amd64</Path>
                        </PathAndCredentials>
                        <PathAndCredentials wcm:action="add" wcm:keyValue="3">
                          <Path>e:\drivers\vioscsi\w11\amd64</Path>
                        </PathAndCredentials>
                        <PathAndCredentials wcm:action="add" wcm:keyValue="4">
                          <Path>e:\drivers\viostor\w11\amd64</Path>
                        </PathAndCredentials>
                        <PathAndCredentials wcm:action="add" wcm:keyValue="5">
                          <Path>e:\drivers\vioserial\w11\amd64</Path>
                        </PathAndCredentials>
                        <PathAndCredentials wcm:action="add" wcm:keyValue="7">
                          <Path>e:\drivers\viorng\w11\amd64</Path>
                        </PathAndCredentials>
                        <PathAndCredentials wcm:action="add" wcm:keyValue="8">
                          <Path>e:\drivers\NetKVM\w11\amd64</Path>
                        </PathAndCredentials>
                        <PathAndCredentials wcm:action="add" wcm:keyValue="9">
                          <Path>e:\drivers\viofs\w11\amd64</Path>
                        </PathAndCredentials>
                        <PathAndCredentials wcm:action="add" wcm:keyValue="10">
                          <Path>e:\drivers\Balloon\w11\amd64</Path>
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
            }
          );
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
              url = "https://storage.googleapis.com/chromium-browser-snapshots/Win_x64/1572379/mini_installer.exe";
              sha256 = "sha256-wrr7tt8zEzgPyxRsFwXGjGvWSS+cfQN/VThFpSVxYlg=";
              name = "chromium-installer.exe";
            }
            {
              url = "https://www.voidtools.com/Everything-1.4.1.1030.x64.msi";
              sha256 = "sha256-W/8tukbHGDi4lm00C6NqGB+wDM1cvaRZADcR64B2jIk=";
              name = "Everything.x64.msi";
            }
            {
              url = "https://7-zip.org/a/7z2501-x64.msi";
              sha256 = "sha256-5+sLftXvpOCHt7F/GReX969bf0QtEpDGbzohd3AF71c=";
              name = "7z-x64.msi";
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
            lib.concatStringsSep "\n" fetchUrls;
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
              if action ? description then
                ''
                  echo "${action.description}"
                ''
              else
                ""
            )
            + (
              let
                qemuCommand = command: ''
                  echo "${command}" | socat - unix-connect:qemu-monitor.socket >& /dev/null
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
                  "${vncDo action.arguments}"
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
                                tesseract image.png image
                                cat image.txt
                            fi
                        done
                        rm image.txt
                    )
                  ''
                else
                  (throw "Unknown command ${action.type}")
              )
            );
          qemuDrives = [
            "file=image,if=virtio,cache=writeback,discard=unmap,detect-zeroes=unmap,format=qcow2"
          ]
          ++ (lib.optionals (!(builtins.isNull configuration.iso)) [
            "media=cdrom,index=2,file=unattended.iso"
            "media=cdrom,index=0,file=${configuration.iso}"
          ])
          ++ (lib.optionals (!(builtins.isNull configuration.floppy)) [
            "format=raw,if=floppy,file=${configuration.floppy},readonly=on"
          ])
          ++ (lib.optionals configuration.useEFI [
            "if=pflash,format=raw,unit=0,file=${pkgs.OVMF.fd}/FV/OVMF_CODE.fd,readonly=on"
            "if=pflash,format=raw,unit=1,file=./OVMF_VARS.fd"
          ]);
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

          ${
            # Do not prepare the ISO, if we're not installing from an ISO
            lib.optionalString (!builtins.isNull configuration.iso) ''
              log "Preparing unattended.iso file"
              mkdir unattended
              pushd unattended > /dev/null

              ${lib.optionalString (!builtins.isNull configuration.autounattendXml) ''
                cp -a ${autounattendXML} Autounattend.xml
              ''}

              mkdir extra
              pushd extra > /dev/null
              ${copyUrls extraFiles}
              popd > /dev/null

              ${lib.optionalString (!builtins.isNull configuration.autounattendXml) ''
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
              quiet 7z x ${virtioIsoPath} $(7z l ${virtioIsoPath}  | grep w11 | grep -i amd64 | grep -F D.... | awk '{ print $4 }')
              popd > /dev/null

              quiet 7z x ${virtioIsoPath} guest-agent/qemu-ga-x86_64.msi
              mv guest-agent/qemu-ga-x86_64.msi extra/
              rmdir guest-agent

              mkdir spice-drivers
              pushd spice-drivers > /dev/null
              quiet 7z x ../extra/spice-guest-tools.exe drivers/vioserial/w10/amd64/vioser.cat
              (
                openssl pkcs7 -inform der -in drivers/vioserial/w10/amd64/vioser.cat -print_certs | \
                  grep Red -A1000 | \
                  grep -m1 'END CERTIFICATE' -B 10000 | \
                  openssl x509 -inform pem -outform der \
                  > ../drivers/redhat-certificate.der \
                  || true
              ) >& /dev/null
              test -s ../drivers/redhat-certificate.der
              popd > /dev/null
              rm -rf spice-drivers

              popd > /dev/null

              log "Assembling unattended.iso"
              mkisofs -quiet -R -J -o "unattended.iso" "unattended/"
            ''
          }

          ${lib.optionalString configuration.useEFI ''
            log "Creating EFI variables file"
            cp ${pkgs.OVMF.fd}/FV/OVMF_VARS.fd .
            chmod u+w OVMF_VARS.fd
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


          ${lib.optionalString ((builtins.length configuration.commands) > 0) ''
            log "Launching script to interact with the VM via VNC"
            (
              ${lib.concatStringsSep "\n" (builtins.map expandCommand configuration.commands)}
            ) &
            # No need to wait for this to terminate
          ''}

          mkdir -p output/share/windows-vm
          mkdir summary

          log "Preparing disk image"
          quiet \
            qemu-img \
            create \
            -f qcow2 \
            -o compat=1.1 \
            image \
            ${builtins.toString (min diskSize configuration.maxDiskSize)}M

          ${lib.optionalString needsSamba ''
            log "Launching samba"
            (
              mkdir -p /build/smb
              mkdir -p /build/smb/private
              smbd --daemon --debuglevel 1 --configfile=${
                pkgs.writeTextFile {
                  name = "smb.conf";
                  text = ''
                    [global]
                    interfaces=127.0.0.1
                    bind interfaces only=yes
                    pid directory=/build/smb
                    lock directory=/build/smb
                    state directory=/build/smb
                    cache directory=/build/smb
                    ncalrpc dir=/build/smb/ncalrpc
                    smb passwd file=/build/smb/smbpasswd
                    private dir=/build/smb/private
                    log file=/build/smb/smbd.log
                    security = user
                    map to guest = Bad User
                    load printers = no
                    printing = bsd
                    disable spoolss = yes
                    usershare max shares = 0
                    smb ports = 8445, 8139

                    [host]
                    path=/build/summary
                    read only=no
                    guest ok=yes
                    force user=nixbld
                  '';
                }
              } >& /dev/null

              # In case of debugging:
              # tail -f /build/smb/smbd.log
            ) &
            # No need to wait for this to terminate
          ''}

          log "Launching QEMU"
          qemu-system-${configuration.qemuArchitecture} \
            -name qemu-windows-install,process=qemu-windows-install \
            -machine q35,accel=kvm \
            -cpu ${configuration.cpu} \
            -smp ${builtins.toString (min cpus configuration.maxCpus)} \
            -m ${builtins.toString (min memory configuration.maxMemory)}M \
            -monitor unix:qemu-monitor.socket,server,nowait \
            -device virtio-net,netdev=user.0 \
            -netdev 'user,id=user.0${lib.optionalString needsSamba ",guestfwd=tcp:10.0.2.4:445-cmd:nc 127.0.0.1 8445,guestfwd=tcp:10.0.2.4:139-cmd:nc 127.0.0.1 8139"}' \
            -vnc 127.0.0.1:0 \
            -boot once=d \
            ${builtins.concatStringsSep " \\\n" (
              builtins.map (
                entry:
                lib.escapeShellArgs [
                  "-drive"
                  entry
                ]
              ) qemuDrives
            )}

          if test "''${#TO_WAIT[@]}" -gt 0; then
            log "Waiting for ''${#TO_WAIT[@]} jobs"
            wait "''${TO_WAIT[@]}"
          fi

          ${lib.optionalString configuration.emitsSummary ''
            log "Collecting installation summary"
            mv summary/summary.zip .
            rm -rf summary

            unzip -q summary.zip

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

                test_service_state "QEMU-GA" "RUNNING"
                test_service_available "vdservice"

                for SERVICE_NAME in ${lib.escapeShellArgs configuration.autounattendXml.servicesToDisable}; do
                  test_service_state "$SERVICE_NAME" "STOPPED"
                done

                test_log_contains oobeSystem.log "Win11Debloat Script"
                test_log_contains oobeSystem.log "Script completed! Please check above for any errors."

                ${lib.optionalString disableWindowsUpdate ''
                  test_log_contains windows-update.log "127.6.6.6"
                ''}

                test_log_contains windowsPE.log "All done!"

                # TODO: test installed programs are available

                exit "$RESULT"
              ''} |& tee test-results.log''}

            cd ..

            mv summary output/share/windows-vm/

            du -hs . >> output/share/windows-vm/summary/disk-space.txt
            du -hs image >> output/share/windows-vm/summary/disk-space.txt
          ''}

          ${
            if compressDiskImage then
              ''
                log "Rewriting disk image to compress it"
                qemu-img \
                  convert \
                  -c \
                  -o compat=1.1 \
                  -O qcow2 \
                  image \
                  output/share/windows-vm/image.qcow2
              ''
            else
              ''
                mv image output/share/windows-vm/image.qcow2
              ''
          }

          ${lib.optionalString configuration.emitsSummary ''
            du -hs output/share/windows-vm/image.qcow2 >> output/share/windows-vm/summary/disk-space.txt
          ''}

          ${lib.optionalString recordInstallation ''
            ${lib.optionalString configuration.emitsSummary ''
              du -hs recording.mkv >> output/share/windows-vm/summary/disk-space.txt
            ''}
              mv recording.mkv output/share/windows-vm
          ''}

          cat > output/share/windows-vm/windows.conf <<EOF
          guest_os="windows"
          boot="${if configuration.useEFI then "efi" else "legacy"}"
          disk_img="image.qcow2"
          tpm="off"
          secureboot="off"
          EOF

          cp -a ${pkgs.writeShellScript "start" ''
            SCRIPT_DIR=$( cd -- "$( dirname -- "''${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
            set -euo pipefail
            cd "$SCRIPT_DIR"
            ${lib.getExe pkgs.quickemu} --vm windows.conf --display spice
          ''} output/share/windows-vm/start

          cp -a ${pkgs.writeShellScript "stop" ''
            SCRIPT_DIR=$( cd -- "$( dirname -- "''${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
            set -euo pipefail
            cd "$SCRIPT_DIR"
            ${lib.getExe pkgs.quickemu} --vm windows.conf --kill
          ''} output/share/windows-vm/stop

          cp -a ${./scripts/mount} output/share/windows-vm/mount

          mkdir -p output/bin
          cp -a ${pkgs.writeShellScript "prepare-windows-vm" ''
            SCRIPT_DIR=$( cd -- "$( dirname -- "''${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
            set -euo pipefail
            cp -ar --reflink=auto "$SCRIPT_DIR/../share/windows-vm" .
            chmod u+w --recursive windows-vm
          ''} output/bin/prepare-windows-vm

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
