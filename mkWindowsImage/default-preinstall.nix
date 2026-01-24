{ pkgs, lib }:
let
  spiceGuestToolsInstaller = pkgs.fetchurl {
    url = "https://www.spice-space.org/download/windows/spice-guest-tools/spice-guest-tools-0.141/spice-guest-tools-0.141.exe";
    sha256 = "sha256-tb4HVIArzX9/4Mzbh3+KYiS6E6KvfYTrCHqJs7AjfaI=";
  };
in
{
  # Windows version conventions used here:
  #
  # Windows 3.11 => 3.11
  # Windows 95 => 4.00.950
  # Windows 95 OSR1 => 4.00.950a
  # Windows 95 OSR2 => 4.00.950b
  # Windows 95 OSR2.5 => 4.00.950c
  # Windows 98 => 4.10.1998
  # Windows 98 Second Edition => 4.10.2222
  # Windows ME => 4.90.3000
  # Windows 2000 => 5.0
  # Windows XP (32-bit) => 5.1
  # Windows XP Professional x64 => 5.2
  # Windows Vista => 6.0
  # Windows 7 => 6.1
  # Windows 8 => 6.2
  # Windows 8.1 => 6.3
  # Windows 10 => 10.0.0
  # Windows 11 => 10.0.22000
  #
  # Basically we ignore the Windows NT line pre-5.0.

  spiceGuest = {

    installer = {
      package = spiceGuestToolsInstaller;
      name = "spice-guest-tools.exe";
      arguments = "/S";
    };

    # https://github.com/utmapp/spice-nsis/blob/main/win-guest-tools.nsis
    operatingSystem.minimumVersion = "5.1";

  };

  notepadPlusPlus = {

    installer = {
      package = pkgs.fetchurl {
        url = "https://github.com/notepad-plus-plus/notepad-plus-plus/releases/download/v8.9/npp.8.9.Installer.x64.msi";
        sha256 = "sha256-LeTdpx0AcwhEl0d0wsZMzHyqV6Nd5O7D2Cq99+UGyNI=";
      };
      name = "npp.Installer.x64.msi";
    };

    # https://github.com/notepad-plus-plus/notepad-plus-plus/blob/master/SUPPORTED_SYSTEM.md
    operatingSystem.minimumVersion = "6.1";

  };

  chocolatey = {

    installer = {
      package = pkgs.fetchurl {
        url = "https://github.com/chocolatey/choco/releases/download/2.6.0/chocolatey-2.6.0.0.msi";
        sha256 = "sha256-UP7K8R0LqJzxbdQeZTzaQJzclNKaeS9wDZ3EWrUxPi0=";
      };
      name = "chocolatey.msi";
    };

    # https://community.chocolatey.org/courses/getting-started/requirements
    operatingSystem.minimumVersion = "6.1";

  };

  dependencyWalker = {

    installer = {
      package = pkgs.fetchurl {
        url = "https://www.dependencywalker.com/depends22_x64.zip";
        sha256 = "sha256-NdtophOHSi6MFCLrDqeGH4JfxxcX1G2r8fJJzpY0tPE=";
      };
      name = "depends_x64.zip";
    };

    # https://www.dependencywalker.com/
    operatingSystem.minimumVersion = "4";

  };

  sysinternalsSuite = {

    installer = {
      package = pkgs.fetchurl {
        # Unfortunately, Sysinternals does not release versioned installers
        url = "https://web.archive.org/web/20251217080248/https://download.sysinternals.com/Files/SysinternalsSuite.zip";
        sha256 = "sha256-oOzkxS7pxxw8AgOCRdPgs8YVD/8OJr1734gvx+5Uz2k=";
      };
      name = "SysinternalsSuite.zip";
    };

    # TODO: check
    operatingSystem.minimumVersion = "6.0";

  };

  depedencies = {

    installer = {
      package = pkgs.fetchurl {
        url = "https://github.com/lucasg/Dependencies/releases/download/v1.11.1/Dependencies_x64_Release.zip";
        sha256 = "sha256-fSLcAPHAn9RBXUitdNHPgBiT6DuaOZRLD85t6nzq6pk=";
      };
      name = "Dependencies_x64_Release.zip";
    };

    # Before Windows 8 you can use dependencyWalker
    operatingSystem.minimumVersion = "6.0";

  };

  git = {

    installer = {
      package = pkgs.fetchurl {
        url = "https://github.com/git-for-windows/git/releases/download/v2.52.0.windows.1/Git-2.52.0-64-bit.exe";
        sha256 = "sha256-2N56MVImbIuxNXfquFDqHfbcz4wqpIvltKHFi3GQ1iw=";
      };
      name = "Git-64-bit.exe";
      arguments = ''/VERYSILENT /NORESTART /NOCANCEL /SP- /CLOSEAPPLICATIONS /RESTARTAPPLICATIONS /COMPONENTS="icons,ext\reg\shellhere,assoc,assoc_sh"'';
    };

    # https://gitforwindows.org/requirements.html
    operatingSystem.minimumVersion = "6.3";

  };

  systemInformer = {

    installer = {
      package = pkgs.fetchurl {
        url = "https://github.com/winsiderss/systeminformer/releases/download/v3.2.25011.2103/systeminformer-3.2.25011-release-setup.exe";
        sha256 = "sha256-dhLV5EpaOSq58NG1uKeb2jzb4ZhI6O6ewjkJqvParUU=";
      };
      name = "systeminformer-release-setup.exe";
      arguments = "-silent";
    };

    # https://systeminformer.sourceforge.io/readme
    operatingSystem.minimumVersion = "6.1";

  };

  firefox = {

    installer = {
      package = pkgs.fetchurl {
        url = "https://download-installer.cdn.mozilla.net/pub/firefox/releases/146.0.1/win64/en-US/Firefox%20Setup%20146.0.1.exe";
        sha256 = "sha256-TjKTXQueQj5xjCwxBm+gloYHca/KSpiHCay0SONx3iI=";
      };
      name = "firefox-installer.exe";
      arguments = "/S";
    };

    # https://www.firefox.com/en-US/firefox/146.0.1/system-requirements/
    operatingSystem.minimumVersion = "10";

  };

  chromium = {

    installer = {
      package = pkgs.fetchurl {
        url = "https://storage.googleapis.com/chromium-browser-snapshots/Win_x64/1572379/mini_installer.exe";
        sha256 = "sha256-wrr7tt8zEzgPyxRsFwXGjGvWSS+cfQN/VThFpSVxYlg=";
      };
      name = "chromium-installer.exe";
      bat = installerPath: ''
        rem Chromium installer needs to write things in the installer directory
        copy ${installerPath} .
        start /wait chromium-installer.exe
        del chromium-installer.exe
      '';
    };

    # https://chromium.googlesource.com/chromium/src/+/main/docs/windows_build_instructions.md
    operatingSystem.minimumVersion = "10";

  };

  everything = {

    installer = {
      package = pkgs.fetchurl {
        url = "https://www.voidtools.com/Everything-1.4.1.1030.x64.msi";
        sha256 = "sha256-W/8tukbHGDi4lm00C6NqGB+wDM1cvaRZADcR64B2jIk=";
      };
      name = "Everything.x64.msi";
    };

    # https://www.voidtools.com/faq/
    operatingSystem.minimumVersion = "5.1";

  };

  p7zip = {
    installer = {
      package = pkgs.fetchurl {
        url = "https://7-zip.org/a/7z2501-x64.msi";
        sha256 = "sha256-5+sLftXvpOCHt7F/GReX969bf0QtEpDGbzohd3AF71c=";
      };
      name = "7z-x64.msi";
    };

    # https://www.7-zip.org/
    operatingSystem.minimumVersion = "5.0";

  };

  qemuGuestAgent = {

    installer = {
      name = "qemu-ga-x86_64.msi";

      package = lib.extractWith7z {
        name = "qemu-ga-x86_64.msi";
        archive = lib.virtioIso;
        paths = [ "guest-agent/qemu-ga-x86_64.msi" ];
      };

    };

    # The ISO contains back to Windows XP
    operatingSystem.minimumVersion = "5.1";

  };

  spiceCertificate = {
    installer = {
      priority = 100;
      package =
        let
          certificate = lib.extractWith7z {
            name = "vioser.cat";
            archive = spiceGuestToolsInstaller;
            paths = [ "drivers/vioserial/w10/amd64/vioser.cat" ];
          };
        in
        pkgs.stdenv.mkDerivation {
          name = "redhat-certificate.der";
          src = null;
          dontUnpack = true;

          nativeBuildInputs = with pkgs; [
            openssl
          ];

          buildPhase = ''
            openssl pkcs7 -inform der -in ${certificate} -print_certs | \
              grep Red -A1000 | \
              grep -m1 'END CERTIFICATE' -B 10000 | \
              openssl x509 -inform pem -outform der \
              > redhat-certificate.der \
              || true
            test -s redhat-certificate.der
          '';

          installPhase = "mv redhat-certificate.der $out";
          dontFixup = true;
        };
      name = "redhat-certificate.der";
      bat = installerPath: ''
        rem Installs the code signing cert for RedHat for drivers embedded in spice-guest-tools
        certutil -addstore -f "TrustedPublisher" "${installerPath}"
      '';
    };

    # https://github.com/utmapp/spice-nsis/blob/main/win-guest-tools.nsis
    operatingSystem.minimumVersion = "5.1";
  };
  win11debloat = {
    installer = {
      name = "Win11Debloat.zip";
      package = pkgs.fetchurl {
        url = "https://codeload.github.com/Raphire/Win11Debloat/zip/refs/tags/2025.12.29";
        sha256 = "sha256-moOrldUaZMP55zhubxX2kP5KRuAzWGU/cXYSkp48OS8=";
      };
      ps1 = installerPath: ''
        Extract-ZipToDesktop -zipFilePath "${installerPath}"
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
      '';
    };
    operatingSystem.minimumVersion = "10";
  };

}
