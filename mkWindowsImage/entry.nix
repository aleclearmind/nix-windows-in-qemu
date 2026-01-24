{ pkgs }:
let
  lib = (import ./lib.nix { inherit pkgs; });
  typeSafeFunction =
    { options, implementation }:
    # Return a function that accepts some arguments
    arguments:
    # and invokes the implementation
    implementation
      # Passing as arguments the result of evaluating the module
      (pkgs.lib.evalModules {
        modules = [
          {
            inherit options;
            config = arguments;
          }
        ];
      }).config;
  defaultPreinstall = builtins.attrValues (
    import ./default-preinstall.nix {
      inherit pkgs;
      inherit lib;
    }
  );
in
typeSafeFunction {
  options = with pkgs.lib; {
    name = mkOption {
      type = types.str;
      example = "windows";
      description = "Name for the image.";
    };

    version = mkOption {
      type = types.enum [
        "windows-11-25h2"
        "windows-11-24h2"
        "windows-11-23h2"
        "windows-3.11"
        "dos-6.22"
      ];
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

    disableWindowsUpdate = mkOption {
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
      default = false;
      description = "Zero out unused disk space to reduce the size of the final image.";
    };

    compressDiskImage = mkOption {
      type = types.bool;
      default = false;
      description = "Rewrite and compress the final disk image.";
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

    recordInstallation = mkOption {
      type = types.bool;
      default = false;
      example = false;
      description = "If true, produces share/windows-vm/recording.mkv, i.e., a video of the installation process recorded via VNC.";
    };

    testInstallation = mkOption {
      type = types.bool;
      default = true;
      example = true;
      description = "If true, tests that the final installation has the expected characteristics (e.g., Windows Updates disabled).";
    };

    runNgen = mkOption {
      type = types.bool;
      default = false;
      example = false;
      description = "If true, optimize .Net programs upon install.";
    };

    preinstall = mkOption {
      type = types.listOf (
        types.submodule {
          options = {
            installer = mkOption {
              type = types.submodule {
                options = {
                  name = mkOption {
                    type = types.str;
                  };
                  package = mkOption {
                    type = types.package;
                  };
                  arguments = mkOption {
                    type = types.nullOr types.str;
                    default = null;
                  };
                  script = mkOption {
                    # TODO: a function taking the full path to the installer
                    default = null;
                  };
                };
              };
            };
            operatingSystem = {
              name = mkOption {
                type = types.enum [
                  "dos"
                  "windows"
                ];
                default = "windows";
                description = "The name of the operating system.";
              };

              minimumVersion = mkOption {
                type = types.nullOr types.str;
                default = null;
              };

              maximumVersion = mkOption {
                type = types.nullOr types.str;
                default = null;
              };

            };
          };
        }
      );
      default = defaultPreinstall;
      description = "List of software to preinstall.";
    };

  };
  implementation =
    userConfiguration:
    (pkgs.lib.evalModules {
      modules = [
        {
          _module.args = {
            pkgs = pkgs;
            userConfiguration = userConfiguration;
            common = lib;
          };
        }
        ./systems/options.nix
        ./systems/windows-11-24h2.nix
        ./systems/windows-11-23h2.nix
        ./systems/windows-3.11.nix
        ./systems/dos-6.22.nix
        ./implementation.nix
      ];
    }).config.output;
}
