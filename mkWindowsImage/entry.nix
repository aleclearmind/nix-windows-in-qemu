{ pkgs }:
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
          {
            inherit options;
            config = arguments;
          }
        ];
      }).config;
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

    recordInstallation = mkOption {
      type = types.bool;
      default = false;
      example = false;
      description = "If true, produces share/windows-vm/recording.mkv, i.e., a video of the installation process recorded via VNC.";
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
          }
          // (import ./lib.nix { inherit pkgs; });
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
