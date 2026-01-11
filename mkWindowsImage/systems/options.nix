{ pkgs, ... }:
with pkgs.lib;
{
  options = {
    systems = mkOption {
      type = types.lazyAttrsOf (
        types.submodule {
          options = {
            qemuArchitecture = mkOption {
              type = types.enum [
                "x86_64"
                "i386"
              ];
              default = "x86_64";
              description = "The QEMU architecture to use.";
            };

            cpu = mkOption {
              type = types.enum [
                "host"
                "486"
              ];
              default = "host";
              description = "The QEMU -cpu option.";
            };

            maxCpus = mkOption {
              type = types.nullOr types.int;
              default = null;
              description = "Maximum number of CPUs allowed for this system.";
            };

            maxMemory = mkOption {
              type = types.nullOr types.int;
              default = null;
              description = "Maximum amount of memory (in MB) for this system.";
            };

            maxDiskSize = mkOption {
              type = types.nullOr types.int;
              default = null;
              description = "Maximum disk size (in MB) for this system.";
            };

            useEFI = mkOption {
              type = types.bool;
              default = false;
              description = "Whether to use EFI for this system.";
            };

            iso = mkOption {
              type = types.path;
              default = "/dev/null";
              description = "Path to the ISO image for installation.";
            };

            floppy = mkOption {
              type = types.nullOr types.path;
              default = null;
              description = "Path to the initial floppy disk image for installation.";
            };

            packerBootSteps = mkOption {
              type = types.str;
              default = "";
              description = "Packer's boot_steps = [ ... ].";
            };

            commands = mkOption {
              default = [ ];
              description = "A list of commands to pilot installation.";
              type = types.listOf (
                types.submodule {
                  options = {
                    type = mkOption {
                      type = types.enum [
                        "wait-for"
                        "vncdo"
                        "change-floppy"
                        "sleep"
                        "quit"
                      ];
                    };
                    description = mkOption {
                      type = types.str;
                      default = "";
                      description = "The description of this command.";
                    };
                    text = mkOption {
                      type = types.str;
                      default = "";
                      description = "The text to wait for.";
                    };
                    arguments = mkOption {
                      type = types.str;
                      default = "";
                      description = "vncdo arguments";
                    };
                    path = mkOption {
                      type = types.str;
                      default = "";
                      description = "Path for the new floppy image.";
                    };
                    time = mkOption {
                      type = types.str;
                      default = "";
                      example = "0.5";
                      description = "Sleep time.";
                    };
                  };
                }
              );
            };

            autounattendXml = mkOption {
              default = null;
              type = types.nullOr (
                types.submodule {
                  options = {
                    imageName = mkOption {
                      type = types.str;
                      default = "";
                      description = "The name of the product to install.";
                    };

                    diskConfiguration = mkOption {
                      type = types.str;
                      default = "";
                      description = "The <DiskConfiguration> section.";
                    };

                    installPartition = mkOption {
                      type = types.int;
                      default = 0;
                      description = "Index of the partition where to install Windows.";
                    };

                    productKey = mkOption {
                      type = types.str;
                      default = "";
                      description = "The <ProductKey> section.";
                    };

                    servicesToDisable = mkOption {
                      type = types.listOf types.str;
                      default = [ ];
                      description = "A list of services to disable very early on.";
                    };
                  };
                }
              );
            };
          };
        }
      );
    };

  };
}
