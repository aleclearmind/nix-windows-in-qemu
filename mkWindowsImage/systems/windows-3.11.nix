{ pkgs, config, ... }:
{
  systems."windows-3.11" =
    let
      popBack = list: pkgs.lib.lists.sublist 0 ((builtins.length list) - 1) list;
      windows311 = pkgs.fetchzip {
        url = "https://www.kirsle.net/projects/DOS/WfW-3.11.zip";
        sha256 = "sha256-21QVcfXi3ZIM2X6ZL2Aq44jHEWK10+M9xONzCEEhsms=";
        stripRoot = false;
      };
      insertFloppy = index: [
        {
          type = "wait-for";
          text = "Please I.sert the disk labeled";
        }
        {
          type = "change-floppy";
          path = "${windows311}/WfW311-${builtins.toString index}.img";
        }
        {
          type = "vncdo";
          arguments = "key enter";
        }
      ];
    in
    config.systems."dos-6.22"
    // {
      operatingSystem = {
        name = "windows";
        version = "3.11";
      };
      commands =
        (popBack config.systems."dos-6.22".commands)
        ++ [
          {
            type = "change-floppy";
            path = "${windows311}/WfW311-1.img";
          }
          {
            type = "vncdo";
            arguments = "type setup.exe";
          }
          {
            type = "vncdo";
            arguments = "key enter";
          }
          {
            description = "Confirm welcome screen";
            type = "vncdo";
            arguments = "key enter";
          }
          {
            description = "Choose express setup";
            type = "vncdo";
            arguments = "key enter";
          }
        ]
        ++ (insertFloppy 2)
        ++ [
          {
            type = "wait-for";
            text = "Your Full Name:";
          }
          {
            type = "vncdo";
            arguments = "type User";
          }
          {
            type = "vncdo";
            arguments = "key tab";
          }
          {
            type = "vncdo";
            arguments = "type Organization";
          }
          {
            description = "Submit user data";
            type = "vncdo";
            arguments = "key enter";
          }
          {
            description = "Confirm user data";
            type = "vncdo";
            arguments = "key enter";
          }
        ]
        ++ (insertFloppy 3)
        ++ (insertFloppy 4)
        ++ (insertFloppy 5)
        ++ (insertFloppy 6)
        ++ [
          {
            type = "wait-for";
            text = "install the printer";
          }
          {
            description = "Skip printer";
            type = "vncdo";
            arguments = "key esc";
          }
          # Network configuration
          {
            type = "wait-for";
            text = ".etwork setti.gs";
          }
          {
            description = "Click on \"Networks\"";
            type = "vncdo";
            arguments = "key n";
          }
          {
            type = "wait-for";
            text = ".icrosoft Wi.dows .etwork";
          }
          {
            description = "Choose \"Install Microsoft Windows Network\"";
            type = "vncdo";
            arguments = "key i";
          }
          {
            description = "Confirm";
            type = "vncdo";
            arguments = "key enter";
          }
          {
            description = "Confirm";
            type = "vncdo";
            arguments = "key enter";
          }
          {
            type = "wait-for";
            text = "Select a .etwork adapter";
          }
          {
            description = "Choose \"unlisted\"";
            type = "vncdo";
            arguments = "key enter";
          }
          {
            type = "wait-for";
            text = "Browse";
          }
          {
            type = "change-floppy";
            path = "${pkgs.fetchurl {
              url = "https://computernewb.com/QEMU/rtl8139.img";
              sha256 = "sha256-CJbl9KnrjzX4AqbXEya7S7ssKibiURXMdRjDpay7c/U=";
            }}";
          }
          {
            description = "Confirm";
            type = "vncdo";
            arguments = "key enter";
          }
          {
            type = "sleep";
            time = "2";
          }
          {
            description = "Pick Realtek 8139";
            type = "vncdo";
            arguments = "key enter";
          }
          {
            type = "wait-for";
            text = ".icrosoft Wi.dows .etwork .a.es";
          }
          {
            description = "Confirm network names";
            type = "vncdo";
            arguments = "key enter";
          }
          # Request for NDIS.386
          {
            type = "wait-for";
            text = "NDIS.386";
          }
          {
            type = "change-floppy";
            path = "${windows311}/WfW311-7.img";
          }
          {
            description = "Confirm";
            type = "vncdo";
            arguments = "key enter";
          }
          # Request for RTSND.386
          {
            type = "wait-for";
            text = "RTSND.386";
          }
          {
            type = "change-floppy";
            path = "${pkgs.fetchurl {
              url = "https://computernewb.com/QEMU/rtl8139.img";
              sha256 = "sha256-CJbl9KnrjzX4AqbXEya7S7ssKibiURXMdRjDpay7c/U=";
            }}";
          }
          {
            description = "Confirm";
            type = "vncdo";
            arguments = "key enter";
          }
          # Request for VREDIR.386
          {
            type = "wait-for";
            text = "VREDIR";
          }
          {
            type = "change-floppy";
            path = "${windows311}/WfW311-7.img";
          }
          {
            description = "Confirm";
            type = "vncdo";
            arguments = "key enter";
          }
          # Request for LMSCRIPT.EXE
          {
            type = "wait-for";
            text = "L.SCRIPT";
          }
          {
            type = "change-floppy";
            path = "${windows311}/WfW311-8.img";
          }
          {
            description = "Confirm";
            type = "vncdo";
            arguments = "key enter";
          }
          # Request for RTSND.DOS
          {
            type = "wait-for";
            text = "RTS.D";
          }
          {
            type = "change-floppy";
            path = "${pkgs.fetchurl {
              url = "https://computernewb.com/QEMU/rtl8139.img";
              sha256 = "sha256-CJbl9KnrjzX4AqbXEya7S7ssKibiURXMdRjDpay7c/U=";
            }}";
          }
          {
            description = "Confirm";
            type = "vncdo";
            arguments = "key enter";
          }
          # Request for WINPOPUP.HLP
          {
            type = "wait-for";
            text = "WI.POPUP";
          }
          {
            type = "change-floppy";
            path = "${windows311}/WfW311-8.img";
          }
          {
            description = "Confirm";
            type = "vncdo";
            arguments = "key enter";
          }
          # Final stages
          {
            type = "wait-for";
            text = "EDIT.COM";
          }
          {
            description = "Confirm EDIT.COM is MS-DOS text editor";
            type = "vncdo";
            arguments = "key enter";
          }
          {
            type = "wait-for";
            text = "You will also be able";
          }
          {
            description = "Skip tutorial";
            type = "vncdo";
            arguments = "key s";
          }
          {
            type = "wait-for";
            text = "You need to restart your";
          }
          {
            description = "Exit to DOS";
            type = "vncdo";
            arguments = "key d";
          }
          {
            type = "wait-for";
            text = "C..WINDOWS";
          }
          {
            description = "We're done, quitting";
            type = "quit";
          }
        ];
    };
}
