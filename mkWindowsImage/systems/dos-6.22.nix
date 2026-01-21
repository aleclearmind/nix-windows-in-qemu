{ pkgs, ... }:
{
  systems."dos-6.22" =
    let
      dos622 = pkgs.fetchzip {
        url = "https://www.kirsle.net/projects/DOS/MS-DOS-6.22.zip";
        sha256 = "sha256-/+tp2w45YufH39CCN1QNxCOOMFR3j4nIBxryNNzxMXw=";
        stripRoot = false;
      };
    in
    {
      qemuArchitecture = "i386";
      cpu = "486";
      maxCpus = 1;
      maxMemory = 16;
      maxDiskSize = 150;
      floppy = "${dos622}/Dos622-1.img";
      emitSummary = false;
      commands =
        let
          dosIdle = pkgs.fetchurl {
            url = "https://computernewb.com/QEMU/dosidle.img";
            sha256 = "sha256-rLig3MIo8WgWNWHJV4eWWqYVbQPPCNLWF7rqo1r1zZY=";
          };
        in
        [
          {
            type = "wait-for";
            text = "Welcome to Setup";
          }
          {
            description = "Confirm welcome screen";
            type = "vncdo";
            arguments = "key enter";
          }
          {
            description = "Confirm format disk";
            type = "vncdo";
            arguments = "key enter";
          }
          {
            type = "sleep";
            time = "1";
          }
          {
            description = "Confirm restart";
            type = "vncdo";
            arguments = "key enter";
          }
          {
            type = "wait-for";
            text = "The settings are correct";
          }
          {
            description = "Confirm locale settings";
            type = "vncdo";
            arguments = "key enter";
          }
          {
            description = "Confirm install location";
            type = "vncdo";
            arguments = "key enter";
          }
          {
            type = "wait-for";
            text = "Setup Disk #2";
          }
          {
            type = "change-floppy";
            path = "${dos622}/Dos622-2.img";
          }
          {
            type = "vncdo";
            arguments = "key enter";
          }
          {
            type = "wait-for";
            text = "Setup Disk #3";
          }
          {
            type = "change-floppy";
            path = "${dos622}/Dos622-3.img";
          }
          {
            type = "vncdo";
            arguments = "key enter";
          }
          {
            # Can't detect "Remove disks"
            type = "sleep";
            time = "5";
          }
          {
            type = "vncdo";
            arguments = "key enter";
          }
          {
            description = "Confirm reboot";
            type = "vncdo";
            arguments = "key enter";
          }
          {
            type = "wait-for";
            text = "HIMEM is testing extended memory...do.e.";
          }
          {
            type = "sleep";
            time = "1";
          }
          {
            type = "change-floppy";
            path = "${dosIdle}";
          }
          {
            description = "Installing dosidle";
            type = "vncdo";
            arguments = "key a";
          }
          {
            type = "vncdo";
            arguments = "key shift-:";
          }
          {
            type = "vncdo";
            arguments = "key enter";
          }
          {
            type = "vncdo";
            arguments = "type dosidle";
          }
          {
            type = "vncdo";
            arguments = "key enter";
          }
          {
            type = "wait-for";
            text = "installed successfully";
          }
          {
            description = "We're done, quitting";
            type = "quit";
          }
        ];
    };

}
