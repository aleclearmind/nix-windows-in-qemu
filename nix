#!/usr/bin/env bash

function log() {
  echo "$1" > /dev/stderr
}

if command -v nix >& /dev/null; then
    exec nix "$@"
fi

if ! test -e "$HOME/.nix-portable/exe/nix"; then
    log "You do not seem to have nix installed."
    log "We can install nix-portable:"
    log ""
    log "    https://github.com/DavHau/nix-portable"
    log ""
    log "It doesn't require root. It's a nix installation wrapped in ~/.nix-portable."
    log "You can remove it anytime just by removing that directory."
    log "If you want to proceed, we will run the following commands:"
    log ""
    log "    mkdir ~/.nix-portable"
    log "    curl -L https://github.com/DavHau/nix-portable/releases/download/v012/nix-portable-x86_64 > ~/.nix-portable/exe/nix"
    log "    chmod +x ~/.nix-portable/exe/nix"
    log ""
    log "Then, from now, this script will invoke ~/.nix-portable/exe/nix."
    log ""
    read -p "Proceed? [yN] " -n 1 -r

    if [[ $REPLY =~ ^[Yy]$ ]]; then
        mkdir ~/.nix-portable/exe
        curl -L https://github.com/DavHau/nix-portable/releases/download/v012/nix-portable-x86_64 > ~/.nix-portable/exe/nix
        chmod +x ~/.nix-portable/exe/nix
    fi
fi

exec "$HOME/.nix-portable/exe/nix" "$@"
