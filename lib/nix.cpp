#include <nix/config.h>

#include <nix/derivations.hh>
#include <nix/globals.hh>
#include <nix/store-api.hh>
#include <nix/util.hh>
#include <nix/crypto.hh>

extern "C" {
  const char *getStoreDir() {
    return nix::settings.nixStore.c_str();
  }
}
