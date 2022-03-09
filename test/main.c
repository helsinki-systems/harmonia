#include <stdio.h>

#include "nix.h"

int main(int argc, char **argv) {
  printf("%s\n", getStoreDir());
}
