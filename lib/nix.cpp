#include <nix/config.h>

#include <nix/derivations.hh>
#include <nix/globals.hh>
#include <nix/store-api.hh>
#include <nix/util.hh>
#include <nix/crypto.hh>

// This is illegal but i dont care
#define DEFAULT_TRY_CATCH(block)                                               \
  try {                                                                        \
    block                                                                      \
  } catch (nix::Error & e) {                                                   \
    fprintf(stderr, "%s\n", e.what());                                         \
  }

static nix::ref<nix::Store> store() {
  static std::shared_ptr<nix::Store> _store;
  if (!_store) {
    DEFAULT_TRY_CATCH({
      nix::loadConfFile();
      nix::settings.lockCPU = false;
      _store = nix::openStore();
    })
  }
  return nix::ref<nix::Store>(_store);
}

extern "C" {
void init() {
  store();
}

void setVerbosity(int32_t level) {
  nix::verbosity = (nix::Verbosity)level;
}

bool isValidPath(const char *path) {
  DEFAULT_TRY_CATCH(return store()->isValidPath(store()->parseStorePath(path));)
  return false;
}

void queryReferences(const char *path) {
  DEFAULT_TRY_CATCH({
    // TODO(conni2461): needs to be returned
    std::vector<std::string> ret;
    for (auto &i :
         store()->queryPathInfo(store()->parseStorePath(path))->references) {
      ret.push_back(store()->printStorePath(i).c_str());
    }
  })
}

void queryPathHash(const char *path) {
  DEFAULT_TRY_CATCH({
    // TODO(conni2461): needs to be returned
    std::string s = store()
                        ->queryPathInfo(store()->parseStorePath(path))
                        ->narHash.to_string(nix::Base32, true);
  })
}

// TODO(conni2461): Remove
typedef const char SV;

SV *queryDeriver(const char *path) {
  // TODO(conni2461)
  return NULL;
}

SV *queryPathInfo(const char *path, int base32) {
  // TODO(conni2461)
  return NULL;
}

SV *queryRawRealisation(const char *outputId) {
  // TODO(conni2461)
  return NULL;
}

SV *queryPathFromHashPart(const char *hashPart) {
  // TODO(conni2461)
  return NULL;
}

SV *computeFSClosure(int flipDirection, int includeOutputs, ...) {
  // TODO(conni2461)
  return NULL;
}

SV *topoSortPaths(...) {
  // TODO(conni2461)
  return NULL;
}

SV *followLinksToStorePath(const char *path) {
  // TODO(conni2461)
  return NULL;
}

void exportPaths(int fd, ...) {
  // TODO(conni2461)
}

void importPaths(int fd, int dontCheckSigs) {
  // TODO(conni2461)
}

SV *hashPath(const char *algo, int base32, const char *path) {
  // TODO(conni2461)
  return NULL;
}

SV *hashFile(const char *algo, int base32, const char *path) {
  // TODO(conni2461)
  return NULL;
}

SV *hashString(const char *algo, int base32, const char *s) {
  // TODO(conni2461)
  return NULL;
}

SV *convertHash(const char *algo, const char *s, int toBase32) {
  // TODO(conni2461)
  return NULL;
}

SV *signString(const char *secretKey_, const char *msg) {
  // TODO(conni2461)
  return NULL;
}

int checkSignature(SV *publicKey_, SV *sig_, const char *msg) {
  // TODO(conni2461)
  return 0;
}

SV *addToStore(const char *srcPath, int recursive, const char *algo) {
  // TODO(conni2461)
  return NULL;
}

SV *makeFixedOutputPath(int recursive, const char *algo, const char *hash,
                        const char *name) {
  // TODO(conni2461)
  return NULL;
}

SV *derivationFromPath(const char *drvPath) {
  // TODO(conni2461)
  return NULL;
}

void addTempRoot(const char *storePath) {
  DEFAULT_TRY_CATCH(store()->addTempRoot(store()->parseStorePath(storePath));)
}

const char *getBinDir() {
  // TODO(conni2461)
  return nix::settings.nixBinDir.c_str();
}

const char *getStoreDir() {
  // TODO(conni2461)
  return nix::settings.nixStore.c_str();
}
}
