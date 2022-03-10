#include <nix/config.h>

#include <nix/derivations.hh>
#include <nix/globals.hh>
#include <nix/store-api.hh>
#include <nix/util.hh>
#include <nix/crypto.hh>

#include <nlohmann/json.hpp>
#include <sodium.h>

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// This is illegal but i dont care
#define DEFAULT_TRY_CATCH(block)                                               \
  try {                                                                        \
    block                                                                      \
  } catch (const nix::Error &e) {                                              \
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

static const char *str_dup(std::string_view str) {
  char *ret = (char *)malloc(str.size() + 1);
  strncpy(ret, str.data(), str.size());
  ret[str.size()] = '\0';
  return ret;
}

extern "C" {
void nix_init() {
  store();
}

void nix_set_verbosity(int32_t level) {
  nix::verbosity = (nix::Verbosity)level;
}

bool nix_is_valid_path(const char *path) {
  DEFAULT_TRY_CATCH(return store()->isValidPath(store()->parseStorePath(path));)
  return false;
}

void nix_query_references(const char *path) {
  DEFAULT_TRY_CATCH({
    std::vector<std::string> ret;
    // TODO(conni2461): RETURN this array ^
    for (const nix::StorePath &store_path :
         store()->queryPathInfo(store()->parseStorePath(path))->references) {
      ret.push_back(store()->printStorePath(store_path).c_str());
    }
  })
}

const char *nix_query_path_hash(const char *path) {
  DEFAULT_TRY_CATCH({
    std::string s = store()
                        ->queryPathInfo(store()->parseStorePath(path))
                        ->narHash.to_string(nix::Base32, true);
    return str_dup(s);
  })
  return NULL;
}

typedef void SV;

const char *nix_query_deriver(const char *path) {
  DEFAULT_TRY_CATCH({
    auto info = store()->queryPathInfo(store()->parseStorePath(path));
    if (!info->deriver) {
      return NULL;
    }
    return str_dup(store()->printStorePath(*info->deriver));
  })
  return NULL;
}

SV *nix_query_path_info(const char *path, int32_t base32) {
  // TODO(conni2461)
  return NULL;
}

const char *nix_query_raw_realisation(const char *output_id) {
  DEFAULT_TRY_CATCH({
    std::shared_ptr<const nix::Realisation> realisation =
        store()->queryRealisation(nix::DrvOutput::parse(output_id));
    if (!realisation) {
      return str_dup("");
    }
    return str_dup(realisation->toJSON().dump());
  })
  return NULL;
}

const char *nix_query_path_from_hash_part(const char *hash_part) {
  DEFAULT_TRY_CATCH({
    std::optional<nix::StorePath> path =
        store()->queryPathFromHashPart(hash_part);
    return str_dup(path ? store()->printStorePath(*path) : "");
  })
  return NULL;
}

SV *nix_compute_fs_closure(bool flip_direction, bool include_outputs,
                           const char **paths) {
  DEFAULT_TRY_CATCH({
    nix::StorePathSet path_set;
    for (size_t i = 0; paths[i] != NULL; ++i) {
      store()->computeFSClosure(store()->parseStorePath(paths[i]), path_set,
                                flip_direction, include_outputs);
    }
    // TODO(conni2461): RETURN this array ^
    // for (auto & i : paths)
    //     XPUSHs(sv_2mortal(newSVpv(store()->printStorePath(i).c_str(), 0)));
  })
  return NULL;
}

SV *nix_topo_sort_paths(const char **paths) {
  DEFAULT_TRY_CATCH({
    nix::StorePathSet path_set;
    for (size_t i = 0; paths[i] != NULL; ++i) {
      path_set.insert(store()->parseStorePath(paths[i]));
    }
    nix::StorePaths sorted = store()->topoSortPaths(path_set);
    // TODO(conni2461): RETURN this array ^
    // for (auto & i : sorted)
    //     XPUSHs(sv_2mortal(newSVpv(store()->printStorePath(i).c_str(), 0)));
  })
  return NULL;
}

const char *nix_follow_links_to_store_path(const char *path) {
  DEFAULT_TRY_CATCH({
    return str_dup(
        store()->printStorePath(store()->followLinksToStorePath(path)));
  })
  return NULL;
}

void nix_export_paths(int32_t fd, const char **paths) {
  DEFAULT_TRY_CATCH({
    nix::StorePathSet path_set;
    for (size_t i = 0; paths[i] != NULL; ++i) {
      path_set.insert(store()->parseStorePath(paths[i]));
    }
    nix::FdSink sink(fd);
    store()->exportPaths(path_set, sink);
  })
}

void nix_import_paths(int32_t fd, bool dont_check_signs) {
  DEFAULT_TRY_CATCH({
    nix::FdSource source(fd);
    store()->importPaths(source,
                         dont_check_signs ? nix::NoCheckSigs : nix::CheckSigs);
  })
}

const char *nix_hash_path(const char *algo, bool base32, const char *path) {
  DEFAULT_TRY_CATCH({
    nix::Hash h = nix::hashPath(nix::parseHashType(algo), path).first;
    std::string s = h.to_string(base32 ? nix::Base32 : nix::Base16, false);
    return str_dup(s);
  })
  return NULL;
}

const char *nix_hash_file(const char *algo, bool base32, const char *path) {
  DEFAULT_TRY_CATCH({
    nix::Hash h = nix::hashFile(nix::parseHashType(algo), path);
    std::string s = h.to_string(base32 ? nix::Base32 : nix::Base16, false);
    return str_dup(s);
  })
  return NULL;
}

const char *nix_hash_string(const char *algo, bool base32, const char *s) {
  DEFAULT_TRY_CATCH({
    nix::Hash h = nix::hashString(nix::parseHashType(algo), s);
    std::string s = h.to_string(base32 ? nix::Base32 : nix::Base16, false);
    return str_dup(s);
  })
  return NULL;
}

const char *nix_convert_hash(const char *algo, const char *s, bool to_base_32) {
  DEFAULT_TRY_CATCH({
    nix::Hash h = nix::Hash::parseAny(s, nix::parseHashType(algo));
    std::string s = h.to_string(to_base_32 ? nix::Base32 : nix::Base16, false);
    return str_dup(s);
  })
  return NULL;
}

const char *nix_sign_string(const char *secret_key, const char *msg) {
  DEFAULT_TRY_CATCH({
    std::string sig = nix::SecretKey(secret_key).signDetached(msg);
    return str_dup(sig);
  })
  return NULL;
}

bool nix_check_signature(const char *public_key, const char *sig,
                         const char *msg) {
  DEFAULT_TRY_CATCH({
    size_t public_key_len = strlen(public_key);
    if (public_key_len != crypto_sign_PUBLICKEYBYTES) {
      throw nix::Error("public key is not valid");
    }

    size_t sig_len = strlen(sig);
    if (sig_len != crypto_sign_BYTES) {
      throw nix::Error("signature is not valid");
    }
    return crypto_sign_verify_detached((unsigned char *)sig,
                                       (unsigned char *)msg, strlen(msg),
                                       (unsigned char *)public_key) == 0;
  })
  return false;
}

const char *nix_add_to_store(const char *src_path, int32_t recursive,
                             const char *algo) {
  DEFAULT_TRY_CATCH({
    nix::FileIngestionMethod method = recursive
                                          ? nix::FileIngestionMethod::Recursive
                                          : nix::FileIngestionMethod::Flat;
    nix::StorePath path =
        store()->addToStore(std::string(nix::baseNameOf(src_path)), src_path,
                            method, nix::parseHashType(algo));
    return str_dup(store()->printStorePath(path));
  })
  return NULL;
}

const char *nix_make_fixed_output_path(bool recursive, const char *algo,
                                       const char *hash, const char *name) {
  DEFAULT_TRY_CATCH({
    nix::Hash h = nix::Hash::parseAny(hash, nix::parseHashType(algo));
    nix::FileIngestionMethod method = recursive
                                          ? nix::FileIngestionMethod::Recursive
                                          : nix::FileIngestionMethod::Flat;
    nix::StorePath path = store()->makeFixedOutputPath(method, h, name);
    return str_dup(store()->printStorePath(path));
  })
  return NULL;
}

SV *nix_derivation_from_path(const char *drv_path) {
  // TODO(conni2461)
  return NULL;
}

void nix_add_temp_root(const char *store_path) {
  DEFAULT_TRY_CATCH(store()->addTempRoot(store()->parseStorePath(store_path));)
}

const char *nix_get_bin_dir() {
  return str_dup(nix::settings.nixBinDir);
}

const char *nix_get_store_dir() {
  return str_dup(nix::settings.nixStore);
}
}
