#ifndef NIX_H
#define NIX_H

#include <stdint.h>
#include <stdbool.h>

// TODO(conni2461): Remove
typedef void SV;

/**
 *
 */
void nix_init();

/**
 *
 */
void nix_set_verbosity(int32_t level);

/**
 *
 */
bool nix_is_valid_path(const char *path);

/**
 * TODO
 */
void nix_query_references(const char *path);

/**
 *
 */
const char *nix_query_path_hash(const char *path);

/**
 *
 */
const char *nix_query_deriver(const char *path);

/**
 * TODO
 */
SV *nix_query_path_info(const char *path, int32_t base32);

/**
 *
 */
const char *nix_query_raw_realisation(const char *output_id);

/**
 *
 */
const char *nix_query_path_from_hash_part(const char *hash_part);

/**
 * TODO
 */
SV *nix_compute_fs_closure(bool flip_direction, bool include_outputs,
                           const char **paths);

/**
 * TODO
 */
SV *nix_topo_sort_paths(const char **paths);

/**
 *
 */
const char *nix_follow_links_to_store_path(const char *path);

/**
 *
 */
void nix_export_paths(int32_t fd, const char **paths);

/**
 *
 */
void nix_import_paths(int32_t fd, bool dont_check_signs);

/**
 *
 */
const char *nix_hash_path(const char *algo, bool base32, const char *path);

/**
 *
 */
const char *nix_hash_file(const char *algo, bool base32, const char *path);

/**
 *
 */
const char *nix_hash_string(const char *algo, bool base32, const char *s);

/**
 *
 */
const char *nix_convert_hash(const char *algo, const char *s, bool to_base_32);

/**
 *
 */
const char *nix_sign_string(const char *secret_key, const char *msg);

/**
 *
 */
bool nix_check_signature(const char *public_key, const char *sig,
                         const char *msg);

/**
 *
 */
const char *nix_add_to_store(const char *src_path, int32_t recursive,
                             const char *algo);

/**
 *
 */
const char *nix_make_fixed_output_path(bool recursive, const char *algo,
                                       const char *hash, const char *name);

/**
 * TODO
 */
SV *nix_derivation_from_path(const char *drv_path);

/**
 *
 */
void nix_add_temp_root(const char *store_path);

/**
 *
 */
const char *nix_get_bin_dir();

/**
 *
 */
const char *nix_get_store_dir();

#endif // NIX_H
