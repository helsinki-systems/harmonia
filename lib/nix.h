#ifndef NIX_H
#define NIX_H

#include <stdint.h>
#include <stdbool.h>
#include <time.h>

// TODO(conni2461): Remove
typedef void SV;

typedef struct {
  const char **arr;
  size_t size;
} nix_str_array_t;

typedef struct {
  const char *lhs;
  const char *rhs;
} nix_str_tuple_t;

typedef struct {
  nix_str_tuple_t **arr;
  size_t size;
} nix_str_hash_t;

typedef struct {
  const char *drv;
  const char *narhash;
  time_t time;
  uint64_t size;
  nix_str_array_t refs;
  nix_str_array_t sigs;
} nix_path_info_t;

typedef struct {
  nix_str_hash_t outputs;
  nix_str_array_t input_drvs;
  nix_str_array_t input_srcs;
  const char *platform;
  const char *builder;
  nix_str_array_t args;
  nix_str_hash_t env;
} nix_drv_t;


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
SV* nix_query_references(const char *path);

/**
 *
 */
const char *nix_query_path_hash(const char *path);

/**
 *
 */
const char *nix_query_deriver(const char *path);

/**
 *
 */
const nix_path_info_t *nix_query_path_info(const char *path, bool base32);

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
const char* nix_export_path(const char *path, size_t size);

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
 *
 */
const nix_drv_t *nix_derivation_from_path(const char *drv_path);

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
