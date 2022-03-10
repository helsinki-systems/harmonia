#ifndef NIX_H
#define NIX_H

#include "stdint.h"
#include "stdbool.h"

// TODO(conni2461): Remove
typedef const char SV;

void init();
void setVerbosity(int level);
bool isValidPath(const char *path);
SV *queryReferences(const char *path);           // TODO(conni2461)
SV *queryPathHash(const char *path);             // TODO(conni2461)
SV *queryDeriver(const char *path);              // TODO(conni2461)
SV *queryPathInfo(const char *path, int base32); // TODO(conni2461)
SV *queryRawRealisation(const char *outputId);   // TODO(conni2461)
SV *queryPathFromHashPart(const char *hashPart); // TODO(conni2461)
SV *computeFSClosure(int flipDirection, int includeOutputs,
                     ...);                                    // TODO(conni2461)
SV *topoSortPaths(...);                                       // TODO(conni2461)
SV *followLinksToStorePath(const char *path);                 // TODO(conni2461)
void exportPaths(int fd, ...);                                // TODO(conni2461)
void importPaths(int fd, int dontCheckSigs);                  // TODO(conni2461)
SV *hashPath(const char *algo, int base32, const char *path); // TODO(conni2461)
SV *hashFile(const char *algo, int base32, const char *path); // TODO(conni2461)
SV *hashString(const char *algo, int base32, const char *s);  // TODO(conni2461)
SV *convertHash(const char *algo, const char *s,
                int toBase32);                           // TODO(conni2461)
SV *signString(const char *secretKey_, const char *msg); // TODO(conni2461)
int checkSignature(SV *publicKey_, SV *sig_,
                   const char *msg); // TODO(conni2461)
SV *addToStore(const char *srcPath, int recursive,
               const char *algo); // TODO(conni2461)
SV *makeFixedOutputPath(int recursive, const char *algo, const char *hash,
                        const char *name);   // TODO(conni2461)
SV *derivationFromPath(const char *drvPath); // TODO(conni2461)
void addTempRoot(const char *storePath);
SV *getBinDir();   // TODO(conni2461)
SV *getStoreDir(); // TODO(conni2461)

#endif // NIX_H
