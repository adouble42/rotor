#ifndef _BLAKE256_H_
#define _BLAKE256_H_
#include <sys/types.h>
#include <stdint.h>

#define PBKDF_B256 86

typedef struct {
  uint32_t h[8], s[4], t[2];
  int buflen, nullt;
  unsigned char buf[64];
} state;

typedef struct {
  state inner;
  state outer;
} hmac_state;

void blake256_init(state *);

void blake256_update(state *, const void *, size_t);

void blake256_final(state *, unsigned char [32]);

void blake256_hash(uint8_t *, const void *, uint64_t);

/* HMAC functions: */

void hmac_blake256_init(hmac_state *, const void *, size_t);

void hmac_blake256_update(hmac_state *, const void *, size_t);

void hmac_blake256_final(unsigned char [32], hmac_state *);

void hmac_blake256_hash(uint8_t *, const void *, uint64_t, const uint8_t *, uint64_t);

/**
 * PBKDF2_BLAKE256(passwd, passwdlen, salt, saltlen, c, buf, dkLen):
 * Compute PBKDF2(passwd, salt, c, dkLen) using HMAC-BLAKE256 as the PRF, and
 * write the output to buf.  The value dkLen must be at most 32 * (2^32 - 1).
 */
void	PBKDF2_BLAKE256(const uint8_t *, size_t, const uint8_t *, size_t, uint64_t, uint8_t *, size_t);

#endif /* _BLAKE256_H_ */
