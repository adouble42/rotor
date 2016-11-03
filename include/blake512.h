#ifndef _BLAKE512_H_
#define _BLAKE512_H_

#include <stdint.h>
#include "sysendian.h"
#define CLIENT_KEY "Client Key"

typedef struct {
  uint64_t h[8], s[4], t[2];
  int buflen, nullt;
  uint8_t buf[128];
} state;

typedef struct {
  state inner;
  state outer;
} hmac_state;

void blake512_init(state *);
void blake384_init(state *);

void blake512_update(state *, const uint8_t *, uint64_t);
void blake384_update(state *, const uint8_t *, uint64_t);

void blake512_final(state *, uint8_t *);
void blake384_final(state *, uint8_t *);

void blake512_hash(uint8_t *, const uint8_t *, uint64_t);
void blake384_hash(uint8_t *, const uint8_t *, uint64_t);

/* HMAC functions: */

void hmac_blake512_init(hmac_state *, const uint8_t *, uint64_t);
void hmac_blake384_init(hmac_state *, const uint8_t *, uint64_t);

void hmac_blake512_update(hmac_state *, const uint8_t *, uint64_t);
void hmac_blake384_update(hmac_state *, const uint8_t *, uint64_t);

void hmac_blake512_final(hmac_state *, uint8_t *);
void hmac_blake384_final(hmac_state *, uint8_t *);

void hmac_blake512_hash(uint8_t *, const uint8_t *, uint64_t, const uint8_t *, uint64_t);
void hmac_blake384_hash(uint8_t *, const uint8_t *, uint64_t, const uint8_t *, uint64_t);

void
PBKDF2_blake512(const uint8_t * passwd, size_t passwdlen, const uint8_t * salt, size_t saltlen, uint64_t c, uint8_t * buf, size_t dkLen);

#endif /* _BLAKE512_H_ */
