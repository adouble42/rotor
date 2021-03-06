/*
 *rotor
 *Copyright (c) 2016, adouble42/mrn@sdf
 *All rights reserved.
 *
 *Redistribution and use in source and binary forms, with or without
 *modification, are permitted provided that the following conditions are met:
 *
 * Redistributions of source code must retain the above copyright notice, this
 * list of conditions and the following disclaimer.
 *
 * Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 *THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 *AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 *IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 *DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 *FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 *DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 *SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 *CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 *OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef __ROTOR_KEYS_H
#define __ROTOR_KEYS_H

#define KDF_ROUNDS 10000

/*
 * rotor key management functions
 *
 * rotor_keypair_generate: generate a new rotor NTRU keypair
 *
 */

struct NtruEncKeyPair rotor_keypair_generate();

/*
 * rotor_exp_armorpriv: export encrypted, armored rotor private key
 */

void rotor_exp_armorpriv(uint8_t *priv_keyx, char *secret, int s_len, char *outfile);

/*
 * rotor_exp_armorpub: export armored rotor public key
 */

void rotor_exp_armorpub(uint8_t pub_keyx[NTRU_PUBLEN], char *outfile);

/*
 * rotor_load_armorpriv: import encrypted, armored rotor private key
 */

struct NtruEncPrivKey rotor_load_armorpriv(const uint8_t *secret, int s_len, char *infile);

/*
 * rotor_load_armorpub: import armored rotor public key
 */

struct NtruEncPubKey rotor_load_armorpub(char *infile);

/*
 * rotor_user_keygen: get user input and generate keypair
 */

void rotor_user_keygen(char *skname, char *pkname);

#endif
