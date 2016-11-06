/*****************************************************************************
 * (c) 2016 BSD 2 clause adouble42/mrn@sdf                                   *
 * rotor - "If knowledge can create problems, it is not through ignorance    * 
 * that we can solve them." -- isaac asimov                                  *
 *                                                                           *
 * rotor-extra.c - loud noises                                               *
 *****************************************************************************/
#include <stdio.h>
#include "rotor.h"
#include "rotor-extra.h"
#include "ntru.h"

void rotor_show_ntru_params() {
  printf("rotor - version %i.%i\n(c)2016 mrn@sdf.org\n\n",ROTOR_MAJOR,ROTOR_MINOR);
  printf("256 bit mode comparison:\n");
  printf("size of ciphertext EES1499EP1 params: %i\n",ntru_enc_len(&EES1499EP1));
  printf("max length of plaintext EES1499EP1 params: %i\n",ntru_max_msg_len(&EES1499EP1));
  printf("size of ciphertext EES1087EP2 params: %i\n",ntru_enc_len(&EES1087EP2));
  printf("max length of plaintext EES1087EP2 params: %i\n",ntru_max_msg_len(&EES1087EP2));
  printf("size of ciphertext EES1171EP1 params: %i\n",ntru_enc_len(&EES1171EP1));
  printf("max length of plaintext EES1171EP1 params: %i\n",ntru_max_msg_len(&EES1171EP1));
  printf("size of ciphertext NTRU_DEFAULT_PARAMS_128_BITS params: %i\n",ntru_enc_len(&NTRU_DEFAULT_PARAMS_128_BITS));
  printf("max length of plaintext NTRU_DEFAULT_PARAMS_128_BITS params: %i\n",ntru_max_msg_len(&NTRU_DEFAULT_PARAMS_128_BITS));
  printf("size of ciphertext NTRU_DEFAULT_PARAMS_256_BITS params: %i\n",ntru_enc_len(&NTRU_DEFAULT_PARAMS_256_BITS));
  printf("max length of plaintext NTRU_DEFAULT_PARAMS_256_BITS params: %i\n",ntru_max_msg_len(&NTRU_DEFAULT_PARAMS_256_BITS));
  printf("192 bits:\n");
  printf("size of ciphertext EES887EP1 params: %i\n",ntru_enc_len(&EES887EP1));
  printf("max length of plaintext EES887EP1 params: %i\n",ntru_max_msg_len(&EES887EP1));
  printf("size of ciphertext EES1087EP1 params: %i\n",ntru_enc_len(&EES1087EP1));
  printf("max length of plaintext EES1087EP1 params: %i\n",ntru_max_msg_len(&EES1087EP1));
}

void rotor_show_help() {
  printf("rotor - version %i.%i\n(c)2016 mrn@sdf.org\n\n",ROTOR_MAJOR,ROTOR_MINOR);
  printf("syntax: rotor <options>\n");
  printf("--help:       show this help screen\n");
  printf("--version:    show version information\n");
  printf("--show-params:dump some NTRU parameter specs\n\n");
  printf("--keygen:     generate public and private keys\n");
  printf("              if no file names specified, use NTRUPrivate.key and NTRUPublic.key in current directory. will overwrite! be careful!\n\n");
  printf("--infile:     specify file to operate on\n");
  printf("--privkey:    specify name of private key, default NTRUPrivate.key\n");
  printf("--pubkey:     specify name of public key, default NTRUPublic.key\n");
  printf("--ext:        encrypt entire file with NTRU public key encryption with internal\n");
  printf("               SHAKE-256 mask, external Salsa20 mask\n");
  printf("              default is to encrypt header with NTRU and body with Salsa20^SHAKE256 stream\n");
  printf("--enc:        encrypt file specified by --infile\n");
  printf("--dec:        decrypt file specified by --infile\n");
  printf("\n\nthis is experimental software!!! you have been warned\n");
}
