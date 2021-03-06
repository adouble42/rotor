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
#ifndef __ROTOR_CRYPT_H
#define __ROTOR_CRYPT_H

/*
 * rotor encryption and decryption master functions
 *
 * rotor_decrypt_file: use keypair to decrypt file
 *
 */

void rotor_decrypt_file(NtruEncKeyPair kr, char *sfname, char *ofname, char *keyfname);

/*
 * rotor encryption and decryption master functions
 *
 * rotor_encrypt_file: use keypair to encrypt file
 *
 */

void rotor_encrypt_file(NtruEncKeyPair kr, char *sfname, char *ofname, char *keyfname);

/*
 * rotor encryption and decryption master functions
 *
 * rotor_decrypt_file: use keypair to decrypt file
 *
 */

void rotor_decrypt_file_sym(NtruEncKeyPair kr, char *sfname, char *ofname);

/*
 * rotor encryption and decryption master functions
 *
 * rotor_encrypt_file: use keypair to encrypt file
 *
 */

void rotor_encrypt_file_sym(NtruEncKeyPair kr, char *sfname, char *ofname);


#endif
