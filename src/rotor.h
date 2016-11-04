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
#ifndef __ROTOR_H
#define __ROTOR_H

// whether or not to use mlock() and mlockall() functions to make sure
// security sensitive constructs are held in wired memory and not swapped
// even if the swap is encrypted we shouldn't trust it

#ifndef __ROTOR_MLOCK
#ifndef __APPLE__
#define __ROTOR_MLOCK
#endif
#endif


#define ROTOR_MAJOR 0
#define ROTOR_MINOR 77

// we define NTRU parameter values because of CompCert build
// arrays must be defined at compile time

#define NTRU_PRIVLEN 339
#define NTRU_ENCLEN 1495
#define NTRU_PUBLEN 1499
#define PRIVATE_TLEN 39
#define PUBLIC_TLEN 38

#define PRIVATE_KEYTAG "-----BEGIN NTRU PRIVATE KEY BLOCK-----"
#define PUBLIC_KEYTAG "-----BEGIN NTRU PUBLIC KEY BLOCK-----"

struct fileHeader {
  int fileSize;
};

#define burn(mem,size) do { volatile char *burnm = (volatile char *)(mem); int burnc = size; while (burnc--) *burnm++ = 0; } while (0)

#endif
