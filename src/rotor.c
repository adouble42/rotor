
/*****************************************************************************
 * (c) 2016 BSD 2 clause adouble42/mrn@sdf                                   *
 * rotor - "If knowledge can create problems, it is not through ignorance    * 
 * that we can solve them." -- isaac asimov                                  *
 *                                                                           *
 * lightweight NTRU public key in block mode, with SHAKE-256 stream cipher   *
 *****************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <termios.h>
#include <unistd.h>
#include <string.h>
#include "ntru.h"
#include "rotor.h"
#include "yescrypt.h"
#include "passwdqc.h"
#include "rotor-crypt.h"
#include "rotor-keys.h"
#include "rotor-extra.h"
#include "shake.h"

#ifdef __ROTOR_MLOCK
#include <sys/mman.h>
#endif

int main(int argc, char *argv[]) {
  uint8_t plain[170];    
  char password_char[170];
  char pkname[64];
  char skname[64];
  char sfname[64];
  char ofname[64];
  char keyfname[64];
  int encMode = 0;
  int extMode = 0;
  int decMode = 0;
  int keyGen = 0;
  int show_params = 0;
  int inFile = 0;

  printf("rotor - version %i.%i\n(c)2016 mrn@sdf.org\n",ROTOR_MAJOR,ROTOR_MINOR);
#ifdef __ROTOR_MLOCK
  printf("rotor was built with use of mlock() and mlockall() enabled. sensitive data will not be swapped to disk.\n\n");
#endif
#ifndef __ROTOR_MLOCK
  printf("rotor was not built with use of mlock() and mlockall() enabled.\n this may result in sensitive information being swapped to disk, although sensitive data is burned immediately after use.\n\n");
#endif
  
  strcpy (pkname, "NTRUPublic.key");
  strcpy (skname, "NTRUPrivate.key");
  int opc;
  for (opc = 1; opc < argc; opc++) {
    if (strcmp(argv[opc], "--pubkey") == 0) {
      strncpy(pkname, argv[opc+1], 64);
      opc++;
    }
    if (strcmp(argv[opc], "--privkey") == 0) {
      strncpy(skname, argv[opc+1], 64);
      opc++;
    }
    if (strcmp(argv[opc], "--infile") == 0) {
      inFile = 1;
      if (argv[opc+1]) {
        strncpy(sfname, argv[opc+1], 64);
        opc++;
      }
    }
    if (strcmp(argv[opc], "--enc") == 0) {
      encMode = 1;
      strncpy(ofname, sfname, 64);
      strncat(ofname, ".enc", 64);
    }
    if (strcmp(argv[opc], "--ext") == 0) {
      extMode = 1;
      strncpy(keyfname, sfname, 64);
      strncat(keyfname, ".key", 64);
    }
    if (strcmp(argv[opc], "--dec") == 0) {
      decMode = 1;
      strncpy(ofname, sfname, 64);
      ofname[(strlen(sfname)-4)] = '\0';
    }
    if (strcmp(argv[opc], "--keygen") == 0) {
      keyGen = 1;
    }
    if (strcmp(argv[opc], "--version") == 0) {
      exit(0);
    }
    if (strcmp(argv[opc], "--show-params") == 0) {
      rotor_show_ntru_params();
      exit(0);
    }	
    if (strcmp(argv[opc], "--help") == 0) {
      rotor_show_help();
      exit(0);
    }
  }
  if (((keyGen != 1) && (opc <= 2)) || ((opc <= 3) && (inFile == 1))) {
    rotor_show_help();
    exit(0);
  }
  if (keyGen == 1) {
    rotor_user_keygen(skname, pkname);
    exit(0);
  }

  NtruEncKeyPair kr; // recover from file
  NtruEncPrivKey *krpr;
  NtruEncPubKey *krpub;
          
  if (decMode == 1) { // don't load it unless we need it
    static struct termios oldt, newt;
    uint8_t secret[64];

#ifdef __ROTOR_MLOCK
    mlockall(MCL_CURRENT);
#endif
    
    tcgetattr(STDIN_FILENO, &oldt); // kill the lights
    newt=oldt;
    newt.c_lflag &= ~(ECHO);
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);
    printf("enter passphrase to begin unlocking private key: ");
    fgets(secret, 64, stdin);
    printf("\n");
    tcsetattr(STDIN_FILENO, TCSANOW, &oldt); // lights on
    
    krpr = (NtruEncPrivKey *)malloc(sizeof(NtruEncPrivKey));
    *krpr = rotor_load_armorpriv(secret, strlen(secret), skname);
    _passwdqc_memzero(&secret, sizeof(secret)); // done with you
    kr.priv = *krpr;
    printf("private key loaded\n");
  }

  printf("importing NTRU public key from file %s\n",pkname);

  krpub = (NtruEncPubKey *)malloc(sizeof(NtruEncPubKey));
  *krpub = rotor_load_armorpub(pkname);
  kr.pub = *krpub;
  printf("keys imported.\n");
 
  if ((encMode == 1) && (extMode == 0)) {
    printf("encrypting using NTRU header only, Salsa20-SHAKE OFB stream.\n");
    rotor_encrypt_file_sym(kr, sfname, ofname);
  } 
  if ((decMode == 1) && (extMode == 0)){
    printf("decrypting using NTRU header only, Salsa20-SHAKE OFB stream.\n");
    rotor_decrypt_file_sym(kr, sfname, ofname);
  }
  if ((encMode == 1) && (extMode == 1)) {
    printf("encrypting using NTRU full length of file.\n");
    rotor_encrypt_file(kr, sfname, ofname, keyfname);
  } 
  if ((decMode == 1) && (extMode == 1)){
    printf("decrypting using NTRU full length of file.\n");
    rotor_decrypt_file(kr, sfname, ofname, keyfname);
  }

  _passwdqc_memzero(&kr, sizeof(kr)); // don't hold on to the past
  _passwdqc_memzero(&krpr, sizeof(krpr)); // it inhibits growth
  free(krpr);
  free(krpub);
  #ifdef __ROTOR_MLOCK
  if (decMode == 1) {
    munlockall();
  }
  #endif
}
