
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
#include "rotor-crypt.h"
#include "rotor-keys.h"
#include "rotor-extra.h"
#include "shake.h"


int main(int argc, char *argv[]) {
  uint8_t plain[170];    
  char password_char[170];
  char pkname[64];
  char skname[64];
  char sfname[64];
  char ofname[64];
  int encMode = 0;
  int decMode = 0;
  int keyGen = 0;
  int show_params = 0;
  int inFile = 0;
    
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
    if (strcmp(argv[opc], "--dec") == 0) {
      decMode = 1;
      strncpy(ofname, sfname, 64);
      ofname[(strlen(sfname)-4)] = '\0';
    }
    if (strcmp(argv[opc], "--keygen") == 0) {
      keyGen = 1;
    }
    if (strcmp(argv[opc], "--version") == 0) {
      printf("rotor - version %i.%i\n(c)2016 mrn@sdf.org\n",ROTOR_MAJOR,ROTOR_MINOR);
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
    kr.priv = *krpr;
    printf("private key loaded\n");
  }

  printf("importing NTRU public key from file %s\n",pkname);

  krpub = (NtruEncPubKey *)malloc(sizeof(NtruEncPubKey));
  *krpub = rotor_load_armorpub(pkname);
  kr.pub = *krpub;
  printf("keys imported.\n");
 
  if (encMode == 1) {
    rotor_encrypt_file(kr, sfname, ofname);
  } 
  if (decMode == 1) {
    rotor_decrypt_file(kr, sfname, ofname);
  }
  free(krpr);
  free(krpub);
}
