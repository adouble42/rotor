/*****************************************************************************
 * (c) 2016 BSD 2 clause adouble42/mrn@sdf                                   *
 * rotor - "If knowledge can create problems, it is not through ignorance    * 
 * that we can solve them." -- isaac asimov                                  *
 *                                                                           *
 * rotor-console.c - console functions                                       *
 *****************************************************************************/
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include "rotor.h"
#include "rotor-console.h"
#include "ntru.h"

/*
 * rotor_console_secret: we've got fgets, how bout fgetsecrets
 * msg - message to user; secret_len - how long; v - 1 verifies
 *
 */


void rotor_console_secret(uint8_t *pass, char *msg, int secret_len, int v) {
  static struct termios oldt, newt;
  //pass = (uint8_t *)malloc(64*sizeof(uint8_t));;
  uint8_t secret[64];
  uint8_t verify[64];
  int i;
  
  tcgetattr(STDIN_FILENO, &oldt);
  newt=oldt;
  newt.c_lflag &= ~(ECHO);
  tcsetattr(STDIN_FILENO, TCSANOW, &newt);
  do {
    printf("choose a strong passphrase to protect your private key: ",msg);
    fgets(secret, secret_len, stdin);
    printf("\n");
    if (v == 1) {
      printf("reenter to confirm: ");
      fgets(verify, secret_len, stdin);
      printf("\n");
    }
  } while (((v == 1) && (strncmp(secret, verify, strlen(secret)))));
  strcpy(*pass, (char *)secret);
  pass[strlen((char *)secret)] = '\0';
  printf("%s\n",(const char *)pass);
  tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
}
