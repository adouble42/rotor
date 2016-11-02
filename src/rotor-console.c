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


const char *rotor_console_secret(char *msg, int secret_len, int v) {
  char *secret =(char *)malloc((sizeof(char))*secret_len);
  static struct termios oldt, newt;
  char *verify =(char *)malloc((sizeof(char))*secret_len);
  
  tcgetattr(STDIN_FILENO, &oldt);
  newt=oldt;
  newt.c_lflag &= ~(ECHO);
  tcsetattr(STDIN_FILENO, TCSANOW, &newt);
  do {
    printf("%s",msg);
    fgets(secret, secret_len, stdin);
    printf("\n");
    if (v == 1) {
      printf("reenter to confirm: ");
      fgets(verify, secret_len, stdin);
      printf("\n");
    }
  } while (((v == 1) && (strncmp(secret, verify, strlen(secret)))));
  tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
  free(verify);
  return (secret);
}
