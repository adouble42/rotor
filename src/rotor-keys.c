/*****************************************************************************
 * (c) 2016 BSD 2 clause adouble42/mrn@sdf                                   *
 * rotor - "If knowledge can create problems, it is not through ignorance    * 
 * that we can solve them." -- isaac asimov                                  *
 *                                                                           *
 * rotor-keys.c - key management functions                                   *
 *****************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <termios.h>
#include "ntru.h"
#include "shake.h"
#include "yescrypt.h"
#include "passwdqc.h"
#include "blake512.h"
#include "rotor.h"
#include "rotor-keys.h"
#include "progressbar.h"

#ifdef __ROTOR_MLOCK
#include <sys/mman.h>
#endif

char const *strip="\r\n"; // strip newlines from armored keys

int zstring_search_chr(const char *token,char s){
    if (!token || s=='\0')
        return 0;

    for (;*token; token++)
        if (*token == s)
            return 1;

    return 0;
}

char *zstring_remove_chr(char *str,const char *bad) {
    char *src = str , *dst = str;
    while(*src)
        if(zstring_search_chr(bad,*src))
            src++;
        else
            *dst++ = *src++;  /* assign first, then incement */

    *dst='\0';
        return str;
}

/* utility function to convert hex character representation to their 
 * nibble (4 bit) values
 */
static uint8_t
nibbleFromChar(char c)
{
  if(c >= '0' && c <= '9') return c - '0';
  if(c >= 'a' && c <= 'f') return c - 'a' + 10;
  if(c >= 'A' && c <= 'F') return c - 'A' + 10;
  return 255;
}

/* Convert a string of characters representing a hex buffer into a 
 * series of bytes of that real value
 */
void
hexStringToBytes(char *inhex, uint8_t *arr, int keysize)
{
  if (!arr) arr = (uint8_t *)malloc(keysize*sizeof(uint8_t));
  uint8_t *retval;
  uint8_t *p;
  int len, i;

  len = strlen(inhex) / 2;
  for(i=0, p = (uint8_t *) inhex; i<len; i++) {
    arr[i] = (nibbleFromChar(*p) << 4) | nibbleFromChar(*(p+1));
    p += 2;
  }
}

static char byteMap[] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };
static int byteMapLen = sizeof(byteMap);

/* Utility function to convert nibbles (4 bit values) into a hex 
character representation */
static char
nibbleToChar(uint8_t nibble)
{
  if(nibble < byteMapLen) return byteMap[nibble];
  return '*';
}

char
*bytesToHexString(uint8_t *bytes, size_t buflen)
{
  char *retval;
  int i,count,sz;

  retval = malloc(buflen*2 + 1);
  for(i=0; i<buflen; i++) {
    retval[(i)*2] = nibbleToChar(bytes[i] >> 4);
    retval[(i)*2+1] = nibbleToChar(bytes[i] & 0x0f);
  }
  retval[i*2+1] = '\0';
  return retval;
}

/*
 * rotor key management functions
 *
 * rotor_keypair_generate: generate a new rotor NTRU keypair
 *
 */


struct NtruEncKeyPair rotor_keypair_generate() {
  NtruEncKeyPair keypair;
  NtruRandGen rng = NTRU_RNG_DEFAULT;
  NtruRandContext rand_ctx;

#ifdef __ROTOR_MLOCK
  mlock(&keypair, sizeof(NtruEncKeyPair));
  mlock(&rng, sizeof(NtruRandGen));
  mlock(&rand_ctx, sizeof(NtruRandContext));
#endif
  
  if (ntru_rand_init(&rand_ctx, &rng) != NTRU_SUCCESS)
      printf("rotor_keypair_generate: rng fail\n");
  if (ntru_gen_key_pair(&EES1087EP2, &keypair, &rand_ctx) != NTRU_SUCCESS)
      printf("rotor_keypair_generate: keygen fail\n");
  ntru_rand_release(&rand_ctx);
#ifdef __ROTOR_MLOCK
  munlock(&rng, sizeof(rng));
  munlock(&rand_ctx, sizeof(rand_ctx));
#endif
  return(keypair);
}

/*
 * rotor_exp_armorpriv: export encrypted, armored rotor private key
 */

void rotor_exp_armorpriv(uint8_t *priv_keyx, char *secret, int s_len, char *outfile) {
  uint8_t shk_outp[NTRU_PRIVLEN];
  uint8_t shk_finalp[NTRU_PRIVLEN];
  char header_privline[PRIVATE_TLEN];
  char armored_key[NTRU_PRIVLEN*2];
  FILE *Out=NULL;
  int i, x, progress;

#ifdef __ROTOR_MLOCK
  mlock(&shk_outp, (sizeof(uint8_t)*NTRU_PRIVLEN));
  mlock(&shk_finalp, (sizeof(uint8_t)*NTRU_PRIVLEN));
  mlock(&secret, sizeof(secret));
  mlock(&priv_keyx, sizeof(priv_keyx));
#endif
  
  sprintf(header_privline,"%s\n", PRIVATE_KEYTAG);
  FIPS202_SHAKE256((uint8_t *)secret, s_len, (uint8_t *)shk_outp, NTRU_PRIVLEN);
  progress = KDF_ROUNDS/100;
  progressbar *cpro = progressbar_new("deriving stream key ",100);

  for (i=0; i<KDF_ROUNDS; i++) { // put the lime in the coconut
    if (i == progress) {
      progressbar_inc(cpro);
      progress = progress + (KDF_ROUNDS/100);
    }
    FIPS202_SHAKE256(shk_outp, NTRU_PRIVLEN, (uint8_t *)shk_finalp, NTRU_PRIVLEN);
    FIPS202_SHAKE256(shk_finalp, NTRU_PRIVLEN, (uint8_t *)shk_outp, NTRU_PRIVLEN);
  }
  progressbar_inc(cpro);
  progressbar_finish(cpro);
  Out=fopen(outfile,"wb");
  if(Out!=NULL)
  {
    fwrite(header_privline,sizeof(char),sizeof(header_privline),Out);
    int xl;
    FIPS202_SHAKE256(shk_outp, NTRU_PRIVLEN, (uint8_t *)shk_finalp, NTRU_PRIVLEN);
    for (xl=0;xl<NTRU_PRIVLEN;xl++) {
      shk_outp[xl] = priv_keyx[xl] ^ shk_finalp[xl];
    }
    strncpy (armored_key, bytesToHexString(shk_outp,NTRU_PRIVLEN), (NTRU_PRIVLEN*2));
    x=0;
    for (i=0;i<(NTRU_PRIVLEN*2);i++) {
      x++;
      fwrite(&armored_key[i],1,1,Out);
      if (x==72) {
	fwrite("\n",1,1,Out);
	x=0;
      }
    }
#ifdef __ROTOR_MLOCK
  munlock(&shk_outp, (sizeof(uint8_t)*NTRU_PRIVLEN));
  munlock(&shk_finalp, (sizeof(uint8_t)*NTRU_PRIVLEN));
  munlock(&secret, sizeof(secret));
  munlock(&priv_keyx, sizeof(priv_keyx));
#endif
    fwrite("\n",1,1,Out);
    for (i=0;i<((sizeof(header_privline))-1);i++) {
      fwrite("-",1,1,Out);
    }
    fwrite("\n",1,1,Out);
    fclose(Out);
  }
}

/*
 * rotor_exp_armorpub: export armored rotor public key
 */

void rotor_exp_armorpub(uint8_t *pub_keyx, char *outfile) {
  char header_publine[PUBLIC_TLEN];
  char armored_key[NTRU_PUBLEN*2];
  int i,x;
  FILE *Out=NULL;

  Out=fopen(outfile,"wb");
  sprintf(header_publine,"%s\n", PUBLIC_KEYTAG);
  strncpy (armored_key, bytesToHexString(pub_keyx,NTRU_PUBLEN), (NTRU_PUBLEN*2));
  if(Out!=NULL)
  {
    fwrite(header_publine,sizeof(char),sizeof(header_publine),Out);
    x=0;
    for (i=0;i<(NTRU_PUBLEN*2);i++) {
      x++;
      fwrite(&armored_key[i],1,1,Out);
      if (x==72) {
	fwrite("\n",1,1,Out);
	x=0;
      }
    }
    fwrite("\n",1,1,Out);
    for (i=0;i<((sizeof(header_publine))-1);i++) {
      fwrite("-",1,1,Out);
    }
    fwrite("\n",1,1,Out);
    fclose(Out);
  }
}

/*
 * rotor_load_armorpriv: import encrypted, armored rotor private key
 */

struct NtruEncPrivKey rotor_load_armorpriv(const uint8_t *secret, int s_len, char *infile) {
  NtruEncPrivKey kr_out;
  yescrypt_local_t locald;
  const char *salt = "saljy";
  uint8_t dk[64];
  uint8_t shk_outp[NTRU_PRIVLEN];
  uint8_t shk_finalp[NTRU_PRIVLEN];
  uint8_t priv_imp[NTRU_PRIVLEN];
  char p_buf[(sizeof(priv_imp)*2)+30];
  char p_buf2[(sizeof(priv_imp)*2)+30];
  char header_privline[PRIVATE_TLEN];
  char *stripchars = "\r\n";
  FILE *In=NULL;
  int i, progress;

  yescrypt_init_local(&locald);
  printf("modified yescrypt KDF initialized\n");
  printf("current yescrypt parameters: 32/8/8/12/9/RW/64\n");
  printf("instead of just a couple rounds of PBKDF, we do a few hundred.\nthis gets you in the front door.\n");
  printf("enhanced with BLAKE 256 - https://131002.net/blake/\n");
  yescrypt_kdf(NULL, &locald, secret, strlen((char *)secret), (uint8_t *) salt, strlen (salt), 32, 8, 8, 12, 9, YESCRYPT_RW, dk, 64);
  yescrypt_free_local(&locald);
  _passwdqc_memzero(&secret, strlen(secret)); // best way to keep a secret:
  printf("now for the next key derivation -SHAKE 256.\n\n");
  FIPS202_SHAKE256(dk, 64, (uint8_t *)shk_finalp, 170);
  _passwdqc_memzero(&dk, 64); // kill everyone else who knows!
  progress = KDF_ROUNDS/100;
  In=fopen(infile,"rb");
  sprintf(header_privline,"%s\n", PRIVATE_KEYTAG);
  if (In!=NULL) {
    FIPS202_SHAKE256(shk_finalp, 170, (uint8_t *)shk_outp, NTRU_PRIVLEN);
    progressbar *cpro = progressbar_new("processing decryption key ",100);
    for (i=0; i<KDF_ROUNDS; i++) { // put the lime in the coconut
      if (i == progress) {
	progressbar_inc(cpro);
	progress = progress + (KDF_ROUNDS/100);
      }
      FIPS202_SHAKE256(shk_outp, NTRU_PRIVLEN, (uint8_t *)shk_finalp, NTRU_PRIVLEN);
      FIPS202_SHAKE256(shk_finalp, NTRU_PRIVLEN, (uint8_t *)shk_outp, NTRU_PRIVLEN);
    }
    _passwdqc_memzero(&shk_finalp, sizeof(shk_finalp)); // no intermediates
    progressbar_inc(cpro);
    progressbar_finish(cpro);
    FIPS202_SHAKE256(shk_outp, NTRU_PRIVLEN, (uint8_t *)shk_finalp, NTRU_PRIVLEN);
    _passwdqc_memzero(&shk_outp, sizeof(shk_outp)); // get it yet?
    printf("loading encrypted private key from file\n");
    fseek(In, sizeof(header_privline), SEEK_SET);
    fread(p_buf, (sizeof(char)), (NTRU_PRIVLEN*2)+30, In);
    hexStringToBytes(zstring_remove_chr(p_buf,strip), (uint8_t *)priv_imp, NTRU_PRIVLEN);
    _passwdqc_memzero(&p_buf, sizeof(p_buf));
    for (i=0; i<NTRU_PRIVLEN; i++) {
      shk_outp[i] = priv_imp[i] ^ shk_finalp[i];
    }
    _passwdqc_memzero(&priv_imp, sizeof(priv_imp)); // yawwwwwn
    _passwdqc_memzero(&shk_finalp, sizeof(shk_finalp));
    fclose(In);
    printf("key decrypted.\n");
    ntru_import_priv(shk_outp, &kr_out);
    _passwdqc_memzero(&shk_outp, sizeof(shk_outp)); // burn it with fire!!!
    return(kr_out);
  }
}

/*
 * rotor_load_armorpub: import armored rotor public key
 */

struct NtruEncPubKey rotor_load_armorpub(char *infile) {
  NtruEncPubKey kp_out;
  char p_buf[(1499*2)+60];
  char p_buf2[(1499*2)+60];
  uint8_t pub_imp[NTRU_PUBLEN];
  char header_publine[PUBLIC_TLEN];

  char *stripchars = "\r\n";
  FILE *In=NULL;

  In=fopen(infile, "rb");
  sprintf(header_publine,"%s\n", PUBLIC_KEYTAG);
  if (In!=NULL) {
    fseek(In, sizeof(header_publine), SEEK_SET);
    fread(p_buf,(sizeof(char)), (ntru_pub_len(&EES1087EP2)*2)+60, In);
    hexStringToBytes(zstring_remove_chr(p_buf,strip), (uint8_t *)pub_imp, ntru_pub_len(&EES1087EP2));
    fclose(In);
    ntru_import_pub(pub_imp, &kp_out);

        return(kp_out);
  }      
}

void rotor_user_keygen(char *skname, char *pkname) {
  static struct termios oldt, newt;
  NtruEncKeyPair kp;
  NtruRandGen rng = NTRU_RNG_DEFAULT;
  NtruRandContext rand_ctx;
  passwdqc_params_t params;
  yescrypt_local_t locald;
  uint8_t pub_arr[NTRU_PUBLEN];
  uint8_t priv_arr[NTRU_PRIVLEN];
  uint8_t secret[64];
  uint8_t verify[64];
  const char *salt = "saljy";
  const char *check_reason;
  char password_char[170];
  uint8_t dk[64];
  uint8_t dkt[64];
  int i, dklen,v,ok_pass;
  dklen=64;
  v=1;
  
  tcgetattr(STDIN_FILENO, &oldt); // kill the lights
  newt=oldt;
  newt.c_lflag &= ~(ECHO);
  tcsetattr(STDIN_FILENO, TCSANOW, &newt);

  passwdqc_params_reset(&params);

  do {
    printf("choose a strong passphrase to protect your private key: ");
    ok_pass=0;
    if (secret) {
      _passwdqc_memzero(&secret, strlen(secret));
    }
    fgets(secret, 64, stdin);
    check_reason = passwdqc_check(&params.qc, secret, NULL, NULL);
    if (!check_reason) {
      ok_pass = 1;
      printf("OK\n");
    } else {
      printf("\nBad passphrase: (%s)\n", check_reason);
    }
    if ((v == 1) && (ok_pass == 1)) {
      printf("reenter to confirm: ");
      fgets(verify, 64, stdin);
      printf("\n");
    }
  } while (((v == 1) && (ok_pass == 0) && (strncmp(secret, verify, strlen(secret)))));
  _passwdqc_memzero(&verify, strlen(verify));
  tcsetattr(STDIN_FILENO, TCSANOW, &oldt); // lights on

  yescrypt_init_local(&locald);
  printf("modified yescrypt KDF initialized\n");
  printf("current yescrypt parameters: 32/8/8/12/9/RW/64\n");
  printf("instead of just a couple rounds of PBKDF, we do a few hundred.\nthis gets you in the front door.\n");
  printf("enhanced with BLAKE 256 - https://131002.net/blake/\n");
  yescrypt_kdf(NULL, &locald, secret, strlen((char *)secret), (uint8_t *) salt, strlen (salt), 32, 8, 8, 12, 9, YESCRYPT_RW, dk, 64);
  yescrypt_free_local(&locald);
  _passwdqc_memzero(&secret, strlen(secret)); // don't need this any more
  printf("now for the next key derivation -SHAKE 256.\n\n");
  FIPS202_SHAKE256(dk, 64, (uint8_t *)password_char, 170);
  _passwdqc_memzero(&dk, 64); // or this
  kp = rotor_keypair_generate(); // generate keypair
  ntru_export_pub(&kp.pub, pub_arr);
  ntru_export_priv(&kp.priv, priv_arr);
  _passwdqc_memzero(&kp, sizeof(kp)); // aaand this can go
  rotor_exp_armorpriv(priv_arr, password_char, 170, skname);
  _passwdqc_memzero(&priv_arr, NTRU_PRIVLEN); // buh
  printf("exporting hex armored NTRU public key to file %s\n", pkname);
  rotor_exp_armorpub(pub_arr, pkname);
  _passwdqc_memzero(&pub_arr, NTRU_PUBLEN); // bye
}
