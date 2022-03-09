#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "../sign.h"

#define MLEN 59
#define NTESTS 1

// Used in HexToByteArray
static int hexchr2bin(const char hex, char *out)
{
  if (out == NULL)
    return 0;
  if (hex >= '0' && hex <= '9') {
    *out = hex - '0';
  } else if (hex >= 'A' && hex <= 'F') {
    *out = hex - 'A' + 10;
  } else if (hex >= 'a' && hex <= 'f') {
    *out = hex - 'a' + 10;
  } else {
    return 0;
  }
  return 1;
}

// Used in reading "pk.txt"
static int HexToByteArray(const char *hex,size_t len, unsigned char *out)
{
  char   b1;
  char   b2;
  size_t i;
  if (hex == NULL || *hex == '\0' || out == NULL)
    return 0;
  if (len % 2 != 0)
    return 0;
  len /= 2;
  for (i=0; i<len; i++) {
    if (!hexchr2bin(hex[i*2], &b1) || !hexchr2bin(hex[i*2+1], &b2)) {
      return 0;
    }
    out[i] = (b1 << 4) | b2;
  }
  return len;
}

int main(void)
{
  unsigned int i;
  int ret;
  size_t mlen = MLEN;
  uint8_t sm[MLEN + CRYPTO_BYTES];
  uint8_t m2[MLEN + CRYPTO_BYTES];
  uint8_t pk[CRYPTO_PUBLICKEYBYTES];
  remove("recovered_bits.txt");

  for(i = 0; i < NTESTS; ++i) {

    // Reading public key from pk.txt
    FILE *pk_file;
    pk_file = fopen("pk.txt", "r");
    for (int pp=0; pp < CRYPTO_PUBLICKEYBYTES; pp++) {
      if (fscanf(pk_file,"%02x", (unsigned int *)&pk[pp])){
      }
    }
    fclose(pk_file);

    // Reading faulty signatures from "faulty_signatures.txt"
    FILE *faultysig_file;
    char * line=NULL;
    size_t len=0;
    ssize_t read;
    faultysig_file = fopen("faulty_signatures.txt", "r");
    if (faultysig_file == NULL){
      printf("Can not read faulty_signatures.txt\n");
      return -1;
    }

    while ((read = getline(&line, &len, faultysig_file)) != -1) {
      memset(sm, 0, CRYPTO_BYTES+MLEN);
      HexToByteArray(line, len, sm);
      ret = crypto_sign_open(m2, &mlen, sm, CRYPTO_BYTES+MLEN, pk);
      if(ret) {
        printf("\nVerification failed\n");
        
        // SIGNATURE CORRECTION ATTACK
        crypto_sign_open_signature_correction(m2, &mlen, sm, CRYPTO_BYTES+MLEN, pk);
      }
    }
    free(line);
    fclose(faultysig_file);
  }

  return 0;
}
