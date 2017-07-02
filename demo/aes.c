#include <stdlib.h>
#include <string.h>
#include <gcrypt.h>
#include <unistd.h>
#include "disp.h"


#define GCRY_CIPHER GCRY_CIPHER_AES128   // Pick the cipher here
#define GCRY_MODE GCRY_CIPHER_MODE_ECB // Pick the cipher mode here

void aesTest(void)
{
    gcry_cipher_hd_t handle;
    size_t keyLength = gcry_cipher_get_algo_keylen(GCRY_CIPHER);

    char* txtBuffer ="123456789 abcdefghijklmnopqrstuvwzyz ABCDEFGHIJKLMNOPQRSTUVWZYZ";
    size_t txtLength = strlen(txtBuffer) +1; // string plus termination
    char * encBuffer = (char *)malloc(txtLength);
    char * outBuffer = (char *)malloc(txtLength);

    char * key = "one test AES key"; // 16 bytes

    gcry_control (GCRYCTL_DISABLE_SECMEM, 0);

    gcry_control (GCRYCTL_INITIALIZATION_FINISHED, 0);

    gcry_cipher_open(&handle, GCRY_CIPHER, GCRY_MODE, 0);

    gcry_cipher_setkey(handle, key, keyLength);

    gcry_cipher_encrypt(handle, encBuffer, txtLength, txtBuffer, txtLength);

    gcry_cipher_decrypt(handle, outBuffer, txtLength, encBuffer, txtLength);

    size_t index;
    printf("encBuffer = ");
    for (index = 0; index<txtLength; index++)
        printf("%c", encBuffer[index]);
    printf("\n");

    printf("outBuffer = %s\n", outBuffer);

    gcry_cipher_close(handle);
    free(encBuffer);
    free(outBuffer);
}


int _main() {
    aesTest();
    return 0;
}

int main() {
	disp_init();
	while (1) {
		_main();
		sleep(10);
	}
	return 0;

}
