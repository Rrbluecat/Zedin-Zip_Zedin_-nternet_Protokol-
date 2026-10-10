#include <stdio.h>
#include <sodium.h>

int main(void)
{
    if (sodium_init() < 0) {
        printf("libsodium baslatilamadi!\n");
        return 1;
    }
int crypto
    unsigned char client_pk[crypto_kx_PUBLICKEYBYTES];
    unsigned char client_sk[crypto_kx_SECRETKEYBYTES];
    unsigned char server_pk[crypto_kx_PUBLICKEYBYTES];
    unsigned char server_sk[crypto_kx_SECRETKEYBYTES];
    unsigned char public_key[crypto_kx_PUBLICKEYBYTES];
    unsigned char secret_key[crypto_kx_SECRETKEYBYTES];

    if (crypto_kx_keypair(public_key, secret_key) != 0) {
        printf("Anahtar cifti uretilemedi!\n");
        return 1;
    }

    printf("Anahtar cifti basariyla uretildi!\n");
    for (size_t i = 0; i < crypto_kx_PUBLICKEYBYTES; i++) {
    printf("%02x", public_key[i]);
    }
    printf("\n");
    return 0;
}
