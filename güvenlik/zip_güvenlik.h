#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/err.h>

int main(){
    unsigned char public_key[32];
    unsigned char arayuz_public_key[32];
    unsigned char paylasilan_gizli[32];
    EVP_PKEY_CTX *ctx;
    EVP_PKEY *anahtar;
    EVP_PKEY *karsi_arayuz;
    EVP_PKEY_CTX *derive_ctx;
    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
    if (EVP_PKEY_keygen_init(ctx) <= 0){
       printf("X25519 baslatilamadi!\n");
    }
    else{
       printf("Devam et yoldas!\n");
    }
    if (EVP_PKEY_keygen(ctx, &anahtar) <= 0){
       printf("X25519 anahtari uretilemedi");
    }
    else{
       printf("X25519 anahtari uretildi");
    }
    size_t public_key_uzunlugu = sizeof(public_key);
    EVP_PKEY_get_raw_public_key(anahtar,public_key,&public_key_uzunlugu);
    karsi_arayuz = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, arayuz_public_key, 32);
    ctx = EVP_PKEY_CTX_new(anahtar, NULL);
    derive_ctx = EVP_PKEY_derive_init(derive_ctx);
    if (EVP_PKEY_derive_init(derive_ctx) != 0){
        printf("Hata anahtar olusturulamadi!");
    }
    EVP_PKEY_derive_set_peer(derive_ctx, karsi_arayuz);
}
