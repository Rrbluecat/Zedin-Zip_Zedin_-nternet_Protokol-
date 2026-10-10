/*
 * Dosya: kx_test_phase1.c
 * Sorumluluk: ZIP Projesi Aşama 1 - X25519 / crypto_kx Session Key Otomatik Testi
 * Platform: Termux / Linux / ARM64
 */

#include <stdio.h>
#include <sodium.h>

int main(void)
{
    // 1. libsodium Başlatma
    if (sodium_init() < 0) {
        printf("[HATA] libsodium baslatilamadi!\n");
        return 1;
    }

    // 2. Client Anahtar Çifti Değişkenleri
    unsigned char client_pk[crypto_kx_PUBLICKEYBYTES];
    unsigned char client_sk[crypto_kx_SECRETKEYBYTES];

    // 3. Server Anahtar Çifti Değişkenleri
    unsigned char server_pk[crypto_kx_PUBLICKEYBYTES];
    unsigned char server_sk[crypto_kx_SECRETKEYBYTES];

    // 4. Session Key Değişkenleri
    unsigned char client_rx[crypto_kx_SESSIONKEYBYTES];
    unsigned char client_tx[crypto_kx_SESSIONKEYBYTES];
    unsigned char server_rx[crypto_kx_SESSIONKEYBYTES];
    unsigned char server_tx[crypto_kx_SESSIONKEYBYTES];

    int test_status = 0; // 0 = Başarılı, 1 = Hata

    // 5. Client Keypair Üretimi
    if (crypto_kx_keypair(client_pk, client_sk) != 0) {
        printf("[HATA] Client anahtar cifti uretilemedi!\n");
        return 1;
    }

    // 6. Server Keypair Üretimi
    if (crypto_kx_keypair(server_pk, server_sk) != 0) {
        printf("[HATA] Server anahtar cifti uretilemedi!\n");
        sodium_memzero(client_sk, sizeof(client_sk));
        return 1;
    }

    // 7. Client Tarafı Session Key Hesaplama
    if (crypto_kx_client_session_keys(client_rx, client_tx,
                                     client_pk, client_sk,
                                     server_pk) != 0) {
        printf("[HATA] Client oturum anahtarlari hesaplanamadi!\n");
        test_status = 1;
        goto cleanup;
    }

    // 8. Server Tarafı Session Key Hesaplama
    if (crypto_kx_server_session_keys(server_rx, server_tx,
                                     server_pk, server_sk,
                                     client_pk) != 0) {
        printf("[HATA] Server oturum anahtarlari hesaplanamadi!\n");
        test_status = 1;
        goto cleanup;
    }

    // 9. Otomatik Test ve Constant-Time Karşılaştırma
    // Beklenen İlişki: client_tx == server_rx AND client_rx == server_tx
    int match_tx_rx = (sodium_memcmp(client_tx, server_rx, crypto_kx_SESSIONKEYBYTES) == 0);
    int match_rx_tx = (sodium_memcmp(client_rx, server_tx, crypto_kx_SESSIONKEYBYTES) == 0);

    if (match_tx_rx && match_rx_tx) {
        printf("[BASARILI] Session key eslesmesi ve simetri testi gecti.\n");
        printf("          client_tx == server_rx : DOGRU\n");
        printf("          client_rx == server_tx : DOGRU\n");
    } else {
        printf("[HATA] Session key eslesmesinde uyumsuzluk tespit edildi!\n");
        test_status = 1;
    }

cleanup:
    // 10. Hassas Verilerin Bellekten Güvenli Şekilde Temizlenmesi
    sodium_memzero(client_sk, sizeof(client_sk));
    sodium_memzero(server_sk, sizeof(server_sk));
    sodium_memzero(client_rx, sizeof(client_rx));
    sodium_memzero(client_tx, sizeof(client_tx));
    sodium_memzero(server_rx, sizeof(server_rx));
    sodium_memzero(server_tx, sizeof(server_tx));

    return test_status;
}

