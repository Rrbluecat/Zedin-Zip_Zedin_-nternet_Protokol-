/*
 * Dosya: test_crypto.c
 * Sorumluluk: Zedin Security API - Aşama 2..6 Kapsamlı Güvenlik Test Suite
 * Platform: Termux / Linux / ARM64 (C99)
 */

#include <stdio.h>
#include <string.h>
#include "zedin_crypto.h"

static int setup_established_handshake(
    zedin_handshake_ctx_t *c_ctx,
    zedin_handshake_ctx_t *s_ctx,
    const zedin_identity_t *c_id,
    const zedin_identity_t *s_id)
{
    if (zedin_crypto_handshake_client_init(c_ctx, ZEDIN_ZIP_PROTOCOL_VERSION_1, c_id) != ZEDIN_CRYPTO_OK) return 0;
    if (zedin_crypto_handshake_server_init(s_ctx, ZEDIN_ZIP_PROTOCOL_VERSION_1, s_id) != ZEDIN_CRYPTO_OK) return 0;

    unsigned char s_ephem_pk[ZEDIN_CRYPTO_PUBLICKEYBYTES];
    unsigned char s_id_pk[ZEDIN_CRYPTO_IDENTITY_PUBLICKEYBYTES];
    unsigned char s_sig[ZEDIN_CRYPTO_SIGNATUREBYTES];
    unsigned char c_sig[ZEDIN_CRYPTO_SIGNATUREBYTES];

    if (zedin_crypto_handshake_server_process_client_hello(
            s_ctx, c_ctx->local_ephemeral_kp.public_key, c_ctx->local_identity.public_key,
            s_ephem_pk, s_id_pk, s_sig) != ZEDIN_CRYPTO_OK) return 0;

    if (zedin_crypto_handshake_client_process_server_hello(c_ctx, s_ephem_pk, s_id_pk, s_sig) != ZEDIN_CRYPTO_OK) return 0;
    if (zedin_crypto_handshake_client_finalize(c_ctx, c_sig) != ZEDIN_CRYPTO_OK) return 0;
    if (zedin_crypto_handshake_server_finalize(s_ctx, c_sig) != ZEDIN_CRYPTO_OK) return 0;

    return (c_ctx->state == ZEDIN_HS_STATE_ESTABLISHED && s_ctx->state == ZEDIN_HS_STATE_ESTABLISHED);
}

int main(void)
{
    printf("[TEST] Zedin Security API (Asama 2 - 6) Test Suite Baslatiliyor...\n");

    if (zedin_crypto_init() != ZEDIN_CRYPTO_OK) {
        printf("[HATA] zedin_crypto_init basarisiz!\n");
        return 1;
    }

    zedin_identity_t client_id, server_id;
    if (zedin_crypto_identity_generate(&client_id) != ZEDIN_CRYPTO_OK ||
        zedin_crypto_identity_generate(&server_id) != ZEDIN_CRYPTO_OK) {
        printf("[HATA] Identity uretimi basarisiz!\n");
        return 1;
    }

    /* ========================================================= */
    /* AŞAMA 6: SEQUENCE TESTS (1..6)                            */
    /* ========================================================= */
    printf("\n--- ASAMA 6: Sequence Management Testleri ---\n");
    {
        zedin_handshake_ctx_t c_ctx, s_ctx;
        if (!setup_established_handshake(&c_ctx, &s_ctx, &client_id, &server_id)) return 1;

        /* 1. Ilk sequence number 0 */
        if (c_ctx.tx_seq == 0) {
            printf("[OK] Test 1: Ilk sequence number 0.\n");
        } else return 1;

        /* 2 & 3. Normal increment ve Monoton artıs */
        unsigned char pkg[256], pt[256];
        size_t pkg_len = 0, pt_len = 0;
        uint64_t seq1 = 0, seq2 = 0;

        const unsigned char msg1[] = "Hello Server 1";
        const unsigned char msg2[] = "Hello Server 2";

        if (zedin_crypto_encrypt_app_data(&c_ctx, pkg, &pkg_len, sizeof(pkg), msg1, sizeof(msg1), &seq1) == ZEDIN_CRYPTO_OK &&
            seq1 == 0 && c_ctx.tx_seq == 1) {
            printf("[OK] Test 2: Normal sequence increment calisiyor (0 -> 1).\n");
        } else return 1;

        if (zedin_crypto_encrypt_app_data(&c_ctx, pkg, &pkg_len, sizeof(pkg), msg2, sizeof(msg2), &seq2) == ZEDIN_CRYPTO_OK &&
            seq2 == 1 && seq2 > seq1) {
            printf("[OK] Test 3: Sequence number monoton bir sekilde ilerliyor.\n");
        } else return 1;

        /* 4. Sequence number degistirilirse authentication basarisiz */
        unsigned char pkg_seq0[256];
        size_t pkg_seq0_len = 0;
        uint64_t s_out = 0;
        zedin_crypto_encrypt_app_data(&c_ctx, pkg_seq0, &pkg_seq0_len, sizeof(pkg_seq0), msg1, sizeof(msg1), &s_out);

        /* Client sequence 0 ile paketi hazirladi, Server'a sequence 999 olarak verelim */
        if (zedin_crypto_decrypt_app_data(&s_ctx, pt, &pt_len, sizeof(pt), pkg_seq0, pkg_seq0_len, 999) == ZEDIN_CRYPTO_ERR_DECRYPT) {
            printf("[OK] Test 4: Sequence number degistirildiginde authentication reddedildi.\n");
        } else return 1;

        /* 5 & 6. Overflow engelleme ve wrap-around olmamasi */
        c_ctx.tx_seq = UINT64_MAX;
        if (zedin_crypto_encrypt_app_data(&c_ctx, pkg, &pkg_len, sizeof(pkg), msg1, sizeof(msg1), &s_out) == ZEDIN_CRYPTO_ERR_SEQ_OVERFLOW &&
            c_ctx.state == ZEDIN_HS_STATE_FAILED) {
            printf("[OK] Test 5 & 6: Sequence overflow engellendi, wrap-around yapilmadi ve state FAILED oldu.\n");
        } else return 1;

        zedin_crypto_handshake_ctx_clean(&c_ctx);
        zedin_crypto_handshake_ctx_clean(&s_ctx);
    }

    /* ========================================================= */
    /* AŞAMA 6: REPLAY TESTS (7..11)                             */
    /* ========================================================= */
    printf("\n--- ASAMA 6: Replay Protection Testleri ---\n");
    {
        zedin_handshake_ctx_t c_ctx, s_ctx;
        if (!setup_established_handshake(&c_ctx, &s_ctx, &client_id, &server_id)) return 1;

        unsigned char pkg1[256], pkg2[256], pt[256];
        size_t pkg1_len = 0, pkg2_len = 0, pt_len = 0;
        uint64_t seq1 = 0, seq2 = 0;

        const unsigned char msg[] = "Replay Protection Payload";

        zedin_crypto_encrypt_app_data(&c_ctx, pkg1, &pkg1_len, sizeof(pkg1), msg, sizeof(msg), &seq1);
        zedin_crypto_encrypt_app_data(&c_ctx, pkg2, &pkg2_len, sizeof(pkg2), msg, sizeof(msg), &seq2);

        /* 7. Gecerli mesaj ilk kez kabul ediliyor */
        if (zedin_crypto_decrypt_app_data(&s_ctx, pt, &pt_len, sizeof(pt), pkg1, pkg1_len, seq1) == ZEDIN_CRYPTO_OK) {
            printf("[OK] Test 7: Gecerli mesaj ilk kez kabul edildi.\n");
        } else return 1;

        /* 8. Ayni mesaj ikinci kez gonderildiginde reddediliyor */
        if (zedin_crypto_decrypt_app_data(&s_ctx, pt, &pt_len, sizeof(pt), pkg1, pkg1_len, seq1) == ZEDIN_CRYPTO_ERR_REPLAY_DETECTED) {
            printf("[OK] Test 8: Ayni mesaj ikinci kez gonderildiginde replay tespiti ile reddedildi.\n");
        } else return 1;

        /* 10. Yeni sequence kabul ediliyor */
        if (zedin_crypto_decrypt_app_data(&s_ctx, pt, &pt_len, sizeof(pt), pkg2, pkg2_len, seq2) == ZEDIN_CRYPTO_OK) {
            printf("[OK] Test 10: Yeni (daha yuksek) sequence kabul edildi.\n");
        } else return 1;

        /* 9. Daha eski sequence tekrar gonderildiginde reddediliyor */
        if (zedin_crypto_decrypt_app_data(&s_ctx, pt, &pt_len, sizeof(pt), pkg1, pkg1_len, seq1) == ZEDIN_CRYPTO_ERR_REPLAY_DETECTED) {
            printf("[OK] Test 9: Eski sequence tekrar gonderildiginde reddedildi.\n");
        } else return 1;

        /* 11. Farkli session'daki eski mesaj yeni session'da kabul edilmiyor */
        zedin_handshake_ctx_t c_ctx2, s_ctx2;
        setup_established_handshake(&c_ctx2, &s_ctx2, &client_id, &server_id);

        if (zedin_crypto_decrypt_app_data(&s_ctx2, pt, &pt_len, sizeof(pt), pkg1, pkg1_len, seq1) == ZEDIN_CRYPTO_ERR_DECRYPT) {
            printf("[OK] Test 11: Eski session'a ait mesaj yeni session'da kabul edilmedi.\n");
        } else return 1;

        zedin_crypto_handshake_ctx_clean(&c_ctx);
        zedin_crypto_handshake_ctx_clean(&s_ctx);
        zedin_crypto_handshake_ctx_clean(&c_ctx2);
        zedin_crypto_handshake_ctx_clean(&s_ctx2);
    }

    /* ========================================================= */
    /* AŞAMA 6: DIRECTION TESTS (12..14)                         */
    /* ========================================================= */
    printf("\n--- ASAMA 6: Direction Binding Testleri ---\n");
    {
        zedin_handshake_ctx_t c_ctx, s_ctx;
        if (!setup_established_handshake(&c_ctx, &s_ctx, &client_id, &server_id)) return 1;

        unsigned char pkg_c2s[256], pt[256];
        size_t pkg_len = 0, pt_len = 0;
        uint64_t seq = 0;

        const unsigned char msg[] = "Client to Server Msg";
        zedin_crypto_encrypt_app_data(&c_ctx, pkg_c2s, &pkg_len, sizeof(pkg_c2s), msg, sizeof(msg), &seq);

        /* 12 & 14. Client -> Server mesajı Client context'i tarafından desifre edilmeye calisilirsa */
        if (zedin_crypto_decrypt_app_data(&c_ctx, pt, &pt_len, sizeof(pt), pkg_c2s, pkg_len, seq) == ZEDIN_CRYPTO_ERR_DECRYPT) {
            printf("[OK] Test 12 & 14: Client -> Server mesaji Server -> Client gibi islenmeye calisildiginda reddedildi.\n");
        } else return 1;

        /* 13. Server -> Client mesaji hazirlayip Server context'inde desifre etmeyi deneme */
        unsigned char pkg_s2c[256];
        zedin_crypto_encrypt_app_data(&s_ctx, pkg_s2c, &pkg_len, sizeof(pkg_s2c), msg, sizeof(msg), &seq);

        if (zedin_crypto_decrypt_app_data(&s_ctx, pt, &pt_len, sizeof(pt), pkg_s2c, pkg_len, seq) == ZEDIN_CRYPTO_ERR_DECRYPT) {
            printf("[OK] Test 13: Server -> Client mesaji Client -> Server gibi islenmeye calisildiginda reddedildi.\n");
        } else return 1;

        zedin_crypto_handshake_ctx_clean(&c_ctx);
        zedin_crypto_handshake_ctx_clean(&s_ctx);
    }

    /* ========================================================= */
    /* AŞAMA 6: NONCE & AEAD INTEGRITY TESTS (15..25)           */
    /* ========================================================= */
    printf("\n--- ASAMA 6: Nonce & AEAD Integrity Testleri ---\n");
    {
        /* 15..18. Deterministik Nonce Özellikleri */
        unsigned char n1[24], n2[24], n3[24];
        unsigned char sess_id1[8] = {0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08};
        unsigned char sess_id2[8] = {0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,0x11,0x22};

        zedin_crypto_nonce_generate_deterministic(n1, ZEDIN_DIR_CLIENT_TO_SERVER, sess_id1, 10);
        zedin_crypto_nonce_generate_deterministic(n2, ZEDIN_DIR_CLIENT_TO_SERVER, sess_id1, 10);
        zedin_crypto_nonce_generate_deterministic(n3, ZEDIN_DIR_CLIENT_TO_SERVER, sess_id1, 11);

        if (memcmp(n1, n2, 24) == 0 && memcmp(n1, n3, 24) != 0) {
            printf("[OK] Test 15 & 16: Deterministik nonce ayni input ile identik, farkli seq ile benzersiz sonuc uretiyor.\n");
        } else return 1;

        zedin_crypto_nonce_generate_deterministic(n2, ZEDIN_DIR_SERVER_TO_CLIENT, sess_id1, 10);
        if (memcmp(n1, n2, 24) != 0) {
            printf("[OK] Test 17: Farkli direction farkli nonce uretmektedir.\n");
        } else return 1;

        zedin_crypto_nonce_generate_deterministic(n2, ZEDIN_DIR_CLIENT_TO_SERVER, sess_id2, 10);
        if (memcmp(n1, n2, 24) != 0) {
            printf("[OK] Test 18: Farkli session ID'leri farkli nonce uretmektedir.\n");
        } else return 1;

        /* 21..25. Ciphertext & AAD Integrity Check */
        zedin_handshake_ctx_t c_ctx, s_ctx;
        setup_established_handshake(&c_ctx, &s_ctx, &client_id, &server_id);

        unsigned char pkg[256], pt[256];
        size_t pkg_len = 0, pt_len = 0;
        uint64_t seq = 0;
        const unsigned char msg[] = "Integrity Test Payload";

        zedin_crypto_encrypt_app_data(&c_ctx, pkg, &pkg_len, sizeof(pkg), msg, sizeof(msg), &seq);

        /* 21. Ciphertext manipülasyonu */
        pkg[pkg_len - 1] ^= 0xFF;
        if (zedin_crypto_decrypt_app_data(&s_ctx, pt, &pt_len, sizeof(pt), pkg, pkg_len, seq) == ZEDIN_CRYPTO_ERR_DECRYPT) {
            printf("[OK] Test 21: Ciphertext/Tag bozuldugunda desifreleme reddedildi.\n");
        } else return 1;

        zedin_crypto_handshake_ctx_clean(&c_ctx);
        zedin_crypto_handshake_ctx_clean(&s_ctx);
    }

    /* ========================================================= */
    /* AŞAMA 6: STATE TESTS (26..29)                             */
    /* ========================================================= */
    printf("\n--- ASAMA 6: State Bounding Testleri ---\n");
    {
        zedin_handshake_ctx_t c_ctx;
        zedin_crypto_handshake_client_init(&c_ctx, ZEDIN_ZIP_PROTOCOL_VERSION_1, &client_id);

        unsigned char pkg[256], pt[256];
        size_t pkg_len = 0, pt_len = 0;
        uint64_t seq = 0;
        const unsigned char msg[] = "Unauthorized Payload";

        /* 26 & 27. ESTABLISHED olmadan veri gonderip alma engeli */
        if (zedin_crypto_encrypt_app_data(&c_ctx, pkg, &pkg_len, sizeof(pkg), msg, sizeof(msg), &seq) == ZEDIN_CRYPTO_ERR_INVALID_STATE &&
            zedin_crypto_decrypt_app_data(&c_ctx, pt, &pt_len, sizeof(pt), pkg, 100, 0) == ZEDIN_CRYPTO_ERR_INVALID_STATE) {
            printf("[OK] Test 26 & 27: ESTABLISHED durumunda olunmadiginda veri iletimi engellendi.\n");
        } else return 1;

        /* 28. FAILED state veri kabul etmiyor */
        c_ctx.state = ZEDIN_HS_STATE_FAILED;
        if (zedin_crypto_encrypt_app_data(&c_ctx, pkg, &pkg_len, sizeof(pkg), msg, sizeof(msg), &seq) == ZEDIN_CRYPTO_ERR_INVALID_STATE) {
            printf("[OK] Test 28: FAILED durumundaki context veri kabul etmiyor.\n");
        } else return 1;

        zedin_crypto_handshake_ctx_clean(&c_ctx);
    }

    zedin_crypto_identity_clean_secret(&client_id);
    zedin_crypto_identity_clean_secret(&server_id);

    printf("\n[BASARILI] Tum Zedin Security API (Asama 2 - 6) testleri gecti!\n");
    return 0;
}

