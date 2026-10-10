/*
 * Dosya: zedin_crypto.c
 * Sorumluluk: Zedin Security API - Core, AEAD, Identity, Transcript, Handshake & Replay/Sequence Management Uygulamasi
 * Platform: Termux / Linux / ARM64 (C99)
 */

#include "zedin_crypto.h"
#include <sodium.h>
#include <string.h>

/* Canonical Serialization TLV Type Identifiers */
#define ZEDIN_TLV_TYPE_DOMAIN_SEP        0x00U
#define ZEDIN_TLV_TYPE_PROTOCOL_VERSION  0x01U
#define ZEDIN_TLV_TYPE_SIGNER_ROLE       0x02U
#define ZEDIN_TLV_TYPE_CLIENT_EPHEM_PK   0x03U
#define ZEDIN_TLV_TYPE_SERVER_EPHEM_PK   0x04U
#define ZEDIN_TLV_TYPE_CLIENT_ID_PK      0x05U
#define ZEDIN_TLV_TYPE_SERVER_ID_PK      0x06U

/* Core & AEAD Fonksiyonlari */

zedin_crypto_status_t zedin_crypto_init(void)
{
    if (sodium_init() < 0) {
        return ZEDIN_CRYPTO_ERR_INIT;
    }
    return ZEDIN_CRYPTO_OK;
}

zedin_crypto_status_t zedin_crypto_keypair_generate(zedin_keypair_t *keypair)
{
    if (keypair == NULL) {
        return ZEDIN_CRYPTO_ERR_NULL_PARAM;
    }

    if (crypto_kx_keypair(keypair->public_key, keypair->secret_key) != 0) {
        sodium_memzero(keypair, sizeof(*keypair));
        return ZEDIN_CRYPTO_ERR_KEYGEN;
    }

    return ZEDIN_CRYPTO_OK;
}

zedin_crypto_status_t zedin_crypto_client_session_keys(
    zedin_session_keys_t *client_keys,
    const zedin_keypair_t *client_keypair,
    const unsigned char server_pk[ZEDIN_CRYPTO_PUBLICKEYBYTES])
{
    if (client_keys == NULL || client_keypair == NULL || server_pk == NULL) {
        return ZEDIN_CRYPTO_ERR_NULL_PARAM;
    }

    if (crypto_kx_client_session_keys(client_keys->rx, client_keys->tx,
                                     client_keypair->public_key,
                                     client_keypair->secret_key,
                                     server_pk) != 0) {
        sodium_memzero(client_keys, sizeof(*client_keys));
        return ZEDIN_CRYPTO_ERR_KX;
    }

    return ZEDIN_CRYPTO_OK;
}

zedin_crypto_status_t zedin_crypto_server_session_keys(
    zedin_session_keys_t *server_keys,
    const zedin_keypair_t *server_keypair,
    const unsigned char client_pk[ZEDIN_CRYPTO_PUBLICKEYBYTES])
{
    if (server_keys == NULL || server_keypair == NULL || client_pk == NULL) {
        return ZEDIN_CRYPTO_ERR_NULL_PARAM;
    }

    if (crypto_kx_server_session_keys(server_keys->rx, server_keys->tx,
                                     server_keypair->public_key,
                                     server_keypair->secret_key,
                                     client_pk) != 0) {
        sodium_memzero(server_keys, sizeof(*server_keys));
        return ZEDIN_CRYPTO_ERR_KX;
    }

    return ZEDIN_CRYPTO_OK;
}

zedin_crypto_status_t zedin_crypto_verify_session_keys(
    const zedin_session_keys_t *client_keys,
    const zedin_session_keys_t *server_keys)
{
    if (client_keys == NULL || server_keys == NULL) {
        return ZEDIN_CRYPTO_ERR_NULL_PARAM;
    }

    int match_tx_rx = (sodium_memcmp(client_keys->tx, server_keys->rx, ZEDIN_CRYPTO_SESSIONKEYBYTES) == 0);
    int match_rx_tx = (sodium_memcmp(client_keys->rx, server_keys->tx, ZEDIN_CRYPTO_SESSIONKEYBYTES) == 0);

    if (match_tx_rx && match_rx_tx) {
        return ZEDIN_CRYPTO_OK;
    }

    return ZEDIN_CRYPTO_ERR_MISMATCH;
}

zedin_crypto_status_t zedin_crypto_encrypt(
    unsigned char *out,
    size_t *out_len,
    size_t max_out_len,
    const unsigned char *plaintext,
    size_t plaintext_len,
    const unsigned char *aad,
    size_t aad_len,
    const unsigned char key[ZEDIN_CRYPTO_AEAD_KEYBYTES])
{
    if (out == NULL || out_len == NULL || key == NULL) {
        return ZEDIN_CRYPTO_ERR_NULL_PARAM;
    }

    if (plaintext_len > 0 && plaintext == NULL) {
        return ZEDIN_CRYPTO_ERR_NULL_PARAM;
    }

    if (aad_len > 0 && aad == NULL) {
        return ZEDIN_CRYPTO_ERR_NULL_PARAM;
    }

    if (plaintext_len > (SIZE_MAX - ZEDIN_CRYPTO_AEAD_NPUBBYTES - ZEDIN_CRYPTO_AEAD_ABYTES)) {
        return ZEDIN_CRYPTO_ERR_OVERFLOW;
    }

    size_t required_len = ZEDIN_CRYPTO_AEAD_NPUBBYTES + plaintext_len + ZEDIN_CRYPTO_AEAD_ABYTES;
    if (max_out_len < required_len) {
        return ZEDIN_CRYPTO_ERR_BUFFER_TOO_SMALL;
    }

    unsigned char *nonce_ptr = out;
    randombytes_buf(nonce_ptr, ZEDIN_CRYPTO_AEAD_NPUBBYTES);

    unsigned char *ciphertext_ptr = out + ZEDIN_CRYPTO_AEAD_NPUBBYTES;
    unsigned long long cipher_out_len = 0;

    int ret = crypto_aead_xchacha20poly1305_ietf_encrypt(
        ciphertext_ptr, &cipher_out_len,
        plaintext, (unsigned long long)plaintext_len,
        aad, (unsigned long long)aad_len,
        NULL, nonce_ptr, key
    );

    if (ret != 0) {
        sodium_memzero(out, max_out_len);
        *out_len = 0;
        return ZEDIN_CRYPTO_ERR_ENCRYPT;
    }

    *out_len = ZEDIN_CRYPTO_AEAD_NPUBBYTES + (size_t)cipher_out_len;
    return ZEDIN_CRYPTO_OK;
}

zedin_crypto_status_t zedin_crypto_decrypt(
    unsigned char *plaintext,
    size_t *plaintext_len,
    size_t max_plaintext_len,
    const unsigned char *in,
    size_t in_len,
    const unsigned char *aad,
    size_t aad_len,
    const unsigned char key[ZEDIN_CRYPTO_AEAD_KEYBYTES])
{
    if (plaintext == NULL || plaintext_len == NULL || in == NULL || key == NULL) {
        return ZEDIN_CRYPTO_ERR_NULL_PARAM;
    }

    if (aad_len > 0 && aad == NULL) {
        return ZEDIN_CRYPTO_ERR_NULL_PARAM;
    }

    size_t min_in_len = ZEDIN_CRYPTO_AEAD_NPUBBYTES + ZEDIN_CRYPTO_AEAD_ABYTES;
    if (in_len < min_in_len) {
        return ZEDIN_CRYPTO_ERR_DECRYPT;
    }

    size_t expected_pt_len = in_len - min_in_len;
    if (max_plaintext_len < expected_pt_len) {
        return ZEDIN_CRYPTO_ERR_BUFFER_TOO_SMALL;
    }

    const unsigned char *nonce_ptr = in;
    const unsigned char *ciphertext_ptr = in + ZEDIN_CRYPTO_AEAD_NPUBBYTES;
    size_t ciphertext_len = in_len - ZEDIN_CRYPTO_AEAD_NPUBBYTES;

    unsigned long long decrypted_len = 0;

    int ret = crypto_aead_xchacha20poly1305_ietf_decrypt(
        plaintext, &decrypted_len,
        NULL,
        ciphertext_ptr, (unsigned long long)ciphertext_len,
        aad, (unsigned long long)aad_len,
        nonce_ptr, key
    );

    if (ret != 0) {
        if (max_plaintext_len > 0) {
            sodium_memzero(plaintext, max_plaintext_len);
        }
        *plaintext_len = 0;
        return ZEDIN_CRYPTO_ERR_DECRYPT;
    }

    *plaintext_len = (size_t)decrypted_len;
    return ZEDIN_CRYPTO_OK;
}

/* Identity API */

zedin_crypto_status_t zedin_crypto_identity_generate(zedin_identity_t *identity)
{
    if (identity == NULL) {
        return ZEDIN_CRYPTO_ERR_NULL_PARAM;
    }

    if (crypto_sign_ed25519_keypair(identity->public_key, identity->secret_key) != 0) {
        sodium_memzero(identity, sizeof(*identity));
        return ZEDIN_CRYPTO_ERR_KEYGEN;
    }

    return ZEDIN_CRYPTO_OK;
}

zedin_crypto_status_t zedin_crypto_identity_sign(
    unsigned char signature[ZEDIN_CRYPTO_SIGNATUREBYTES],
    const unsigned char *message,
    size_t message_len,
    const zedin_identity_t *identity)
{
    if (signature == NULL || identity == NULL) {
        return ZEDIN_CRYPTO_ERR_NULL_PARAM;
    }

    if (message_len > 0 && message == NULL) {
        return ZEDIN_CRYPTO_ERR_NULL_PARAM;
    }

    int ret = crypto_sign_ed25519_detached(
        signature, NULL,
        message, (unsigned long long)message_len,
        identity->secret_key
    );

    if (ret != 0) {
        sodium_memzero(signature, ZEDIN_CRYPTO_SIGNATUREBYTES);
        return ZEDIN_CRYPTO_ERR_SIGN;
    }

    return ZEDIN_CRYPTO_OK;
}

zedin_crypto_status_t zedin_crypto_identity_verify(
    const unsigned char signature[ZEDIN_CRYPTO_SIGNATUREBYTES],
    const unsigned char *message,
    size_t message_len,
    const unsigned char public_key[ZEDIN_CRYPTO_IDENTITY_PUBLICKEYBYTES])
{
    if (signature == NULL || public_key == NULL) {
        return ZEDIN_CRYPTO_ERR_NULL_PARAM;
    }

    if (message_len > 0 && message == NULL) {
        return ZEDIN_CRYPTO_ERR_NULL_PARAM;
    }

    int ret = crypto_sign_ed25519_verify_detached(
        signature,
        message, (unsigned long long)message_len,
        public_key
    );

    if (ret != 0) {
        return ZEDIN_CRYPTO_ERR_VERIFY;
    }

    return ZEDIN_CRYPTO_OK;
}

/* Handshake Transcript & Canonical Serialization */

zedin_crypto_status_t zedin_crypto_handshake_transcript_init(
    zedin_handshake_transcript_t *transcript,
    uint16_t version,
    zedin_role_t signer_role,
    const unsigned char client_ephemeral_pk[ZEDIN_CRYPTO_PUBLICKEYBYTES],
    const unsigned char server_ephemeral_pk[ZEDIN_CRYPTO_PUBLICKEYBYTES],
    const unsigned char client_identity_pk[ZEDIN_CRYPTO_IDENTITY_PUBLICKEYBYTES],
    const unsigned char server_identity_pk[ZEDIN_CRYPTO_IDENTITY_PUBLICKEYBYTES])
{
    if (transcript == NULL || client_ephemeral_pk == NULL ||
        server_ephemeral_pk == NULL || client_identity_pk == NULL ||
        server_identity_pk == NULL) {
        return ZEDIN_CRYPTO_ERR_NULL_PARAM;
    }

    if (signer_role != ZEDIN_ROLE_CLIENT && signer_role != ZEDIN_ROLE_SERVER) {
        return ZEDIN_CRYPTO_ERR_INVALID_ROLE;
    }

    memset(transcript, 0, sizeof(*transcript));

    transcript->version = version;
    transcript->signer_role = signer_role;
    memcpy(transcript->client_ephemeral_pk, client_ephemeral_pk, ZEDIN_CRYPTO_PUBLICKEYBYTES);
    memcpy(transcript->server_ephemeral_pk, server_ephemeral_pk, ZEDIN_CRYPTO_PUBLICKEYBYTES);
    memcpy(transcript->client_identity_pk, client_identity_pk, ZEDIN_CRYPTO_IDENTITY_PUBLICKEYBYTES);
    memcpy(transcript->server_identity_pk, server_identity_pk, ZEDIN_CRYPTO_IDENTITY_PUBLICKEYBYTES);

    return ZEDIN_CRYPTO_OK;
}

static size_t serialize_tlv(unsigned char *buf, uint8_t type, uint16_t len, const void *val)
{
    buf[0] = type;
    buf[1] = (unsigned char)((len >> 8) & 0xFF);
    buf[2] = (unsigned char)(len & 0xFF);
    if (len > 0 && val != NULL) {
        memcpy(&buf[3], val, len);
    }
    return 3U + (size_t)len;
}

zedin_crypto_status_t zedin_crypto_serialize_transcript(
    const zedin_handshake_transcript_t *t,
    unsigned char *out_buf,
    size_t max_out,
    size_t *out_len)
{
    if (t == NULL || out_buf == NULL || out_len == NULL) {
        return ZEDIN_CRYPTO_ERR_NULL_PARAM;
    }

    const size_t dom_len = strlen(ZEDIN_ZIP_DOMAIN_SEPARATOR);
    size_t required = (3 + dom_len) + (3 + 2) + (3 + 1) +
                      (3 + ZEDIN_CRYPTO_PUBLICKEYBYTES) +
                      (3 + ZEDIN_CRYPTO_PUBLICKEYBYTES) +
                      (3 + ZEDIN_CRYPTO_IDENTITY_PUBLICKEYBYTES) +
                      (3 + ZEDIN_CRYPTO_IDENTITY_PUBLICKEYBYTES);

    if (max_out < required) {
        return ZEDIN_CRYPTO_ERR_BUFFER_TOO_SMALL;
    }

    size_t offset = 0;

    offset += serialize_tlv(&out_buf[offset], ZEDIN_TLV_TYPE_DOMAIN_SEP, (uint16_t)dom_len, ZEDIN_ZIP_DOMAIN_SEPARATOR);

    uint8_t ver_bytes[2];
    ver_bytes[0] = (uint8_t)((t->version >> 8) & 0xFF);
    ver_bytes[1] = (uint8_t)(t->version & 0xFF);
    offset += serialize_tlv(&out_buf[offset], ZEDIN_TLV_TYPE_PROTOCOL_VERSION, 2, ver_bytes);

    uint8_t role_byte = (uint8_t)t->signer_role;
    offset += serialize_tlv(&out_buf[offset], ZEDIN_TLV_TYPE_SIGNER_ROLE, 1, &role_byte);

    offset += serialize_tlv(&out_buf[offset], ZEDIN_TLV_TYPE_CLIENT_EPHEM_PK, ZEDIN_CRYPTO_PUBLICKEYBYTES, t->client_ephemeral_pk);
    offset += serialize_tlv(&out_buf[offset], ZEDIN_TLV_TYPE_SERVER_EPHEM_PK, ZEDIN_CRYPTO_PUBLICKEYBYTES, t->server_ephemeral_pk);
    offset += serialize_tlv(&out_buf[offset], ZEDIN_TLV_TYPE_CLIENT_ID_PK, ZEDIN_CRYPTO_IDENTITY_PUBLICKEYBYTES, t->client_identity_pk);
    offset += serialize_tlv(&out_buf[offset], ZEDIN_TLV_TYPE_SERVER_ID_PK, ZEDIN_CRYPTO_IDENTITY_PUBLICKEYBYTES, t->server_identity_pk);

    *out_len = offset;
    return ZEDIN_CRYPTO_OK;
}

zedin_crypto_status_t zedin_crypto_handshake_sign(
    unsigned char signature[ZEDIN_CRYPTO_SIGNATUREBYTES],
    const zedin_handshake_transcript_t *transcript,
    const zedin_identity_t *signer_identity)
{
    if (signature == NULL || transcript == NULL || signer_identity == NULL) {
        return ZEDIN_CRYPTO_ERR_NULL_PARAM;
    }

    unsigned char serialized[512];
    size_t serialized_len = 0;

    zedin_crypto_status_t st = zedin_crypto_serialize_transcript(
        transcript, serialized, sizeof(serialized), &serialized_len
    );

    if (st != ZEDIN_CRYPTO_OK) {
        sodium_memzero(signature, ZEDIN_CRYPTO_SIGNATUREBYTES);
        return st;
    }

    st = zedin_crypto_identity_sign(signature, serialized, serialized_len, signer_identity);
    sodium_memzero(serialized, sizeof(serialized));

    return st;
}

zedin_crypto_status_t zedin_crypto_handshake_verify(
    const unsigned char signature[ZEDIN_CRYPTO_SIGNATUREBYTES],
    const zedin_handshake_transcript_t *transcript,
    const unsigned char signer_identity_pk[ZEDIN_CRYPTO_IDENTITY_PUBLICKEYBYTES])
{
    if (signature == NULL || transcript == NULL || signer_identity_pk == NULL) {
        return ZEDIN_CRYPTO_ERR_NULL_PARAM;
    }

    unsigned char serialized[512];
    size_t serialized_len = 0;

    zedin_crypto_status_t st = zedin_crypto_serialize_transcript(
        transcript, serialized, sizeof(serialized), &serialized_len
    );

    if (st != ZEDIN_CRYPTO_OK) {
        return st;
    }

    st = zedin_crypto_identity_verify(signature, serialized, serialized_len, signer_identity_pk);
    sodium_memzero(serialized, sizeof(serialized));

    return st;
}

/* Handshake State Machine Implementasyonu */

static void generate_session_id(unsigned char session_id[ZEDIN_SESSION_ID_BYTES], const zedin_handshake_transcript_t *t)
{
    unsigned char serialized[512];
    size_t serialized_len = 0;
    if (zedin_crypto_serialize_transcript(t, serialized, sizeof(serialized), &serialized_len) == ZEDIN_CRYPTO_OK) {
        unsigned char hash[crypto_generichash_BYTES];
        crypto_generichash(hash, sizeof(hash), serialized, serialized_len, NULL, 0);
        memcpy(session_id, hash, ZEDIN_SESSION_ID_BYTES);
        sodium_memzero(serialized, sizeof(serialized));
    }
}

zedin_crypto_status_t zedin_crypto_handshake_client_init(
    zedin_handshake_ctx_t *ctx,
    uint16_t version,
    const zedin_identity_t *client_identity)
{
    if (ctx == NULL || client_identity == NULL) {
        return ZEDIN_CRYPTO_ERR_NULL_PARAM;
    }

    memset(ctx, 0, sizeof(*ctx));
    ctx->role = ZEDIN_ROLE_CLIENT;
    ctx->state = ZEDIN_HS_STATE_INIT;
    ctx->version = version;
    ctx->tx_seq = 0;
    ctx->replay_state.last_rx_seq = 0;
    ctx->replay_state.initialized = 0;

    memcpy(&ctx->local_identity, client_identity, sizeof(zedin_identity_t));

    zedin_crypto_status_t st = zedin_crypto_keypair_generate(&ctx->local_ephemeral_kp);
    if (st != ZEDIN_CRYPTO_OK) {
        zedin_crypto_handshake_ctx_clean(ctx);
        ctx->state = ZEDIN_HS_STATE_FAILED;
        return st;
    }

    ctx->state = ZEDIN_HS_STATE_EPHEMERAL_GENERATED;
    return ZEDIN_CRYPTO_OK;
}

zedin_crypto_status_t zedin_crypto_handshake_server_init(
    zedin_handshake_ctx_t *ctx,
    uint16_t version,
    const zedin_identity_t *server_identity)
{
    if (ctx == NULL || server_identity == NULL) {
        return ZEDIN_CRYPTO_ERR_NULL_PARAM;
    }

    memset(ctx, 0, sizeof(*ctx));
    ctx->role = ZEDIN_ROLE_SERVER;
    ctx->state = ZEDIN_HS_STATE_INIT;
    ctx->version = version;
    ctx->tx_seq = 0;
    ctx->replay_state.last_rx_seq = 0;
    ctx->replay_state.initialized = 0;

    memcpy(&ctx->local_identity, server_identity, sizeof(zedin_identity_t));

    ctx->state = ZEDIN_HS_STATE_WAIT_CLIENT_HELLO;
    return ZEDIN_CRYPTO_OK;
}

zedin_crypto_status_t zedin_crypto_handshake_server_process_client_hello(
    zedin_handshake_ctx_t *server_ctx,
    const unsigned char client_ephemeral_pk[ZEDIN_CRYPTO_PUBLICKEYBYTES],
    const unsigned char client_identity_pk[ZEDIN_CRYPTO_IDENTITY_PUBLICKEYBYTES],
    unsigned char out_server_ephemeral_pk[ZEDIN_CRYPTO_PUBLICKEYBYTES],
    unsigned char out_server_identity_pk[ZEDIN_CRYPTO_IDENTITY_PUBLICKEYBYTES],
    unsigned char out_server_signature[ZEDIN_CRYPTO_SIGNATUREBYTES])
{
    if (server_ctx == NULL || client_ephemeral_pk == NULL || client_identity_pk == NULL ||
        out_server_ephemeral_pk == NULL || out_server_identity_pk == NULL || out_server_signature == NULL) {
        if (server_ctx != NULL) server_ctx->state = ZEDIN_HS_STATE_FAILED;
        return ZEDIN_CRYPTO_ERR_NULL_PARAM;
    }

    if (server_ctx->role != ZEDIN_ROLE_SERVER || server_ctx->state != ZEDIN_HS_STATE_WAIT_CLIENT_HELLO) {
        server_ctx->state = ZEDIN_HS_STATE_FAILED;
        return ZEDIN_CRYPTO_ERR_INVALID_STATE;
    }

    memcpy(server_ctx->peer_ephemeral_pk, client_ephemeral_pk, ZEDIN_CRYPTO_PUBLICKEYBYTES);
    memcpy(server_ctx->peer_identity_pk, client_identity_pk, ZEDIN_CRYPTO_IDENTITY_PUBLICKEYBYTES);

    zedin_crypto_status_t st = zedin_crypto_keypair_generate(&server_ctx->local_ephemeral_kp);
    if (st != ZEDIN_CRYPTO_OK) {
        server_ctx->state = ZEDIN_HS_STATE_FAILED;
        return st;
    }

    zedin_handshake_transcript_t server_transcript;
    st = zedin_crypto_handshake_transcript_init(
        &server_transcript,
        server_ctx->version,
        ZEDIN_ROLE_SERVER,
        server_ctx->peer_ephemeral_pk,
        server_ctx->local_ephemeral_kp.public_key,
        server_ctx->peer_identity_pk,
        server_ctx->local_identity.public_key
    );

    if (st != ZEDIN_CRYPTO_OK) {
        server_ctx->state = ZEDIN_HS_STATE_FAILED;
        return st;
    }

    st = zedin_crypto_handshake_sign(server_ctx->local_signature, &server_transcript, &server_ctx->local_identity);
    if (st != ZEDIN_CRYPTO_OK) {
        server_ctx->state = ZEDIN_HS_STATE_FAILED;
        return st;
    }

    memcpy(out_server_ephemeral_pk, server_ctx->local_ephemeral_kp.public_key, ZEDIN_CRYPTO_PUBLICKEYBYTES);
    memcpy(out_server_identity_pk, server_ctx->local_identity.public_key, ZEDIN_CRYPTO_IDENTITY_PUBLICKEYBYTES);
    memcpy(out_server_signature, server_ctx->local_signature, ZEDIN_CRYPTO_SIGNATUREBYTES);

    server_ctx->state = ZEDIN_HS_STATE_CLIENT_AUTHENTICATED;
    return ZEDIN_CRYPTO_OK;
}

zedin_crypto_status_t zedin_crypto_handshake_client_process_server_hello(
    zedin_handshake_ctx_t *client_ctx,
    const unsigned char server_ephemeral_pk[ZEDIN_CRYPTO_PUBLICKEYBYTES],
    const unsigned char server_identity_pk[ZEDIN_CRYPTO_IDENTITY_PUBLICKEYBYTES],
    const unsigned char server_signature[ZEDIN_CRYPTO_SIGNATUREBYTES])
{
    if (client_ctx == NULL || server_ephemeral_pk == NULL || server_identity_pk == NULL || server_signature == NULL) {
        if (client_ctx != NULL) client_ctx->state = ZEDIN_HS_STATE_FAILED;
        return ZEDIN_CRYPTO_ERR_NULL_PARAM;
    }

    if (client_ctx->role != ZEDIN_ROLE_CLIENT || client_ctx->state != ZEDIN_HS_STATE_EPHEMERAL_GENERATED) {
        client_ctx->state = ZEDIN_HS_STATE_FAILED;
        return ZEDIN_CRYPTO_ERR_INVALID_STATE;
    }

    memcpy(client_ctx->peer_ephemeral_pk, server_ephemeral_pk, ZEDIN_CRYPTO_PUBLICKEYBYTES);
    memcpy(client_ctx->peer_identity_pk, server_identity_pk, ZEDIN_CRYPTO_IDENTITY_PUBLICKEYBYTES);
    memcpy(client_ctx->peer_signature, server_signature, ZEDIN_CRYPTO_SIGNATUREBYTES);

    zedin_handshake_transcript_t server_transcript;
    zedin_crypto_status_t st = zedin_crypto_handshake_transcript_init(
        &server_transcript,
        client_ctx->version,
        ZEDIN_ROLE_SERVER,
        client_ctx->local_ephemeral_kp.public_key,
        client_ctx->peer_ephemeral_pk,
        client_ctx->local_identity.public_key,
        client_ctx->peer_identity_pk
    );

    if (st != ZEDIN_CRYPTO_OK) {
        client_ctx->state = ZEDIN_HS_STATE_FAILED;
        return st;
    }

    st = zedin_crypto_handshake_verify(client_ctx->peer_signature, &server_transcript, client_ctx->peer_identity_pk);
    if (st != ZEDIN_CRYPTO_OK) {
        client_ctx->state = ZEDIN_HS_STATE_FAILED;
        return ZEDIN_CRYPTO_ERR_VERIFY;
    }

    client_ctx->state = ZEDIN_HS_STATE_SERVER_AUTHENTICATED;
    return ZEDIN_CRYPTO_OK;
}

zedin_crypto_status_t zedin_crypto_handshake_client_finalize(
    zedin_handshake_ctx_t *client_ctx,
    unsigned char out_client_signature[ZEDIN_CRYPTO_SIGNATUREBYTES])
{
    if (client_ctx == NULL || out_client_signature == NULL) {
        if (client_ctx != NULL) client_ctx->state = ZEDIN_HS_STATE_FAILED;
        return ZEDIN_CRYPTO_ERR_NULL_PARAM;
    }

    if (client_ctx->role != ZEDIN_ROLE_CLIENT || client_ctx->state != ZEDIN_HS_STATE_SERVER_AUTHENTICATED) {
        client_ctx->state = ZEDIN_HS_STATE_FAILED;
        return ZEDIN_CRYPTO_ERR_INVALID_STATE;
    }

    zedin_handshake_transcript_t client_transcript;
    zedin_crypto_status_t st = zedin_crypto_handshake_transcript_init(
        &client_transcript,
        client_ctx->version,
        ZEDIN_ROLE_CLIENT,
        client_ctx->local_ephemeral_kp.public_key,
        client_ctx->peer_ephemeral_pk,
        client_ctx->local_identity.public_key,
        client_ctx->peer_identity_pk
    );

    if (st != ZEDIN_CRYPTO_OK) {
        client_ctx->state = ZEDIN_HS_STATE_FAILED;
        return st;
    }

    st = zedin_crypto_handshake_sign(client_ctx->local_signature, &client_transcript, &client_ctx->local_identity);
    if (st != ZEDIN_CRYPTO_OK) {
        client_ctx->state = ZEDIN_HS_STATE_FAILED;
        return st;
    }

    st = zedin_crypto_client_session_keys(&client_ctx->session_keys, &client_ctx->local_ephemeral_kp, client_ctx->peer_ephemeral_pk);
    if (st != ZEDIN_CRYPTO_OK) {
        client_ctx->state = ZEDIN_HS_STATE_FAILED;
        return st;
    }

    generate_session_id(client_ctx->session_id, &client_transcript);

    memcpy(out_client_signature, client_ctx->local_signature, ZEDIN_CRYPTO_SIGNATUREBYTES);
    client_ctx->state = ZEDIN_HS_STATE_ESTABLISHED;
    return ZEDIN_CRYPTO_OK;
}

zedin_crypto_status_t zedin_crypto_handshake_server_finalize(
    zedin_handshake_ctx_t *server_ctx,
    const unsigned char client_signature[ZEDIN_CRYPTO_SIGNATUREBYTES])
{
    if (server_ctx == NULL || client_signature == NULL) {
        if (server_ctx != NULL) server_ctx->state = ZEDIN_HS_STATE_FAILED;
        return ZEDIN_CRYPTO_ERR_NULL_PARAM;
    }

    if (server_ctx->role != ZEDIN_ROLE_SERVER || server_ctx->state != ZEDIN_HS_STATE_CLIENT_AUTHENTICATED) {
        server_ctx->state = ZEDIN_HS_STATE_FAILED;
        return ZEDIN_CRYPTO_ERR_INVALID_STATE;
    }

    memcpy(server_ctx->peer_signature, client_signature, ZEDIN_CRYPTO_SIGNATUREBYTES);

    zedin_handshake_transcript_t client_transcript;
    zedin_crypto_status_t st = zedin_crypto_handshake_transcript_init(
        &client_transcript,
        server_ctx->version,
        ZEDIN_ROLE_CLIENT,
        server_ctx->peer_ephemeral_pk,
        server_ctx->local_ephemeral_kp.public_key,
        server_ctx->peer_identity_pk,
        server_ctx->local_identity.public_key
    );

    if (st != ZEDIN_CRYPTO_OK) {
        server_ctx->state = ZEDIN_HS_STATE_FAILED;
        return st;
    }

    st = zedin_crypto_handshake_verify(server_ctx->peer_signature, &client_transcript, server_ctx->peer_identity_pk);
    if (st != ZEDIN_CRYPTO_OK) {
        server_ctx->state = ZEDIN_HS_STATE_FAILED;
        return ZEDIN_CRYPTO_ERR_VERIFY;
    }

    st = zedin_crypto_server_session_keys(&server_ctx->session_keys, &server_ctx->local_ephemeral_kp, server_ctx->peer_ephemeral_pk);
    if (st != ZEDIN_CRYPTO_OK) {
        server_ctx->state = ZEDIN_HS_STATE_FAILED;
        return st;
    }

    generate_session_id(server_ctx->session_id, &client_transcript);

    server_ctx->state = ZEDIN_HS_STATE_ESTABLISHED;
    return ZEDIN_CRYPTO_OK;
}

zedin_crypto_status_t zedin_crypto_handshake_get_session_keys(
    const zedin_handshake_ctx_t *ctx,
    zedin_session_keys_t *out_session_keys)
{
    if (ctx == NULL || out_session_keys == NULL) {
        return ZEDIN_CRYPTO_ERR_NULL_PARAM;
    }

    if (ctx->state != ZEDIN_HS_STATE_ESTABLISHED) {
        return ZEDIN_CRYPTO_ERR_INVALID_STATE;
    }

    memcpy(out_session_keys, &ctx->session_keys, sizeof(zedin_session_keys_t));
    return ZEDIN_CRYPTO_OK;
}

/* ========================================================================= */
/* AŞAMA 6: SEQUENCE, NONCE, REPLAY PROTECTION & APP DATA IMPLEMENTATION     */
/* ========================================================================= */

zedin_crypto_status_t zedin_crypto_nonce_generate_deterministic(
    unsigned char nonce[ZEDIN_CRYPTO_AEAD_NPUBBYTES],
    zedin_direction_t direction,
    const unsigned char session_id[ZEDIN_SESSION_ID_BYTES],
    uint64_t sequence)
{
    if (nonce == NULL || session_id == NULL) {
        return ZEDIN_CRYPTO_ERR_NULL_PARAM;
    }

    if (direction != ZEDIN_DIR_CLIENT_TO_SERVER && direction != ZEDIN_DIR_SERVER_TO_CLIENT) {
        return ZEDIN_CRYPTO_ERR_INVALID_DIR;
    }

    memset(nonce, 0, ZEDIN_CRYPTO_AEAD_NPUBBYTES);

    /* Byte 0..7: Magic Domain + Direction */
    if (direction == ZEDIN_DIR_CLIENT_TO_SERVER) {
        memcpy(&nonce[0], "ZEDIN_C2S", 8);
    } else {
        memcpy(&nonce[0], "ZEDIN_S2C", 8);
    }

    /* Byte 8..15: Session Binding ID */
    memcpy(&nonce[8], session_id, ZEDIN_SESSION_ID_BYTES);

    /* Byte 16..23: 64-bit Big-Endian Sequence Number */
    nonce[16] = (unsigned char)((sequence >> 56) & 0xFF);
    nonce[17] = (unsigned char)((sequence >> 48) & 0xFF);
    nonce[18] = (unsigned char)((sequence >> 40) & 0xFF);
    nonce[19] = (unsigned char)((sequence >> 32) & 0xFF);
    nonce[20] = (unsigned char)((sequence >> 24) & 0xFF);
    nonce[21] = (unsigned char)((sequence >> 16) & 0xFF);
    nonce[22] = (unsigned char)((sequence >> 8) & 0xFF);
    nonce[23] = (unsigned char)(sequence & 0xFF);

    return ZEDIN_CRYPTO_OK;
}

zedin_crypto_status_t zedin_crypto_replay_check_and_update(
    zedin_replay_state_t *replay_state,
    uint64_t sequence)
{
    if (replay_state == NULL) {
        return ZEDIN_CRYPTO_ERR_NULL_PARAM;
    }

    if (replay_state->initialized) {
        if (sequence <= replay_state->last_rx_seq) {
            return ZEDIN_CRYPTO_ERR_REPLAY_DETECTED;
        }
    }

    replay_state->last_rx_seq = sequence;
    replay_state->initialized = 1;

    return ZEDIN_CRYPTO_OK;
}

static size_t build_aad_metadata(
    unsigned char aad[19],
    uint16_t version,
    zedin_direction_t dir,
    const unsigned char session_id[ZEDIN_SESSION_ID_BYTES],
    uint64_t sequence)
{
    aad[0] = (unsigned char)((version >> 8) & 0xFF);
    aad[1] = (unsigned char)(version & 0xFF);
    aad[2] = (unsigned char)dir;
    memcpy(&aad[3], session_id, ZEDIN_SESSION_ID_BYTES);
    aad[11] = (unsigned char)((sequence >> 56) & 0xFF);
    aad[12] = (unsigned char)((sequence >> 48) & 0xFF);
    aad[13] = (unsigned char)((sequence >> 40) & 0xFF);
    aad[14] = (unsigned char)((sequence >> 32) & 0xFF);
    aad[15] = (unsigned char)((sequence >> 24) & 0xFF);
    aad[16] = (unsigned char)((sequence >> 16) & 0xFF);
    aad[17] = (unsigned char)((sequence >> 8) & 0xFF);
    aad[18] = (unsigned char)(sequence & 0xFF);
    return 19U;
}

zedin_crypto_status_t zedin_crypto_encrypt_app_data(
    zedin_handshake_ctx_t *ctx,
    unsigned char *out,
    size_t *out_len,
    size_t max_out_len,
    const unsigned char *plaintext,
    size_t plaintext_len,
    uint64_t *out_sequence)
{
    if (ctx == NULL || out == NULL || out_len == NULL || out_sequence == NULL) {
        return ZEDIN_CRYPTO_ERR_NULL_PARAM;
    }

    if (ctx->state != ZEDIN_HS_STATE_ESTABLISHED) {
        return ZEDIN_CRYPTO_ERR_INVALID_STATE;
    }

    if (ctx->tx_seq == UINT64_MAX) {
        ctx->state = ZEDIN_HS_STATE_FAILED;
        return ZEDIN_CRYPTO_ERR_SEQ_OVERFLOW;
    }

    zedin_direction_t dir = (ctx->role == ZEDIN_ROLE_CLIENT) ? ZEDIN_DIR_CLIENT_TO_SERVER : ZEDIN_DIR_SERVER_TO_CLIENT;

    unsigned char nonce[ZEDIN_CRYPTO_AEAD_NPUBBYTES];
    zedin_crypto_status_t st = zedin_crypto_nonce_generate_deterministic(nonce, dir, ctx->session_id, ctx->tx_seq);
    if (st != ZEDIN_CRYPTO_OK) return st;

    unsigned char aad[19];
    size_t aad_len = build_aad_metadata(aad, ctx->version, dir, ctx->session_id, ctx->tx_seq);

    size_t required_len = ZEDIN_CRYPTO_AEAD_NPUBBYTES + plaintext_len + ZEDIN_CRYPTO_AEAD_ABYTES;
    if (max_out_len < required_len) {
        return ZEDIN_CRYPTO_ERR_BUFFER_TOO_SMALL;
    }

    memcpy(out, nonce, ZEDIN_CRYPTO_AEAD_NPUBBYTES);
    unsigned char *ciphertext_ptr = out + ZEDIN_CRYPTO_AEAD_NPUBBYTES;
    unsigned long long cipher_out_len = 0;

    int ret = crypto_aead_xchacha20poly1305_ietf_encrypt(
        ciphertext_ptr, &cipher_out_len,
        plaintext, (unsigned long long)plaintext_len,
        aad, (unsigned long long)aad_len,
        NULL, nonce, ctx->session_keys.tx
    );

    if (ret != 0) {
        sodium_memzero(out, max_out_len);
        *out_len = 0;
        ctx->state = ZEDIN_HS_STATE_FAILED;
        return ZEDIN_CRYPTO_ERR_ENCRYPT;
    }

    *out_len = ZEDIN_CRYPTO_AEAD_NPUBBYTES + (size_t)cipher_out_len;
    *out_sequence = ctx->tx_seq;
    ctx->tx_seq++;

    return ZEDIN_CRYPTO_OK;
}

zedin_crypto_status_t zedin_crypto_decrypt_app_data(
    zedin_handshake_ctx_t *ctx,
    unsigned char *plaintext,
    size_t *plaintext_len,
    size_t max_plaintext_len,
    const unsigned char *in,
    size_t in_len,
    uint64_t sequence)
{
    if (ctx == NULL || plaintext == NULL || plaintext_len == NULL || in == NULL) {
        return ZEDIN_CRYPTO_ERR_NULL_PARAM;
    }

    if (ctx->state != ZEDIN_HS_STATE_ESTABLISHED) {
        return ZEDIN_CRYPTO_ERR_INVALID_STATE;
    }

    zedin_direction_t rx_dir = (ctx->role == ZEDIN_ROLE_CLIENT) ? ZEDIN_DIR_SERVER_TO_CLIENT : ZEDIN_DIR_CLIENT_TO_SERVER;

    /* Replay Protection Check (Desifreleme öncesi) */
    if (ctx->replay_state.initialized && sequence <= ctx->replay_state.last_rx_seq) {
        return ZEDIN_CRYPTO_ERR_REPLAY_DETECTED;
    }

    size_t min_in_len = ZEDIN_CRYPTO_AEAD_NPUBBYTES + ZEDIN_CRYPTO_AEAD_ABYTES;
    if (in_len < min_in_len) {
        return ZEDIN_CRYPTO_ERR_DECRYPT;
    }

    unsigned char expected_nonce[ZEDIN_CRYPTO_AEAD_NPUBBYTES];
    zedin_crypto_status_t st = zedin_crypto_nonce_generate_deterministic(expected_nonce, rx_dir, ctx->session_id, sequence);
    if (st != ZEDIN_CRYPTO_OK) return st;

    /* Nonce Mismatch Kontrolü */
    if (sodium_memcmp(in, expected_nonce, ZEDIN_CRYPTO_AEAD_NPUBBYTES) != 0) {
        return ZEDIN_CRYPTO_ERR_DECRYPT;
    }

    unsigned char aad[19];
    size_t aad_len = build_aad_metadata(aad, ctx->version, rx_dir, ctx->session_id, sequence);

    const unsigned char *ciphertext_ptr = in + ZEDIN_CRYPTO_AEAD_NPUBBYTES;
    size_t ciphertext_len = in_len - ZEDIN_CRYPTO_AEAD_NPUBBYTES;

    unsigned long long decrypted_len = 0;
    int ret = crypto_aead_xchacha20poly1305_ietf_decrypt(
        plaintext, &decrypted_len,
        NULL,
        ciphertext_ptr, (unsigned long long)ciphertext_len,
        aad, (unsigned long long)aad_len,
        expected_nonce, ctx->session_keys.rx
    );

    if (ret != 0) {
        if (max_plaintext_len > 0) {
            sodium_memzero(plaintext, max_plaintext_len);
        }
        *plaintext_len = 0;
        return ZEDIN_CRYPTO_ERR_DECRYPT;
    }

    /* Başarılı doğrulama sonrası Replay State güncelleme */
    st = zedin_crypto_replay_check_and_update(&ctx->replay_state, sequence);
    if (st != ZEDIN_CRYPTO_OK) {
        return st;
    }

    *plaintext_len = (size_t)decrypted_len;
    return ZEDIN_CRYPTO_OK;
}

/* Cleanup Fonksiyonlari */

void zedin_crypto_clean(void *p, size_t len)
{
    if (p != NULL && len > 0) {
        sodium_memzero(p, len);
    }
}

void zedin_crypto_keypair_clean_secret(zedin_keypair_t *keypair)
{
    if (keypair != NULL) {
        sodium_memzero(keypair->secret_key, sizeof(keypair->secret_key));
    }
}

void zedin_crypto_session_keys_clean(zedin_session_keys_t *session_keys)
{
    if (session_keys != NULL) {
        sodium_memzero(session_keys->rx, sizeof(session_keys->rx));
        sodium_memzero(session_keys->tx, sizeof(session_keys->tx));
    }
}

void zedin_crypto_identity_clean_secret(zedin_identity_t *identity)
{
    if (identity != NULL) {
        sodium_memzero(identity->secret_key, sizeof(identity->secret_key));
    }
}

void zedin_crypto_handshake_ctx_clean(zedin_handshake_ctx_t *ctx)
{
    if (ctx != NULL) {
        zedin_crypto_keypair_clean_secret(&ctx->local_ephemeral_kp);
        zedin_crypto_identity_clean_secret(&ctx->local_identity);
        zedin_crypto_session_keys_clean(&ctx->session_keys);
        sodium_memzero(ctx, sizeof(*ctx));
    }
}

