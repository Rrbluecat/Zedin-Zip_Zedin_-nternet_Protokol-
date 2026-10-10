/*
 * Dosya: zedin_crypto.h
 * Sorumluluk: Zedin Security API - Core, AEAD, Identity, Transcript, Handshake & Replay/Sequence Management
 * Platform: Termux / Linux / ARM64 (C99)
 */

#ifndef ZEDIN_CRYPTO_H
#define ZEDIN_CRYPTO_H

#include <stddef.h>
#include <stdint.h>

/* Kriptografik Boyut Sabitleri (crypto_kx & XChaCha20-Poly1305) */
#define ZEDIN_CRYPTO_PUBLICKEYBYTES  32U
#define ZEDIN_CRYPTO_SECRETKEYBYTES  32U
#define ZEDIN_CRYPTO_SESSIONKEYBYTES 32U

#define ZEDIN_CRYPTO_AEAD_KEYBYTES   32U
#define ZEDIN_CRYPTO_AEAD_NPUBBYTES  24U
#define ZEDIN_CRYPTO_AEAD_ABYTES     16U

/* Ed25519 Identity ve Imza Sabitleri */
#define ZEDIN_CRYPTO_IDENTITY_PUBLICKEYBYTES 32U
#define ZEDIN_CRYPTO_IDENTITY_SECRETKEYBYTES 64U
#define ZEDIN_CRYPTO_SIGNATUREBYTES          64U

/* Protocol Version ve Domain Separator */
#define ZEDIN_ZIP_PROTOCOL_VERSION_1 0x0100U
#define ZEDIN_ZIP_DOMAIN_SEPARATOR "ZEDIN-ZIP-HANDSHAKE-V1"

/* Session ve Direction Sabitleri (Asama 6) */
#define ZEDIN_SESSION_ID_BYTES 8U

typedef enum {
    ZEDIN_DIR_CLIENT_TO_SERVER = 0x01,
    ZEDIN_DIR_SERVER_TO_CLIENT = 0x02
} zedin_direction_t;

/* Hata Kodlari */
typedef enum {
    ZEDIN_CRYPTO_OK = 0,
    ZEDIN_CRYPTO_ERR_INIT = -1,
    ZEDIN_CRYPTO_ERR_NULL_PARAM = -2,
    ZEDIN_CRYPTO_ERR_KEYGEN = -3,
    ZEDIN_CRYPTO_ERR_KX = -4,
    ZEDIN_CRYPTO_ERR_MISMATCH = -5,
    ZEDIN_CRYPTO_ERR_ENCRYPT = -6,
    ZEDIN_CRYPTO_ERR_DECRYPT = -7,
    ZEDIN_CRYPTO_ERR_BUFFER_TOO_SMALL = -8,
    ZEDIN_CRYPTO_ERR_OVERFLOW = -9,
    ZEDIN_CRYPTO_ERR_SIGN = -10,
    ZEDIN_CRYPTO_ERR_VERIFY = -11,
    ZEDIN_CRYPTO_ERR_INVALID_ROLE = -12,
    ZEDIN_CRYPTO_ERR_INVALID_STATE = -13,
    ZEDIN_CRYPTO_ERR_REPLAY_DETECTED = -14,
    ZEDIN_CRYPTO_ERR_SEQ_OVERFLOW = -15,
    ZEDIN_CRYPTO_ERR_INVALID_DIR = -16
} zedin_crypto_status_t;

/* Handshake Rolleri */
typedef enum {
    ZEDIN_ROLE_CLIENT = 0x01,
    ZEDIN_ROLE_SERVER = 0x02
} zedin_role_t;

/* Handshake State Machine Durumlari */
typedef enum {
    ZEDIN_HS_STATE_INIT = 0,
    ZEDIN_HS_STATE_EPHEMERAL_GENERATED,
    ZEDIN_HS_STATE_WAIT_CLIENT_HELLO,
    ZEDIN_HS_STATE_CLIENT_AUTHENTICATED,
    ZEDIN_HS_STATE_SERVER_AUTHENTICATED,
    ZEDIN_HS_STATE_ESTABLISHED,
    ZEDIN_HS_STATE_FAILED
} zedin_handshake_state_t;

/* Anahtar Cifti Yapilari */
typedef struct {
    unsigned char public_key[ZEDIN_CRYPTO_PUBLICKEYBYTES];
    unsigned char secret_key[ZEDIN_CRYPTO_SECRETKEYBYTES];
} zedin_keypair_t;

typedef struct {
    unsigned char rx[ZEDIN_CRYPTO_SESSIONKEYBYTES];
    unsigned char tx[ZEDIN_CRYPTO_SESSIONKEYBYTES];
} zedin_session_keys_t;

/* Ed25519 Kimlik Yapisi */
typedef struct {
    unsigned char public_key[ZEDIN_CRYPTO_IDENTITY_PUBLICKEYBYTES];
    unsigned char secret_key[ZEDIN_CRYPTO_IDENTITY_SECRETKEYBYTES];
} zedin_identity_t;

/* Handshake Transcript Yapisi */
typedef struct {
    uint16_t version;
    zedin_role_t signer_role;
    unsigned char client_ephemeral_pk[ZEDIN_CRYPTO_PUBLICKEYBYTES];
    unsigned char server_ephemeral_pk[ZEDIN_CRYPTO_PUBLICKEYBYTES];
    unsigned char client_identity_pk[ZEDIN_CRYPTO_IDENTITY_PUBLICKEYBYTES];
    unsigned char server_identity_pk[ZEDIN_CRYPTO_IDENTITY_PUBLICKEYBYTES];
} zedin_handshake_transcript_t;

/* Replay State Yapisi (Asama 6) */
typedef struct {
    uint64_t last_rx_seq;
    int initialized;
} zedin_replay_state_t;

/* Handshake ve Session Context Yapisi (Asama 5 + Asama 6) */
typedef struct {
    zedin_role_t role;
    zedin_handshake_state_t state;
    uint16_t version;

    zedin_keypair_t local_ephemeral_kp;
    unsigned char peer_ephemeral_pk[ZEDIN_CRYPTO_PUBLICKEYBYTES];

    zedin_identity_t local_identity;
    unsigned char peer_identity_pk[ZEDIN_CRYPTO_IDENTITY_PUBLICKEYBYTES];

    zedin_session_keys_t session_keys;
    unsigned char session_id[ZEDIN_SESSION_ID_BYTES];

    /* Asama 6: Sequence ve Replay State */
    uint64_t tx_seq;
    zedin_replay_state_t replay_state;

    unsigned char local_signature[ZEDIN_CRYPTO_SIGNATUREBYTES];
    unsigned char peer_signature[ZEDIN_CRYPTO_SIGNATUREBYTES];
} zedin_handshake_ctx_t;

/* Core API Fonksiyonlari */
zedin_crypto_status_t zedin_crypto_init(void);
zedin_crypto_status_t zedin_crypto_keypair_generate(zedin_keypair_t *keypair);
zedin_crypto_status_t zedin_crypto_client_session_keys(
    zedin_session_keys_t *client_keys,
    const zedin_keypair_t *client_keypair,
    const unsigned char server_pk[ZEDIN_CRYPTO_PUBLICKEYBYTES]
);
zedin_crypto_status_t zedin_crypto_server_session_keys(
    zedin_session_keys_t *server_keys,
    const zedin_keypair_t *server_keypair,
    const unsigned char client_pk[ZEDIN_CRYPTO_PUBLICKEYBYTES]
);
zedin_crypto_status_t zedin_crypto_verify_session_keys(
    const zedin_session_keys_t *client_keys,
    const zedin_session_keys_t *server_keys
);

/* AEAD Sifreleme ve Cozme API'si */
zedin_crypto_status_t zedin_crypto_encrypt(
    unsigned char *out,
    size_t *out_len,
    size_t max_out_len,
    const unsigned char *plaintext,
    size_t plaintext_len,
    const unsigned char *aad,
    size_t aad_len,
    const unsigned char key[ZEDIN_CRYPTO_AEAD_KEYBYTES]
);

zedin_crypto_status_t zedin_crypto_decrypt(
    unsigned char *plaintext,
    size_t *plaintext_len,
    size_t max_plaintext_len,
    const unsigned char *in,
    size_t in_len,
    const unsigned char *aad,
    size_t aad_len,
    const unsigned char key[ZEDIN_CRYPTO_AEAD_KEYBYTES]
);

/* Ed25519 Identity API */
zedin_crypto_status_t zedin_crypto_identity_generate(zedin_identity_t *identity);

zedin_crypto_status_t zedin_crypto_identity_sign(
    unsigned char signature[ZEDIN_CRYPTO_SIGNATUREBYTES],
    const unsigned char *message,
    size_t message_len,
    const zedin_identity_t *identity
);

zedin_crypto_status_t zedin_crypto_identity_verify(
    const unsigned char signature[ZEDIN_CRYPTO_SIGNATUREBYTES],
    const unsigned char *message,
    size_t message_len,
    const unsigned char public_key[ZEDIN_CRYPTO_IDENTITY_PUBLICKEYBYTES]
);

/* Handshake Transcript ve Signature Binding API */
zedin_crypto_status_t zedin_crypto_handshake_transcript_init(
    zedin_handshake_transcript_t *transcript,
    uint16_t version,
    zedin_role_t signer_role,
    const unsigned char client_ephemeral_pk[ZEDIN_CRYPTO_PUBLICKEYBYTES],
    const unsigned char server_ephemeral_pk[ZEDIN_CRYPTO_PUBLICKEYBYTES],
    const unsigned char client_identity_pk[ZEDIN_CRYPTO_IDENTITY_PUBLICKEYBYTES],
    const unsigned char server_identity_pk[ZEDIN_CRYPTO_IDENTITY_PUBLICKEYBYTES]
);

zedin_crypto_status_t zedin_crypto_serialize_transcript(
    const zedin_handshake_transcript_t *transcript,
    unsigned char *out_buf,
    size_t max_out,
    size_t *out_len
);

zedin_crypto_status_t zedin_crypto_handshake_sign(
    unsigned char signature[ZEDIN_CRYPTO_SIGNATUREBYTES],
    const zedin_handshake_transcript_t *transcript,
    const zedin_identity_t *signer_identity
);

zedin_crypto_status_t zedin_crypto_handshake_verify(
    const unsigned char signature[ZEDIN_CRYPTO_SIGNATUREBYTES],
    const zedin_handshake_transcript_t *transcript,
    const unsigned char signer_identity_pk[ZEDIN_CRYPTO_IDENTITY_PUBLICKEYBYTES]
);

/* Handshake State Machine API */
zedin_crypto_status_t zedin_crypto_handshake_client_init(
    zedin_handshake_ctx_t *ctx,
    uint16_t version,
    const zedin_identity_t *client_identity
);

zedin_crypto_status_t zedin_crypto_handshake_server_init(
    zedin_handshake_ctx_t *ctx,
    uint16_t version,
    const zedin_identity_t *server_identity
);

zedin_crypto_status_t zedin_crypto_handshake_server_process_client_hello(
    zedin_handshake_ctx_t *server_ctx,
    const unsigned char client_ephemeral_pk[ZEDIN_CRYPTO_PUBLICKEYBYTES],
    const unsigned char client_identity_pk[ZEDIN_CRYPTO_IDENTITY_PUBLICKEYBYTES],
    unsigned char out_server_ephemeral_pk[ZEDIN_CRYPTO_PUBLICKEYBYTES],
    unsigned char out_server_identity_pk[ZEDIN_CRYPTO_IDENTITY_PUBLICKEYBYTES],
    unsigned char out_server_signature[ZEDIN_CRYPTO_SIGNATUREBYTES]
);

zedin_crypto_status_t zedin_crypto_handshake_client_process_server_hello(
    zedin_handshake_ctx_t *client_ctx,
    const unsigned char server_ephemeral_pk[ZEDIN_CRYPTO_PUBLICKEYBYTES],
    const unsigned char server_identity_pk[ZEDIN_CRYPTO_IDENTITY_PUBLICKEYBYTES],
    const unsigned char server_signature[ZEDIN_CRYPTO_SIGNATUREBYTES]
);

zedin_crypto_status_t zedin_crypto_handshake_client_finalize(
    zedin_handshake_ctx_t *client_ctx,
    unsigned char out_client_signature[ZEDIN_CRYPTO_SIGNATUREBYTES]
);

zedin_crypto_status_t zedin_crypto_handshake_server_finalize(
    zedin_handshake_ctx_t *server_ctx,
    const unsigned char client_signature[ZEDIN_CRYPTO_SIGNATUREBYTES]
);

zedin_crypto_status_t zedin_crypto_handshake_get_session_keys(
    const zedin_handshake_ctx_t *ctx,
    zedin_session_keys_t *out_session_keys
);

/* ========================================================================= */
/* ASAMA 6: SEQUENCE, NONCE, REPLAY PROTECTION & APP DATA API                */
/* ========================================================================= */

zedin_crypto_status_t zedin_crypto_nonce_generate_deterministic(
    unsigned char nonce[ZEDIN_CRYPTO_AEAD_NPUBBYTES],
    zedin_direction_t direction,
    const unsigned char session_id[ZEDIN_SESSION_ID_BYTES],
    uint64_t sequence
);

zedin_crypto_status_t zedin_crypto_replay_check_and_update(
    zedin_replay_state_t *replay_state,
    uint64_t sequence
);

zedin_crypto_status_t zedin_crypto_encrypt_app_data(
    zedin_handshake_ctx_t *ctx,
    unsigned char *out,
    size_t *out_len,
    size_t max_out_len,
    const unsigned char *plaintext,
    size_t plaintext_len,
    uint64_t *out_sequence
);

zedin_crypto_status_t zedin_crypto_decrypt_app_data(
    zedin_handshake_ctx_t *ctx,
    unsigned char *plaintext,
    size_t *plaintext_len,
    size_t max_plaintext_len,
    const unsigned char *in,
    size_t in_len,
    uint64_t sequence
);

/* Cleanup Fonksiyonlari */
void zedin_crypto_clean(void *p, size_t len);
void zedin_crypto_keypair_clean_secret(zedin_keypair_t *keypair);
void zedin_crypto_session_keys_clean(zedin_session_keys_t *session_keys);
void zedin_crypto_identity_clean_secret(zedin_identity_t *identity);
void zedin_crypto_handshake_ctx_clean(zedin_handshake_ctx_t *ctx);

#endif /* ZEDIN_CRYPTO_H */

