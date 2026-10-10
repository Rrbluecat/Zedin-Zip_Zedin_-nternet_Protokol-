#ifndef ZIP_SECURITY_H
#define ZIP_SECURITY_H

#include <stddef.h>
#include <stdint.h>

#include "güvenlik/zedin_crypto.h"

#define ZIP_SECURITY_MAGIC 0x5A495031U
#define ZIP_SECURITY_VERSION 0x0100U

/*
 * Header:
 *
 * 4 bytes  magic
 * 2 bytes  version
 * 1 byte   packet type
 * 1 byte   direction
 * 8 bytes  sequence
 * 4 bytes  payload length
 *
 * Total: 20 bytes
 */
#define ZIP_SECURITY_HEADER_SIZE 20U

/*
 * Wire payload maksimumu.
 *
 * APP_DATA:
 * 24 byte deterministic nonce
 * + ciphertext
 * + 16 byte authentication tag
 *
 * Bu nedenle maksimum plaintext:
 * 65535 - 24 - 16 = 65495 byte
 */
#define ZIP_SECURITY_MAX_PAYLOAD 65535U
#define ZIP_SECURITY_MAX_PLAINTEXT \
    (ZIP_SECURITY_MAX_PAYLOAD - ZEDIN_CRYPTO_AEAD_NPUBBYTES - \
     ZEDIN_CRYPTO_AEAD_ABYTES)

typedef enum {
    ZIP_PACKET_CLIENT_HELLO  = 0x01,
    ZIP_PACKET_SERVER_HELLO  = 0x02,
    ZIP_PACKET_CLIENT_FINISH = 0x03,
    ZIP_PACKET_APP_DATA      = 0x04
} zip_packet_type_t;

typedef enum {
    ZIP_DIRECTION_CLIENT_TO_SERVER = 0x01,
    ZIP_DIRECTION_SERVER_TO_CLIENT = 0x02
} zip_direction_t;

typedef enum {
    ZIP_SECURITY_OK = 0,
    ZIP_SECURITY_ERR_NULL_PARAM = -1,
    ZIP_SECURITY_ERR_INVALID_MAGIC = -2,
    ZIP_SECURITY_ERR_INVALID_VERSION = -3,
    ZIP_SECURITY_ERR_INVALID_TYPE = -4,
    ZIP_SECURITY_ERR_INVALID_DIRECTION = -5,
    ZIP_SECURITY_ERR_INVALID_LENGTH = -6,
    ZIP_SECURITY_ERR_BUFFER_TOO_SMALL = -7,
    ZIP_SECURITY_ERR_IO = -8,
    ZIP_SECURITY_ERR_EOF = -9,
    ZIP_SECURITY_ERR_CRYPTO = -10
} zip_security_status_t;

typedef struct {
    uint16_t version;
    zip_packet_type_t packet_type;
    zip_direction_t direction;
    uint64_t sequence;
    uint32_t payload_length;
} zip_packet_header_t;

zip_security_status_t zip_security_header_encode(
    const zip_packet_header_t *header,
    unsigned char out[ZIP_SECURITY_HEADER_SIZE]
);

zip_security_status_t zip_security_header_decode(
    const unsigned char in[ZIP_SECURITY_HEADER_SIZE],
    zip_packet_header_t *header
);

zip_security_status_t zip_security_header_validate(
    const zip_packet_header_t *header
);

zip_security_status_t zip_security_send_all(
    int socket_fd,
    const unsigned char *data,
    size_t data_len
);

zip_security_status_t zip_security_recv_all(
    int socket_fd,
    unsigned char *data,
    size_t data_len
);

zip_security_status_t zip_security_send_packet(
    int socket_fd,
    const zip_packet_header_t *header,
    const unsigned char *payload
);

zip_security_status_t zip_security_recv_packet(
    int socket_fd,
    zip_packet_header_t *header,
    unsigned char *payload,
    size_t payload_capacity,
    size_t *payload_length
);

/*
 * Aşama 6 crypto katmanını ZIP framing ile birleştirir.
 */
zip_security_status_t zip_security_send_encrypted_app_data(
    int socket_fd,
    zedin_handshake_ctx_t *ctx,
    const unsigned char *plaintext,
    size_t plaintext_len
);

zip_security_status_t zip_security_recv_encrypted_app_data(
    int socket_fd,
    zedin_handshake_ctx_t *ctx,
    unsigned char *plaintext,
    size_t plaintext_capacity,
    size_t *plaintext_len
);

#endif
