#include "zip_security.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

#define ZIP_SECURITY_MAGIC_BYTE_0 0x5AU
#define ZIP_SECURITY_MAGIC_BYTE_1 0x49U
#define ZIP_SECURITY_MAGIC_BYTE_2 0x50U
#define ZIP_SECURITY_MAGIC_BYTE_3 0x31U

static void write_u16_be(
    unsigned char *out,
    uint16_t value
)
{
    out[0] = (unsigned char)((value >> 8) & 0xFFU);
    out[1] = (unsigned char)(value & 0xFFU);
}

static uint16_t read_u16_be(
    const unsigned char *in
)
{
    return (uint16_t)(
        ((uint16_t)in[0] << 8) |
        (uint16_t)in[1]
    );
}

static void write_u32_be(
    unsigned char *out,
    uint32_t value
)
{
    out[0] = (unsigned char)((value >> 24) & 0xFFU);
    out[1] = (unsigned char)((value >> 16) & 0xFFU);
    out[2] = (unsigned char)((value >> 8) & 0xFFU);
    out[3] = (unsigned char)(value & 0xFFU);
}

static uint32_t read_u32_be(
    const unsigned char *in
)
{
    return
        ((uint32_t)in[0] << 24) |
        ((uint32_t)in[1] << 16) |
        ((uint32_t)in[2] << 8) |
        (uint32_t)in[3];
}

static void write_u64_be(
    unsigned char *out,
    uint64_t value
)
{
    out[0] = (unsigned char)((value >> 56) & 0xFFU);
    out[1] = (unsigned char)((value >> 48) & 0xFFU);
    out[2] = (unsigned char)((value >> 40) & 0xFFU);
    out[3] = (unsigned char)((value >> 32) & 0xFFU);
    out[4] = (unsigned char)((value >> 24) & 0xFFU);
    out[5] = (unsigned char)((value >> 16) & 0xFFU);
    out[6] = (unsigned char)((value >> 8) & 0xFFU);
    out[7] = (unsigned char)(value & 0xFFU);
}

static uint64_t read_u64_be(
    const unsigned char *in
)
{
    return
        ((uint64_t)in[0] << 56) |
        ((uint64_t)in[1] << 48) |
        ((uint64_t)in[2] << 40) |
        ((uint64_t)in[3] << 32) |
        ((uint64_t)in[4] << 24) |
        ((uint64_t)in[5] << 16) |
        ((uint64_t)in[6] << 8) |
        (uint64_t)in[7];
}

static int is_valid_packet_type(
    uint8_t packet_type
)
{
    return packet_type == ZIP_PACKET_CLIENT_HELLO ||
           packet_type == ZIP_PACKET_SERVER_HELLO ||
           packet_type == ZIP_PACKET_CLIENT_FINISH ||
           packet_type == ZIP_PACKET_APP_DATA;
}

static int is_valid_direction(
    uint8_t direction
)
{
    return direction == ZIP_DIRECTION_CLIENT_TO_SERVER ||
           direction == ZIP_DIRECTION_SERVER_TO_CLIENT;
}

static zip_direction_t role_to_direction(
    zedin_role_t role
)
{
    if (role == ZEDIN_ROLE_CLIENT) {
        return ZIP_DIRECTION_CLIENT_TO_SERVER;
    }

    return ZIP_DIRECTION_SERVER_TO_CLIENT;
}

zip_security_status_t zip_security_header_validate(
    const zip_packet_header_t *header
)
{
    if (header == NULL) {
        return ZIP_SECURITY_ERR_NULL_PARAM;
    }

    if (header->version != ZIP_SECURITY_VERSION) {
        return ZIP_SECURITY_ERR_INVALID_VERSION;
    }

    if (!is_valid_packet_type((uint8_t)header->packet_type)) {
        return ZIP_SECURITY_ERR_INVALID_TYPE;
    }

    if (!is_valid_direction((uint8_t)header->direction)) {
        return ZIP_SECURITY_ERR_INVALID_DIRECTION;
    }

    if (header->payload_length > ZIP_SECURITY_MAX_PAYLOAD) {
        return ZIP_SECURITY_ERR_INVALID_LENGTH;
    }

    /*
     * Handshake paketlerinde sequence kullanılmaz.
     */
    if (header->packet_type != ZIP_PACKET_APP_DATA &&
        header->sequence != 0U) {
        return ZIP_SECURITY_ERR_INVALID_LENGTH;
    }

    return ZIP_SECURITY_OK;
}

zip_security_status_t zip_security_header_encode(
    const zip_packet_header_t *header,
    unsigned char out[ZIP_SECURITY_HEADER_SIZE]
)
{
    zip_security_status_t status;

    if (header == NULL || out == NULL) {
        return ZIP_SECURITY_ERR_NULL_PARAM;
    }

    status = zip_security_header_validate(header);

    if (status != ZIP_SECURITY_OK) {
        return status;
    }

    out[0] = ZIP_SECURITY_MAGIC_BYTE_0;
    out[1] = ZIP_SECURITY_MAGIC_BYTE_1;
    out[2] = ZIP_SECURITY_MAGIC_BYTE_2;
    out[3] = ZIP_SECURITY_MAGIC_BYTE_3;

    write_u16_be(&out[4], header->version);

    out[6] = (unsigned char)header->packet_type;
    out[7] = (unsigned char)header->direction;

    write_u64_be(&out[8], header->sequence);

    write_u32_be(&out[16], header->payload_length);

    return ZIP_SECURITY_OK;
}

zip_security_status_t zip_security_header_decode(
    const unsigned char in[ZIP_SECURITY_HEADER_SIZE],
    zip_packet_header_t *header
)
{
    if (in == NULL || header == NULL) {
        return ZIP_SECURITY_ERR_NULL_PARAM;
    }

    if (in[0] != ZIP_SECURITY_MAGIC_BYTE_0 ||
        in[1] != ZIP_SECURITY_MAGIC_BYTE_1 ||
        in[2] != ZIP_SECURITY_MAGIC_BYTE_2 ||
        in[3] != ZIP_SECURITY_MAGIC_BYTE_3) {
        return ZIP_SECURITY_ERR_INVALID_MAGIC;
    }

    header->version = read_u16_be(&in[4]);
    header->packet_type = (zip_packet_type_t)in[6];
    header->direction = (zip_direction_t)in[7];
    header->sequence = read_u64_be(&in[8]);
    header->payload_length = read_u32_be(&in[16]);

    return zip_security_header_validate(header);
}

zip_security_status_t zip_security_send_all(
    int socket_fd,
    const unsigned char *data,
    size_t data_len
)
{
    size_t total_sent = 0U;

    if (data == NULL && data_len != 0U) {
        return ZIP_SECURITY_ERR_NULL_PARAM;
    }

    while (total_sent < data_len) {
        ssize_t sent = send(
            socket_fd,
            data + total_sent,
            data_len - total_sent,
            0
        );

        if (sent > 0) {
            total_sent += (size_t)sent;
            continue;
        }

        if (sent == 0) {
            return ZIP_SECURITY_ERR_EOF;
        }

        if (errno == EINTR) {
            continue;
        }

        return ZIP_SECURITY_ERR_IO;
    }

    return ZIP_SECURITY_OK;
}

zip_security_status_t zip_security_recv_all(
    int socket_fd,
    unsigned char *data,
    size_t data_len
)
{
    size_t total_received = 0U;

    if (data == NULL && data_len != 0U) {
        return ZIP_SECURITY_ERR_NULL_PARAM;
    }

    while (total_received < data_len) {
        ssize_t received = recv(
            socket_fd,
            data + total_received,
            data_len - total_received,
            0
        );

        if (received > 0) {
            total_received += (size_t)received;
            continue;
        }

        if (received == 0) {
            return ZIP_SECURITY_ERR_EOF;
        }

        if (errno == EINTR) {
            continue;
        }

        return ZIP_SECURITY_ERR_IO;
    }

    return ZIP_SECURITY_OK;
}

zip_security_status_t zip_security_send_packet(
    int socket_fd,
    const zip_packet_header_t *header,
    const unsigned char *payload
)
{
    unsigned char encoded_header[ZIP_SECURITY_HEADER_SIZE];
    zip_security_status_t status;

    if (header == NULL) {
        return ZIP_SECURITY_ERR_NULL_PARAM;
    }

    if (payload == NULL && header->payload_length != 0U) {
        return ZIP_SECURITY_ERR_NULL_PARAM;
    }

    status = zip_security_header_encode(
        header,
        encoded_header
    );

    if (status != ZIP_SECURITY_OK) {
        return status;
    }

    status = zip_security_send_all(
        socket_fd,
        encoded_header,
        ZIP_SECURITY_HEADER_SIZE
    );

    if (status != ZIP_SECURITY_OK) {
        return status;
    }

    if (header->payload_length == 0U) {
        return ZIP_SECURITY_OK;
    }

    return zip_security_send_all(
        socket_fd,
        payload,
        header->payload_length
    );
}

zip_security_status_t zip_security_recv_packet(
    int socket_fd,
    zip_packet_header_t *header,
    unsigned char *payload,
    size_t payload_capacity,
    size_t *payload_length
)
{
    unsigned char encoded_header[ZIP_SECURITY_HEADER_SIZE];
    zip_security_status_t status;

    if (header == NULL || payload_length == NULL) {
        return ZIP_SECURITY_ERR_NULL_PARAM;
    }

    status = zip_security_recv_all(
        socket_fd,
        encoded_header,
        ZIP_SECURITY_HEADER_SIZE
    );

    if (status != ZIP_SECURITY_OK) {
        return status;
    }

    status = zip_security_header_decode(
        encoded_header,
        header
    );

    if (status != ZIP_SECURITY_OK) {
        return status;
    }

    if ((size_t)header->payload_length > payload_capacity) {
        return ZIP_SECURITY_ERR_BUFFER_TOO_SMALL;
    }

    if (header->payload_length != 0U && payload == NULL) {
        return ZIP_SECURITY_ERR_NULL_PARAM;
    }

    status = zip_security_recv_all(
        socket_fd,
        payload,
        header->payload_length
    );

    if (status != ZIP_SECURITY_OK) {
        return status;
    }

    *payload_length = (size_t)header->payload_length;

    return ZIP_SECURITY_OK;
}

zip_security_status_t zip_security_send_encrypted_app_data(
    int socket_fd,
    zedin_handshake_ctx_t *ctx,
    const unsigned char *plaintext,
    size_t plaintext_len
)
{
    unsigned char *encrypted = NULL;
    size_t encrypted_len = 0U;
    uint64_t sequence = 0U;

    zip_packet_header_t header;
    zip_security_status_t status;
    zedin_crypto_status_t crypto_status;

    if (ctx == NULL) {
        return ZIP_SECURITY_ERR_NULL_PARAM;
    }

    if (plaintext == NULL && plaintext_len != 0U) {
        return ZIP_SECURITY_ERR_NULL_PARAM;
    }

    if (plaintext_len > ZIP_SECURITY_MAX_PLAINTEXT) {
        return ZIP_SECURITY_ERR_INVALID_LENGTH;
    }

    encrypted = malloc(ZIP_SECURITY_MAX_PAYLOAD);

    if (encrypted == NULL) {
        return ZIP_SECURITY_ERR_IO;
    }

    crypto_status = zedin_crypto_encrypt_app_data(
        ctx,
        encrypted,
        &encrypted_len,
        ZIP_SECURITY_MAX_PAYLOAD,
        plaintext,
        plaintext_len,
        &sequence
    );

    if (crypto_status != ZEDIN_CRYPTO_OK) {
        free(encrypted);
        return ZIP_SECURITY_ERR_CRYPTO;
    }

    if (encrypted_len > ZIP_SECURITY_MAX_PAYLOAD) {
        free(encrypted);
        return ZIP_SECURITY_ERR_INVALID_LENGTH;
    }

    header.version = ctx->version;
    header.packet_type = ZIP_PACKET_APP_DATA;
    header.direction = role_to_direction(ctx->role);
    header.sequence = sequence;
    header.payload_length = (uint32_t)encrypted_len;

    status = zip_security_send_packet(
        socket_fd,
        &header,
        encrypted
    );

    free(encrypted);

    return status;
}

zip_security_status_t zip_security_recv_encrypted_app_data(
    int socket_fd,
    zedin_handshake_ctx_t *ctx,
    unsigned char *plaintext,
    size_t plaintext_capacity,
    size_t *plaintext_len
)
{
    unsigned char *encrypted = NULL;
    size_t encrypted_len = 0U;

    zip_packet_header_t header;
    zip_security_status_t status;
    zedin_crypto_status_t crypto_status;

    zip_direction_t expected_direction;

    if (ctx == NULL || plaintext_len == NULL) {
        return ZIP_SECURITY_ERR_NULL_PARAM;
    }

    if (plaintext == NULL && plaintext_capacity != 0U) {
        return ZIP_SECURITY_ERR_NULL_PARAM;
    }

    if (ctx->role == ZEDIN_ROLE_CLIENT) {
        expected_direction = ZIP_DIRECTION_SERVER_TO_CLIENT;
    } else if (ctx->role == ZEDIN_ROLE_SERVER) {
        expected_direction = ZIP_DIRECTION_CLIENT_TO_SERVER;
    } else {
        return ZIP_SECURITY_ERR_CRYPTO;
    }

    encrypted = malloc(ZIP_SECURITY_MAX_PAYLOAD);

    if (encrypted == NULL) {
        return ZIP_SECURITY_ERR_IO;
    }

    status = zip_security_recv_packet(
        socket_fd,
        &header,
        encrypted,
        ZIP_SECURITY_MAX_PAYLOAD,
        &encrypted_len
    );

    if (status != ZIP_SECURITY_OK) {
        free(encrypted);
        return status;
    }

    if (header.packet_type != ZIP_PACKET_APP_DATA) {
        free(encrypted);
        return ZIP_SECURITY_ERR_INVALID_TYPE;
    }

    if (header.direction != expected_direction) {
        free(encrypted);
        return ZIP_SECURITY_ERR_INVALID_DIRECTION;
    }

    if (header.version != ctx->version) {
        free(encrypted);
        return ZIP_SECURITY_ERR_INVALID_VERSION;
    }

    crypto_status = zedin_crypto_decrypt_app_data(
        ctx,
        plaintext,
        plaintext_len,
        plaintext_capacity,
        encrypted,
        encrypted_len,
        header.sequence
    );

    free(encrypted);

    if (crypto_status != ZEDIN_CRYPTO_OK) {
        return ZIP_SECURITY_ERR_CRYPTO;
    }

    return ZIP_SECURITY_OK;
}
