#include "zip_security.h"

#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static int test_header_encode_decode(void)
{
    zip_packet_header_t original;
    zip_packet_header_t decoded;
    unsigned char encoded[ZIP_SECURITY_HEADER_SIZE];

    original.version = ZIP_SECURITY_VERSION;
    original.packet_type = ZIP_PACKET_CLIENT_HELLO;
    original.direction = ZIP_DIRECTION_CLIENT_TO_SERVER;
    original.sequence = 0U;
    original.payload_length = 64U;

    if (zip_security_header_encode(&original, encoded) != ZIP_SECURITY_OK) {
        return 0;
    }

    if (zip_security_header_decode(encoded, &decoded) != ZIP_SECURITY_OK) {
        return 0;
    }

    return decoded.version == original.version &&
           decoded.packet_type == original.packet_type &&
           decoded.direction == original.direction &&
           decoded.payload_length == original.payload_length;
}

static int test_invalid_magic(void)
{
    unsigned char encoded[ZIP_SECURITY_HEADER_SIZE] = {
        0
    };

    zip_packet_header_t header;

    encoded[0] = 0xFFU;

    return zip_security_header_decode(
        encoded,
        &header
    ) == ZIP_SECURITY_ERR_INVALID_MAGIC;
}

static int test_invalid_packet_type(void)
{
    zip_packet_header_t header;

    header.version = ZIP_SECURITY_VERSION;
    header.packet_type = (zip_packet_type_t)0xFFU;
    header.direction = ZIP_DIRECTION_CLIENT_TO_SERVER;
    header.payload_length = 0U;

    return zip_security_header_validate(&header) ==
           ZIP_SECURITY_ERR_INVALID_TYPE;
}

static int test_invalid_direction(void)
{
    zip_packet_header_t header;

    header.version = ZIP_SECURITY_VERSION;
    header.packet_type = ZIP_PACKET_APP_DATA;
    header.direction = (zip_direction_t)0xFFU;
    header.payload_length = 0U;

    return zip_security_header_validate(&header) ==
           ZIP_SECURITY_ERR_INVALID_DIRECTION;
}

static int test_invalid_length(void)
{
    zip_packet_header_t header;

    header.version = ZIP_SECURITY_VERSION;
    header.packet_type = ZIP_PACKET_APP_DATA;
    header.direction = ZIP_DIRECTION_CLIENT_TO_SERVER;
    header.payload_length = ZIP_SECURITY_MAX_PAYLOAD + 1U;

    return zip_security_header_validate(&header) ==
           ZIP_SECURITY_ERR_INVALID_LENGTH;
}

static int test_socket_packet(void)
{
    int sockets[2];
    zip_packet_header_t send_header;
    zip_packet_header_t recv_header;

    unsigned char send_payload[] =
        "Zedin Internet Protokolu test paketi";

    unsigned char recv_payload[128];
    size_t recv_length = 0U;

    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) != 0) {
        return 0;
    }

    send_header.version = ZIP_SECURITY_VERSION;
    send_header.packet_type = ZIP_PACKET_APP_DATA;
    send_header.direction = ZIP_DIRECTION_CLIENT_TO_SERVER;
    send_header.payload_length =
        (uint32_t)(sizeof(send_payload) - 1U);

    if (zip_security_send_packet(
            sockets[0],
            &send_header,
            send_payload) != ZIP_SECURITY_OK) {

        close(sockets[0]);
        close(sockets[1]);
        return 0;
    }

    if (zip_security_recv_packet(
            sockets[1],
            &recv_header,
            recv_payload,
            sizeof(recv_payload),
            &recv_length) != ZIP_SECURITY_OK) {

        close(sockets[0]);
        close(sockets[1]);
        return 0;
    }

    close(sockets[0]);
    close(sockets[1]);

    return recv_header.version == send_header.version &&
           recv_header.packet_type == send_header.packet_type &&
           recv_header.direction == send_header.direction &&
           recv_header.payload_length == send_header.payload_length &&
           recv_length == sizeof(send_payload) - 1U &&
           memcmp(
               recv_payload,
               send_payload,
               recv_length
           ) == 0;
}

static int test_buffer_too_small(void)
{
    int sockets[2];

    zip_packet_header_t send_header;
    zip_packet_header_t recv_header;

    unsigned char payload[] = "BUFFER TEST";
    unsigned char tiny_buffer[2];

    size_t recv_length = 0U;

    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) != 0) {
        return 0;
    }

    send_header.version = ZIP_SECURITY_VERSION;
    send_header.packet_type = ZIP_PACKET_APP_DATA;
    send_header.direction = ZIP_DIRECTION_CLIENT_TO_SERVER;
    send_header.payload_length =
        (uint32_t)(sizeof(payload) - 1U);

    if (zip_security_send_packet(
            sockets[0],
            &send_header,
            payload) != ZIP_SECURITY_OK) {

        close(sockets[0]);
        close(sockets[1]);
        return 0;
    }

    if (zip_security_recv_packet(
            sockets[1],
            &recv_header,
            tiny_buffer,
            sizeof(tiny_buffer),
            &recv_length) != ZIP_SECURITY_ERR_BUFFER_TOO_SMALL) {

        close(sockets[0]);
        close(sockets[1]);
        return 0;
    }

    close(sockets[0]);
    close(sockets[1]);

    return 1;
}

int main(void)
{
    int passed = 0;
    int total = 7;

    printf("=== ZIP Security Stage 7 Framing Tests ===\n\n");

    if (test_header_encode_decode()) {
        printf("[PASS] Header encode/decode\n");
        passed++;
    } else {
        printf("[FAIL] Header encode/decode\n");
    }

    if (test_invalid_magic()) {
        printf("[PASS] Invalid magic rejected\n");
        passed++;
    } else {
        printf("[FAIL] Invalid magic rejected\n");
    }

    if (test_invalid_packet_type()) {
        printf("[PASS] Invalid packet type rejected\n");
        passed++;
    } else {
        printf("[FAIL] Invalid packet type rejected\n");
    }

    if (test_invalid_direction()) {
        printf("[PASS] Invalid direction rejected\n");
        passed++;
    } else {
        printf("[FAIL] Invalid direction rejected\n");
    }

    if (test_invalid_length()) {
        printf("[PASS] Invalid payload length rejected\n");
        passed++;
    } else {
        printf("[FAIL] Invalid payload length rejected\n");
    }

    if (test_socket_packet()) {
        printf("[PASS] Real socket packet send/recv\n");
        passed++;
    } else {
        printf("[FAIL] Real socket packet send/recv\n");
    }

    if (!test_buffer_too_small()) {
        printf("[FAIL] Buffer size protection\n");
    } else {
        printf("[PASS] Buffer size protection\n");
        passed++;
    }

    printf("\nResult: %d/%d tests passed\n", passed, total);

    return passed == total ? 0 : 1;
}
