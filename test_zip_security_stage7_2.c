#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <sys/socket.h>
#include <unistd.h>

#include "zip_security.h"
#include "güvenlik/zedin_crypto.h"

#define TEST_BUFFER_SIZE 1024

static int tests_passed = 0;
static int tests_failed = 0;

static void test_result(const char *name, int ok)
{
    if (ok) {
        printf("[PASS] %s\n", name);
        tests_passed++;
    } else {
        printf("[FAIL] %s\n", name);
        tests_failed++;
    }
}

static int setup_handshake(
    zedin_handshake_ctx_t *client,
    zedin_handshake_ctx_t *server,
    zedin_identity_t *client_identity,
    zedin_identity_t *server_identity)
{
    unsigned char client_ephemeral[ZEDIN_CRYPTO_PUBLICKEYBYTES];
    unsigned char client_identity_pk[ZEDIN_CRYPTO_IDENTITY_PUBLICKEYBYTES];

    unsigned char server_ephemeral[ZEDIN_CRYPTO_PUBLICKEYBYTES];
    unsigned char server_identity_pk[ZEDIN_CRYPTO_IDENTITY_PUBLICKEYBYTES];

    unsigned char server_signature[ZEDIN_CRYPTO_SIGNATUREBYTES];
    unsigned char client_signature[ZEDIN_CRYPTO_SIGNATUREBYTES];

    if (zedin_crypto_identity_generate(client_identity) != ZEDIN_CRYPTO_OK)
        return 0;

    if (zedin_crypto_identity_generate(server_identity) != ZEDIN_CRYPTO_OK)
        return 0;

    if (zedin_crypto_handshake_client_init(
            client,
            ZEDIN_ZIP_PROTOCOL_VERSION_1,
            client_identity) != ZEDIN_CRYPTO_OK)
        return 0;

    if (zedin_crypto_handshake_server_init(
            server,
            ZEDIN_ZIP_PROTOCOL_VERSION_1,
            server_identity) != ZEDIN_CRYPTO_OK)
        return 0;

    memcpy(
        client_ephemeral,
        client->local_ephemeral_kp.public_key,
        ZEDIN_CRYPTO_PUBLICKEYBYTES
    );

    memcpy(
        client_identity_pk,
        client_identity->public_key,
        ZEDIN_CRYPTO_IDENTITY_PUBLICKEYBYTES
    );

    if (zedin_crypto_handshake_server_process_client_hello(
            server,
            client_ephemeral,
            client_identity_pk,
            server_ephemeral,
            server_identity_pk,
            server_signature) != ZEDIN_CRYPTO_OK)
        return 0;

    if (zedin_crypto_handshake_client_process_server_hello(
            client,
            server_ephemeral,
            server_identity_pk,
            server_signature) != ZEDIN_CRYPTO_OK)
        return 0;

    if (zedin_crypto_handshake_client_finalize(
            client,
            client_signature) != ZEDIN_CRYPTO_OK)
        return 0;

    if (zedin_crypto_handshake_server_finalize(
            server,
            client_signature) != ZEDIN_CRYPTO_OK)
        return 0;

    if (client->state != ZEDIN_HS_STATE_ESTABLISHED)
        return 0;

    if (server->state != ZEDIN_HS_STATE_ESTABLISHED)
        return 0;

    return 1;
}

static void cleanup_test(
    int sockets[2],
    zedin_handshake_ctx_t *client,
    zedin_handshake_ctx_t *server,
    zedin_identity_t *client_identity,
    zedin_identity_t *server_identity)
{
    zedin_crypto_handshake_ctx_clean(client);
    zedin_crypto_handshake_ctx_clean(server);

    zedin_crypto_identity_clean_secret(client_identity);
    zedin_crypto_identity_clean_secret(server_identity);

    close(sockets[0]);
    close(sockets[1]);
}

static int test_encrypted_app_data(void)
{
    int sockets[2];

    zedin_handshake_ctx_t client;
    zedin_handshake_ctx_t server;

    zedin_identity_t client_identity;
    zedin_identity_t server_identity;

    const unsigned char message[] =
        "Zedin Internet Protocol encrypted message";

    unsigned char received[TEST_BUFFER_SIZE];
    size_t received_len = 0;

    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) != 0)
        return 0;

    memset(&client, 0, sizeof(client));
    memset(&server, 0, sizeof(server));
    memset(&client_identity, 0, sizeof(client_identity));
    memset(&server_identity, 0, sizeof(server_identity));

    if (!setup_handshake(
            &client,
            &server,
            &client_identity,
            &server_identity)) {

        close(sockets[0]);
        close(sockets[1]);
        return 0;
    }

    if (zip_security_send_encrypted_app_data(
            sockets[0],
            &client,
            message,
            sizeof(message) - 1) != ZIP_SECURITY_OK) {

        cleanup_test(
            sockets,
            &client,
            &server,
            &client_identity,
            &server_identity);

        return 0;
    }

    if (client.tx_seq != 1) {
        cleanup_test(
            sockets,
            &client,
            &server,
            &client_identity,
            &server_identity);

        return 0;
    }

    if (zip_security_recv_encrypted_app_data(
            sockets[1],
            &server,
            received,
            sizeof(received),
            &received_len) != ZIP_SECURITY_OK) {

        cleanup_test(
            sockets,
            &client,
            &server,
            &client_identity,
            &server_identity);

        return 0;
    }

    int ok =
        received_len == sizeof(message) - 1 &&
        memcmp(received, message, sizeof(message) - 1) == 0 &&
        server.replay_state.initialized &&
        server.replay_state.last_rx_seq == 0;

    cleanup_test(
        sockets,
        &client,
        &server,
        &client_identity,
        &server_identity);

    return ok;
}

static int test_replay_rejected(void)
{
    int sockets[2];

    zedin_handshake_ctx_t client;
    zedin_handshake_ctx_t server;

    zedin_identity_t client_identity;
    zedin_identity_t server_identity;

    const unsigned char message[] = "replay-test";

    unsigned char encrypted[ZIP_SECURITY_MAX_PAYLOAD];
    unsigned char received[TEST_BUFFER_SIZE];

    size_t encrypted_len = 0;
    size_t received_len = 0;

    uint64_t sequence;

    zip_packet_header_t header;

    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) != 0)
        return 0;

    memset(&client, 0, sizeof(client));
    memset(&server, 0, sizeof(server));
    memset(&client_identity, 0, sizeof(client_identity));
    memset(&server_identity, 0, sizeof(server_identity));

    if (!setup_handshake(
            &client,
            &server,
            &client_identity,
            &server_identity))
        goto fail;

    if (zedin_crypto_encrypt_app_data(
            &client,
            encrypted,
            &encrypted_len,
            sizeof(encrypted),
            message,
            sizeof(message) - 1,
            &sequence) != ZEDIN_CRYPTO_OK)
        goto fail;

    header.version = client.version;
    header.packet_type = ZIP_PACKET_APP_DATA;
    header.direction = ZIP_DIRECTION_CLIENT_TO_SERVER;
    header.sequence = sequence;
    header.payload_length = (uint32_t)encrypted_len;

    if (zip_security_send_packet(
            sockets[0],
            &header,
            encrypted) != ZIP_SECURITY_OK)
        goto fail;

    if (zip_security_recv_encrypted_app_data(
            sockets[1],
            &server,
            received,
            sizeof(received),
            &received_len) != ZIP_SECURITY_OK)
        goto fail;

    /*
     * Aynı paketi tekrar gönderiyoruz.
     * Server sequence=0 değerini daha önce kabul etti.
     * İkinci paket replay olarak reddedilmelidir.
     */
    if (zip_security_send_packet(
            sockets[0],
            &header,
            encrypted) != ZIP_SECURITY_OK)
        goto fail;

    if (zip_security_recv_encrypted_app_data(
            sockets[1],
            &server,
            received,
            sizeof(received),
            &received_len) == ZIP_SECURITY_ERR_CRYPTO) {

        cleanup_test(
            sockets,
            &client,
            &server,
            &client_identity,
            &server_identity);

        return 1;
    }

fail:
    cleanup_test(
        sockets,
        &client,
        &server,
        &client_identity,
        &server_identity);

    return 0;
}

static int test_sequence_tampering(void)
{
    int sockets[2];

    zedin_handshake_ctx_t client;
    zedin_handshake_ctx_t server;

    zedin_identity_t client_identity;
    zedin_identity_t server_identity;

    const unsigned char message[] = "sequence-tampering";

    unsigned char encrypted[ZIP_SECURITY_MAX_PAYLOAD];
    unsigned char received[TEST_BUFFER_SIZE];

    size_t encrypted_len = 0;
    size_t received_len = 0;

    uint64_t sequence;

    zip_packet_header_t header;

    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) != 0)
        return 0;

    memset(&client, 0, sizeof(client));
    memset(&server, 0, sizeof(server));
    memset(&client_identity, 0, sizeof(client_identity));
    memset(&server_identity, 0, sizeof(server_identity));

    if (!setup_handshake(
            &client,
            &server,
            &client_identity,
            &server_identity))
        goto fail;

    if (zedin_crypto_encrypt_app_data(
            &client,
            encrypted,
            &encrypted_len,
            sizeof(encrypted),
            message,
            sizeof(message) - 1,
            &sequence) != ZEDIN_CRYPTO_OK)
        goto fail;

    header.version = client.version;
    header.packet_type = ZIP_PACKET_APP_DATA;
    header.direction = ZIP_DIRECTION_CLIENT_TO_SERVER;

    /*
     * Ciphertext sequence=0 ile üretildi.
     * Header'a sequence=1 yazıyoruz.
     * Böylece nonce/AAD doğrulaması başarısız olmalıdır.
     */
    header.sequence = sequence + 1;
    header.payload_length = (uint32_t)encrypted_len;

    if (zip_security_send_packet(
            sockets[0],
            &header,
            encrypted) != ZIP_SECURITY_OK)
        goto fail;

    if (zip_security_recv_encrypted_app_data(
            sockets[1],
            &server,
            received,
            sizeof(received),
            &received_len) == ZIP_SECURITY_ERR_CRYPTO) {

        cleanup_test(
            sockets,
            &client,
            &server,
            &client_identity,
            &server_identity);

        return 1;
    }

fail:
    cleanup_test(
        sockets,
        &client,
        &server,
        &client_identity,
        &server_identity);

    return 0;
}

static int test_wrong_direction(void)
{
    int sockets[2];

    zedin_handshake_ctx_t client;
    zedin_handshake_ctx_t server;

    zedin_identity_t client_identity;
    zedin_identity_t server_identity;

    const unsigned char message[] = "direction-test";

    unsigned char encrypted[ZIP_SECURITY_MAX_PAYLOAD];
    unsigned char received[TEST_BUFFER_SIZE];

    size_t encrypted_len = 0;
    size_t received_len = 0;

    uint64_t sequence;

    zip_packet_header_t header;

    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) != 0)
        return 0;

    memset(&client, 0, sizeof(client));
    memset(&server, 0, sizeof(server));
    memset(&client_identity, 0, sizeof(client_identity));
    memset(&server_identity, 0, sizeof(server_identity));

    if (!setup_handshake(
            &client,
            &server,
            &client_identity,
            &server_identity))
        goto fail;

    if (zedin_crypto_encrypt_app_data(
            &client,
            encrypted,
            &encrypted_len,
            sizeof(encrypted),
            message,
            sizeof(message) - 1,
            &sequence) != ZEDIN_CRYPTO_OK)
        goto fail;

    header.version = client.version;
    header.packet_type = ZIP_PACKET_APP_DATA;

    /*
     * Gerçekte client -> server olan paketi
     * server -> client olarak işaretliyoruz.
     */
    header.direction = ZIP_DIRECTION_SERVER_TO_CLIENT;
    header.sequence = sequence;

    header.payload_length = (uint32_t)encrypted_len;

    if (zip_security_send_packet(
            sockets[0],
            &header,
            encrypted) != ZIP_SECURITY_OK)
        goto fail;

    if (zip_security_recv_encrypted_app_data(
            sockets[1],
            &server,
            received,
            sizeof(received),
            &received_len) == ZIP_SECURITY_ERR_INVALID_DIRECTION) {

        cleanup_test(
            sockets,
            &client,
            &server,
            &client_identity,
            &server_identity);

        return 1;
    }

fail:
    cleanup_test(
        sockets,
        &client,
        &server,
        &client_identity,
        &server_identity);

    return 0;
}

int main(void)
{
    printf("=== ZIP Security Stage 7.2 Crypto Integration Tests ===\n\n");

    if (zedin_crypto_init() != ZEDIN_CRYPTO_OK) {
        printf("[FAIL] libsodium initialization\n");
        return 1;
    }

    test_result(
        "Encrypted APP_DATA send/recv",
        test_encrypted_app_data());

    test_result(
        "Replay packet rejected",
        test_replay_rejected());

    test_result(
        "Sequence tampering rejected",
        test_sequence_tampering());

    test_result(
        "Wrong direction rejected",
        test_wrong_direction());

    printf("\nResult: %d/%d tests passed\n",
           tests_passed,
           tests_passed + tests_failed);

    return tests_failed == 0 ? 0 : 1;
}
