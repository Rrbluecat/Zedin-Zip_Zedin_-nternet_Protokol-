#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "zip_security.h"
#include "güvenlik/zedin_crypto.h"

int main(void){
    int soket;
    int sonuc;
    char mesaj[] = "ZEDIN/1.0\nGET /anasayfa\n";
    char cevap[256];
    struct sockaddr_in adres;
    char cevap_versiyon[64];
    char durum[64];
    int cevap_uzunlugu;
    char *govde;
    char header[256];
    zedin_identity_t client_identity;
    zedin_handshake_ctx_t client_ctx;

    unsigned char handshake_payload[128];
    size_t handshake_payload_length;

    zip_packet_header_t handshake_header;
    zip_security_status_t security_status;
    zedin_crypto_status_t crypto_status;

    unsigned char server_ephemeral_pk[ZEDIN_CRYPTO_PUBLICKEYBYTES];
    unsigned char server_identity_pk[ZEDIN_CRYPTO_IDENTITY_PUBLICKEYBYTES];
    unsigned char server_signature[ZEDIN_CRYPTO_SIGNATUREBYTES];
    unsigned char client_signature[ZEDIN_CRYPTO_SIGNATUREBYTES];
    adres.sin_family = AF_INET;
    adres.sin_port = htons(8080);
    adres.sin_addr.s_addr = inet_addr("127.0.0.1");

    soket = socket(AF_INET, SOCK_STREAM, 0);
    if (soket != -1){
    printf("Soket basarili!\n");
    }
    else{
    printf("Soket basarisiz!\n");
    }
    sonuc = connect(soket, (struct sockaddr*)&adres, sizeof(adres));
    if (sonuc != -1){
    printf("Baglanti kuruldu!\n");
    }
    else{
    printf("Baglanti kurulamadi!\n");
    return 1;
    }

    if (zedin_crypto_init() != ZEDIN_CRYPTO_OK){
        printf("Crypto baslatilamadi!\n");
        close(soket);
        return 1;
    }

    if (zedin_crypto_identity_generate(&client_identity) != ZEDIN_CRYPTO_OK){
        printf("Client identity olusturulamadi!\n");
        close(soket);
        return 1;
    }

    crypto_status = zedin_crypto_handshake_client_init(
        &client_ctx,
        ZEDIN_ZIP_PROTOCOL_VERSION_1,
        &client_identity
    );

    if (crypto_status != ZEDIN_CRYPTO_OK){
        printf("Client handshake baslatilamadi!\n");
        close(soket);
        return 1;
    }
        memcpy(
        handshake_payload,
        client_ctx.local_ephemeral_kp.public_key,
        ZEDIN_CRYPTO_PUBLICKEYBYTES
    );

    memcpy(
        handshake_payload + ZEDIN_CRYPTO_PUBLICKEYBYTES,
        client_ctx.local_identity.public_key,
        ZEDIN_CRYPTO_IDENTITY_PUBLICKEYBYTES
    );

    handshake_payload_length =
        ZEDIN_CRYPTO_PUBLICKEYBYTES +
        ZEDIN_CRYPTO_IDENTITY_PUBLICKEYBYTES;

    handshake_header.version = ZIP_SECURITY_VERSION;
    handshake_header.packet_type = ZIP_PACKET_CLIENT_HELLO;
    handshake_header.direction = ZIP_DIRECTION_CLIENT_TO_SERVER;
    handshake_header.sequence = 0;
    handshake_header.payload_length = (uint32_t)handshake_payload_length;

    security_status = zip_security_send_packet(
        soket,
        &handshake_header,
        handshake_payload
    );

    if (security_status != ZIP_SECURITY_OK){
        printf("CLIENT_HELLO gonderilemedi!\n");
        close(soket);
        return 1;
    }

        security_status = zip_security_recv_packet(
        soket,
        &handshake_header,
        handshake_payload,
        sizeof(handshake_payload),
        &handshake_payload_length
    );

    if (security_status != ZIP_SECURITY_OK){
        printf("SERVER_HELLO alinamadi!\n");
        close(soket);
        return 1;
    }

    if (handshake_header.packet_type != ZIP_PACKET_SERVER_HELLO ||
        handshake_header.direction != ZIP_DIRECTION_SERVER_TO_CLIENT ||
        handshake_header.sequence != 0 ||
        handshake_payload_length !=
            ZEDIN_CRYPTO_PUBLICKEYBYTES +
            ZEDIN_CRYPTO_IDENTITY_PUBLICKEYBYTES +
            ZEDIN_CRYPTO_SIGNATUREBYTES){
        printf("Gecersiz SERVER_HELLO!\n");
        close(soket);
        return 1;
    }

    memcpy(
        server_ephemeral_pk,
        handshake_payload,
        ZEDIN_CRYPTO_PUBLICKEYBYTES
    );

    memcpy(
        server_identity_pk,
        handshake_payload + ZEDIN_CRYPTO_PUBLICKEYBYTES,
        ZEDIN_CRYPTO_IDENTITY_PUBLICKEYBYTES
    );

    memcpy(
        server_signature,
        handshake_payload +
        ZEDIN_CRYPTO_PUBLICKEYBYTES +
        ZEDIN_CRYPTO_IDENTITY_PUBLICKEYBYTES,
        ZEDIN_CRYPTO_SIGNATUREBYTES
    );

    crypto_status = zedin_crypto_handshake_client_process_server_hello(
        &client_ctx,
        server_ephemeral_pk,
        server_identity_pk,
        server_signature
    );

    if (crypto_status != ZEDIN_CRYPTO_OK){
        printf("SERVER_HELLO dogrulanamadi!\n");
        close(soket);
        return 1;
    }

    printf("SERVER_HELLO dogrulandi!\n");
    printf("CLIENT_HELLO gonderildi!\n");
        crypto_status = zedin_crypto_handshake_client_finalize(
        &client_ctx,
        client_signature
    );

    if (crypto_status != ZEDIN_CRYPTO_OK){
        printf("Client handshake finalize basarisiz!\n");
        close(soket);
        return 1;
    }

    memcpy(
        handshake_payload,
        client_signature,
        ZEDIN_CRYPTO_SIGNATUREBYTES
    );

    handshake_payload_length = ZEDIN_CRYPTO_SIGNATUREBYTES;

    handshake_header.version = ZIP_SECURITY_VERSION;
    handshake_header.packet_type = ZIP_PACKET_CLIENT_FINISH;
    handshake_header.direction = ZIP_DIRECTION_CLIENT_TO_SERVER;
    handshake_header.sequence = 0;
    handshake_header.payload_length = (uint32_t)handshake_payload_length;

    security_status = zip_security_send_packet(
        soket,
        &handshake_header,
        handshake_payload
    );

    if (security_status != ZIP_SECURITY_OK){
        printf("CLIENT_FINISH gonderilemedi!\n");
        close(soket);
        return 1;
    }

    printf("ZIP handshake tamamlandi!\n");
    security_status = zip_security_send_encrypted_app_data(
    	   soket,
    	   &client_ctx,
    	   (const unsigned char
    *)mesaj,
           strlen(mesaj)
         );

         if (security_status != ZIP_SECURITY_OK){
         	printf("Sifreli mesaj gonderilemedi!\n");
         	close(soket);
         	return 1;
         }

         printf("Sifreli mesaj gonderildi!\n");

         size_t sifreli_cevap_uzunlugu = 0;

         security_status = zip_security_recv_encrypted_app_data(
         	soket,
         	&client_ctx,
         	(unsigned char *)cevap,
         	sizeof(cevap) - 1,
         	&sifreli_cevap_uzunlugu
         );
         if (security_status != ZIP_SECURITY_OK){
         	printf("Sifreli cevap alinamadi!\n");
         	close(soket);
         	return 1;
         }
         cevap[sifreli_cevap_uzunlugu] 
     = '\0';
  
         govde = strstr(cevap, "\n\n");
        if (govde != NULL){
        int header_uzunlugu = govde - cevap;
        memcpy(header, cevap, header_uzunlugu);
        header[header_uzunlugu] = '\0';
        printf("HEADER:\n%s\n", header);
        govde += 2;
        printf("Govde: %s", govde);
        if (sscanf(header, "%63s %63s", cevap_versiyon, durum) == 2){
            printf("Versiyon: %s\n", cevap_versiyon);
            printf("Durum: %s\n", durum);
            char *ct_konum = strstr(header, "CONTENT-TYPE:");
        if (ct_konum != NULL){
            printf("Content-Type bulundu!\n");
            ct_konum += strlen("CONTENT-TYPE:");
            printf("Icerik Turu: %s\n", ct_konum);
       }
       else{
            printf("Conten-Type bulunamadi!\n");
      }
     }
    }
    else{
        printf("Govde bulunamadi!\n");
     }
    char *cl_konum = strstr(header, "CONTENT-LENGTH:");
    if (cl_konum != NULL){
       printf("Content-Length bulundu!\n");
       cl_konum += strlen("CONTENT-LENGTH:");
       cevap_uzunlugu = atoi(cl_konum);
       printf("Icerik Uzunlugu: %d\n", cevap_uzunlugu);
       int gercek_govde_uzunlugu = strlen(govde);
       printf("Gercek Govde Uzunlugu: %d\n", gercek_govde_uzunlugu);
     if (cevap_uzunlugu == gercek_govde_uzunlugu) {
       printf("Govde uzunlugu dogrulandi!\n");
    }
    else {
    printf("Govde uzunlugu uyusmuyor!\n");
     }
    }
    else{
       printf("Content-Length bulunamadi!\n");
     }

    return 0;
}
