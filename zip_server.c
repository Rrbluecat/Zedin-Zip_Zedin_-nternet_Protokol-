#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "zip_security.h"
#include "güvenlik/zedin_crypto.h"

static void cevap_gonder(
    int soket,
    zedin_handshake_ctx_t *server_ctx,
    const char *cevap
)
{
    zip_security_status_t durum = zip_security_send_encrypted_app_data(
        soket,
        server_ctx,
        (const unsigned char *)cevap,
        strlen(cevap)
    );

    if (durum != ZIP_SECURITY_OK) {
        printf("Sifreli cevap gonderilemedi! Durum: %d\n", durum);
    }
}

int main(void){
    int kabul;
    socklen_t adres_uzunlugu;
    int soket;
    int sonuc;
    char mesaj[257];
    char cevap[256];
    char versiyon[64];
    char method[64];
    char yol[64];
    char *parca;
    int icerik_uzunlugu;
    zedin_identity_t server_identity;

    soket = socket(AF_INET, SOCK_STREAM, 0);
    if (soket != -1){
    printf("Soket Baglandi!\n");
    }
    else {
    printf("Socket baglanamadi!\n");
    return 1;
    }
    struct sockaddr_in adres;

    adres.sin_family = AF_INET;
    adres.sin_port = htons(8080);
    adres.sin_addr.s_addr = inet_addr("127.0.0.1");

    sonuc =  bind(soket, (struct sockaddr*)&adres, sizeof(adres));
    if (sonuc != -1) {
    printf("Bind basarili!\n");
    }
    else {
    printf("Bind basarisiz!\n");
    return 1;
    }
    sonuc = listen(soket, 5);
    if (sonuc == 0){
    printf("Dinleme basarali!\n");
    }
    else{
    printf("Dinleme basarisiz!\n");
    return 1;
    }
    if (zedin_crypto_init() != ZEDIN_CRYPTO_OK){
        printf("Crypto baslatilamadi!\n");
        close(soket);
        return 1;
    }

    if (zedin_crypto_identity_generate(&server_identity) != ZEDIN_CRYPTO_OK){
       printf("Server identity olusturulamadi!\n");
       close(soket);
       return 1;
    }

    printf("ZIP güvenlik katmani hazir!\n");
      while(1){
          zedin_handshake_ctx_t server_ctx;
    adres_uzunlugu = sizeof(adres);
    kabul = accept(soket,(struct sockaddr*)&adres, &adres_uzunlugu);
    if (kabul == -1){
    printf("Client kabul edilemedi!\n");
    continue;
    }
    else{
    printf("Client kabul edildi!\n");
    }
    unsigned char handshake_payload[128];
    size_t handshake_payload_length;
    zip_packet_header_t handshake_header;
    zip_security_status_t security_status;
    zedin_crypto_status_t crypto_status;
    unsigned char server_ephemeral_pk[ZEDIN_CRYPTO_PUBLICKEYBYTES];
    unsigned char server_identity_pk[ZEDIN_CRYPTO_IDENTITY_PUBLICKEYBYTES];
    unsigned char server_signature[ZEDIN_CRYPTO_SIGNATUREBYTES];
    crypto_status = zedin_crypto_handshake_server_init
    (
    	    &server_ctx,
    	    ZEDIN_ZIP_PROTOCOL_VERSION_1,
    	    &server_identity
 	);
    if (crypto_status != ZEDIN_CRYPTO_OK) {
    	printf("Server handshake baslatilamadi!\n");
    	close(kabul);
        continue;
    }
    security_status = zip_security_recv_packet(kabul,&handshake_header,handshake_payload,
    sizeof(handshake_payload),
    &handshake_payload_length
    );

    if (security_status != ZIP_SECURITY_OK) {
        printf("CLIENT_HELLO alinamadi!\n");
        close(kabul);
        continue;
    }
    if (handshake_header.packet_type != ZIP_PACKET_CLIENT_HELLO ||
        handshake_header.direction != ZIP_DIRECTION_CLIENT_TO_SERVER ||
        handshake_header.sequence != 0 ||
        handshake_payload_length != 64U) {
    	printf("Gecersiz CLIENT_HELLO!\n");
    	close(kabul);
    	continue;
    }
    memcpy(server_ctx.peer_ephemeral_pk,handshake_payload,ZEDIN_CRYPTO_PUBLICKEYBYTES
    );
    memcpy(
    server_ctx.peer_identity_pk,
    handshake_payload + 
    ZEDIN_CRYPTO_PUBLICKEYBYTES,

    ZEDIN_CRYPTO_IDENTITY_PUBLICKEYBYTES
    );
    crypto_status = zedin_crypto_handshake_server_process_client_hello(
    &server_ctx,
    server_ctx.peer_ephemeral_pk,
    server_ctx.peer_identity_pk,
    server_ephemeral_pk,
    server_identity_pk,
    server_signature
    );

    if (crypto_status != ZEDIN_CRYPTO_OK) {
        printf("CLIENT_HELLO handshake islemi basarisiz!\n");
        close(kabul);
        continue;
    }
        memcpy(
        handshake_payload,
        server_ephemeral_pk,
        ZEDIN_CRYPTO_PUBLICKEYBYTES
    );

    memcpy(
        handshake_payload + ZEDIN_CRYPTO_PUBLICKEYBYTES,
        server_identity_pk,
        ZEDIN_CRYPTO_IDENTITY_PUBLICKEYBYTES
    );

    memcpy(
        handshake_payload +
        ZEDIN_CRYPTO_PUBLICKEYBYTES +
        ZEDIN_CRYPTO_IDENTITY_PUBLICKEYBYTES,
        server_signature,
        ZEDIN_CRYPTO_SIGNATUREBYTES
    );

    handshake_payload_length =
        ZEDIN_CRYPTO_PUBLICKEYBYTES +
        ZEDIN_CRYPTO_IDENTITY_PUBLICKEYBYTES +
        ZEDIN_CRYPTO_SIGNATUREBYTES;

    handshake_header.version = ZIP_SECURITY_VERSION;
    handshake_header.packet_type = ZIP_PACKET_SERVER_HELLO;
    handshake_header.direction = ZIP_DIRECTION_SERVER_TO_CLIENT;
    handshake_header.sequence = 0;
    handshake_header.payload_length = (uint32_t)handshake_payload_length;

    security_status = zip_security_send_packet(
        kabul,
        &handshake_header,
        handshake_payload
    );

    if (security_status != ZIP_SECURITY_OK) {
        printf("SERVER_HELLO gonderilemedi!\n");
        close(kabul);
        continue;
    }

        printf("SERVER_HELLO gonderildi!\n");

    security_status = zip_security_recv_packet(
        kabul,
        &handshake_header,
        handshake_payload,
        sizeof(handshake_payload),
        &handshake_payload_length
    );

    if (security_status != ZIP_SECURITY_OK) {
        printf("CLIENT_FINISH alinamadi!\n");
        close(kabul);
        continue;
    }

    if (handshake_header.packet_type != ZIP_PACKET_CLIENT_FINISH ||
        handshake_header.direction != ZIP_DIRECTION_CLIENT_TO_SERVER ||
        handshake_header.sequence != 0 ||
        handshake_payload_length != ZEDIN_CRYPTO_SIGNATUREBYTES) {
        printf("Gecersiz CLIENT_FINISH!\n");
        close(kabul);
        continue;
    }

    crypto_status = zedin_crypto_handshake_server_finalize(
        &server_ctx,
        handshake_payload
    );

    if (crypto_status != ZEDIN_CRYPTO_OK) {
        printf("CLIENT_FINISH dogrulanamadi!\n");
        close(kabul);
        continue;
    }

        printf("ZIP handshake tamamlandi!\n");

    size_t mesaj_uzunlugu;

    security_status = zip_security_recv_encrypted_app_data(
        kabul,
        &server_ctx,
        (unsigned char *)mesaj,
        sizeof(mesaj) - 1,
        &mesaj_uzunlugu
    );

    if (security_status != ZIP_SECURITY_OK) {
        printf("Sifreli APP_DATA alinamadi!\n");
        close(kabul);
        continue;
    }

    mesaj[mesaj_uzunlugu] = '\0';

    printf("Mesaj alindi!\n");
    printf("Mesajiniz: %s", mesaj);
    parca = strtok(mesaj, "\n");
    if (parca == 0){
       printf("400\n Yazmak istediginiz sey bulunamadi!");
       char *icerik = "\nHata kodu: 400!\n Yazmak istediginiz sey bulunamadi!\n";
       icerik_uzunlugu = strlen(icerik);
       sprintf(cevap, "ZEDIN/1.0 400\n" "CONTENT-TYPE:text/plain\n" "CONTENT-LENGTH:%d\n" "\n" "%s", icerik_uzunlugu, icerik);
       cevap_gonder(kabul, &server_ctx, cevap);
       close(kabul);
       continue;
    }
    strcpy(versiyon, parca);
    parca = strtok(NULL, "\n");
    if (strcmp(versiyon, "ZEDIN/1.0") != 0){
       char *icerik = "\nHata kodu: 400!\n Yazmak istediginiz sey bulunamadi!\n";
       icerik_uzunlugu = strlen(icerik);
       sprintf(cevap, "ZEDIN/1.0 400\n" "CONTENT-TYPE:text/plain\n" "CONTENT-LENGTH:%d\n" "\n" "%s", icerik_uzunlugu, icerik);
       cevap_gonder(kabul, &server_ctx, cevap);
       close(kabul);
       continue;
    }
    else {
        printf("Yoluna devam edebilirsin yoldas");
    }
    if (parca == 0){
       printf("\nHata kodu: 400!\n Yazmak istediginiz sey bulunamadi!\n");
       char *icerik = "\nHata kodu: 400!\n Yazmak istediginiz sey bulunamadi!\n";
       icerik_uzunlugu = strlen(icerik);
       sprintf(cevap, "ZEDIN/1.0 400\n" "CONTENT-TYPE:text/plain\n" "CONTENT-LENGTH:%d\n" "\n" "%s", icerik_uzunlugu, icerik);
       cevap_gonder(kabul, &server_ctx, cevap);
       close(kabul);
       continue;
    }
    parca = strtok(parca, " ");
    if (parca == 0){
       printf("\nHata kodu: 400!\n Yazmak istediginiz sey bulunamadi!\n");
       char *icerik = "\nHata kodu: 400!\n Yazmak istediginiz sey bulunamadi!\n";
       icerik_uzunlugu = strlen(icerik);
       sprintf(cevap, "ZEDIN/1.0 400\n" "CONTENT-TYPE:text/plain\n" "CONTENT-LENGTH:%d\n" "\n" "%s", icerik_uzunlugu, icerik);
       cevap_gonder(kabul, &server_ctx, cevap);
       close(kabul);
       continue;
    }
    strcpy(method, parca);
    parca = strtok(NULL, " ");
    if (parca == 0){
       printf("\nHata kodu: 400!\n Yazmak istediginiz sey bulunamadi!\n");
       char *icerik = "\nHata kodu: 400!\n Yazmak istediginiz sey bulunamadi!\n";
       icerik_uzunlugu = strlen(icerik);
       sprintf(cevap, "ZEDIN/1.0 400\n" "CONTENT-TYPE:text/plain\n" "CONTENT-LENGTH:%d\n" "\n" "%s", icerik_uzunlugu, icerik);
       cevap_gonder(kabul, &server_ctx, cevap);
       close(kabul);
       continue;
    }
    strcpy(yol, parca);
    printf("Versiyon: %s\n", versiyon);
    printf("Method: %s\n", method);
    printf("Yol: %s\n", yol);
    if (strcmp(method, "GET") == 0){
       printf("Method basarili yola devam!\n");
    }
    else{
       printf("Method basarisiz! Hata kodu: 405\n");
       char *icerik = "405 yazmak istediginiz sey bulunamadi!\n";
       icerik_uzunlugu = strlen(icerik);
       sprintf(cevap, "ZEDIN/1.0 405\n" "CONTENT-TYPE:text/plain\n" "CONTENT-LENGTH:%d\n" "\n" "%s", icerik_uzunlugu, icerik);
       cevap_gonder(kabul, &server_ctx, cevap);
       close(kabul);
       continue;
    }
    if (strcmp(yol, "/anasayfa") == 0) {
        char *icerik = "Zedin'e hos geldiniz!\n";

        icerik_uzunlugu = strlen(icerik);
        sprintf(cevap, "ZEDIN/1.0 200\n" "CONTENT-TYPE:text/plain\n" "CONTENT-LENGTH:%d\n" "\n" "%s", icerik_uzunlugu, icerik);
        cevap_gonder(kabul, &server_ctx, cevap);
    }
    else if(strcmp(yol, "/hakkinda") == 0){
        char *icerik = "Zedin Internet Protokolu, Zedin ekosisteminin kullanisli bir internet aracidir!\n";
        icerik_uzunlugu = strlen(icerik);
        sprintf(cevap, "ZEDIN/1.0 200\n" "CONTENT-TYPE:text/plain\n" "CONTENT-LENGTH:%d\n" "\n" "%s", icerik_uzunlugu, icerik);
        cevap_gonder(kabul, &server_ctx, cevap);
    }
    else{
        char *icerik = "Zedin Internet Protokolu bu sayfayi bulamadi!\n";
        icerik_uzunlugu = strlen(icerik);
        sprintf(cevap, "ZEDIN/1.0 404\n" "CONTENT-TYPE:text/plain\n" "CONTENT-LENGTH:%d\n" "\n" "%s", icerik_uzunlugu, icerik);
        cevap_gonder(kabul, &server_ctx, cevap);
      }
      close(kabul);
    }
    return 0;
}
