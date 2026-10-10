# Zedin-Zip_Zedin_-nternet_Protokol-
Zedin ZIP

Zedin Internet Protocol (ZIP), C dilinde geliştirilen istemci-sunucu iletişim protokolü prototipidir. Proje, Zedin ekosisteminin ağ iletişimi altyapısını oluşturmayı amaçlar.

«Durum: Erken geliştirme aşamasında olan çalışan prototip. Üretim ortamında kullanıma hazır değildir.»

Özellikler

- C99: C dilinde geliştirilen istemci ve sunucu.
- Paket çerçeveleme: Sabit boyutlu başlık ve doğrulanan paket alanları.
- Anahtar anlaşması: İstemci ve sunucu arasında oturum anahtarlarının oluşturulması.
- Kimlik ve imza: Ed25519 tabanlı imza işlemleri.
- Şifreli iletişim: XChaCha20-Poly1305 tabanlı doğrulanmış şifreleme.
- Replay koruması: Paket sıra numaralarının kontrolü.
- Testler: Paket çerçeveleme ve şifreli veri iletişimi için testler.

Teknolojiler

- C99
- libsodium
- POSIX soketleri
- Termux / Linux

Gereksinimler

- C derleyicisi (GCC veya uyumlu bir derleyici)
- libsodium geliştirme dosyaları
- POSIX soketlerini destekleyen bir ortam

Termux üzerinde gerekli paketler:

pkg install clang libsodium

Derleme

Proje dizininde şu komutları kullan:

Sunucu:

gcc -Wall -Wextra -Wpedantic -std=c99 \
-I. -Igüvenlik \
zip_server.c zip_security.c güvenlik/zedin_crypto.c \
-lsodium -o zip_server

İstemci:

gcc -Wall -Wextra -Wpedantic -std=c99 \
-I. -Igüvenlik \
zip_client.c zip_security.c güvenlik/zedin_crypto.c \
-lsodium -o zip_client

Çalıştırma

İlk terminalde sunucuyu başlat:

./zip_server

İkinci terminalde istemciyi başlat:

./zip_client

Mevcut prototipin sunucu ve istemci yapılandırması yerel test içindir. Kodda kullanılan adres ve bağlantı ayarları değiştirilmeden farklı cihazlar arasında iletişim kurulacağı varsayılmamalıdır.

Mevcut Durum

Mevcut prototipte:

- İstemci-sunucu bağlantısı kurulabilir.
- El sıkışma aşaması tamamlanabilir.
- Şifreli uygulama verisi gönderilebilir.
- Sunucu yanıtı istemci tarafından alınabilir.
- Paket çerçeveleme ve belirli güvenlik davranışları test edilebilir.

Protokolün tasarımı ve uygulaması geliştirme aşamasındadır.

Güvenlik Sınırlamaları

Bu sürüm deneysel bir prototiptir.

Sunucunun kimlik açık anahtarının bağımsız ve güvenilir bir kaynaktan doğrulanması henüz tamamlanmamıştır. Bu nedenle imza doğrulaması tek başına bağlanılan sunucunun gerçekten beklenen sunucu olduğunu kanıtlamaz.

Protokolü hassas veriler veya üretim ortamındaki iletişim için kullanmayın.

Yol Haritası

- [x] Temel istemci-sunucu prototipi
- [x] Paket çerçeveleme
- [x] Şifreli uygulama verisi iletişimi
- [x] Temel güvenlik testleri
- [ ] Kimlik doğrulama ve güven modeli iyileştirmeleri
- [ ] Protokol dokümantasyonunun genişletilmesi
- [ ] Zedin ekosisteminin diğer bileşenleriyle entegrasyon

Proje

Zedin, Türkçe odaklı ve kullanıcı kontrolünü önemseyen bir yazılım ekosistemi oluşturma hedefiyle geliştirilmektedir.

ZIP, bu ekosistemin iletişim altyapısına yönelik deneysel bir bileşendir.

Lisans

Lisans henüz belirlenmemiştir. Lisans seçimi yapılana kadar projeye ilişkin kullanım ve yeniden dağıtım koşullarını ayrıca değerlendirin.
