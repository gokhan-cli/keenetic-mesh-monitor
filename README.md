# Keenetic Mesh Monitor

Keenetic controller'ın RCI API'sinden mesh bağlantısı (backhaul: hız, sinyal, MCS, kanal genişliği, akış), node sistem durumu ve Wi-Fi istemcilerini toplayıp Grafana'da gösterir.

```
Keenetic controller (RCI) → keenetic-exporter → Prometheus (90 gün) → Grafana :3000
```

## 1. Router'da izleme kullanıcısı

Kullanıcılar ve erişim → Kullanıcı oluştur:
- Ad: `monitor`, güçlü şifre
- Yalnızca **Web arayüzü** erişimi
- **"Sistem ayarlarının kaydedilmesini engelle"** açık kalsın (salt-okuma için)

## 2. Proxmox LXC

Debian 12 LXC, 1 vCPU / 1 GB RAM / 8 GB disk yeterli. Docker için LXC seçeneklerinde `nesting=1,keyctl=1` açık olmalı.

Docker resmi deposundan kurulum:

```bash
apt update && apt install -y ca-certificates curl
install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/debian $(. /etc/os-release && echo $VERSION_CODENAME) stable" > /etc/apt/sources.list.d/docker.list
apt update && apt install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
```

## 3. Başlatma

```bash
cd keenetic-mesh-monitor
cp .env.example .env && nano .env      # şifreleri girin
docker compose up -d --build
docker logs keenetic-exporter          # "RCI oturumu açıldı" görülmeli
```

`.env` değiştiğinde `restart` yetmez (env dosyası yeniden okunmaz), container'ı yeniden oluşturun:

```bash
docker compose up -d --force-recreate keenetic-exporter
```

Grafana: `http://<lxc-ip>:3000` → kullanıcı `admin`, şifre `.env` içindeki `GF_ADMIN_PASSWORD`.
Dashboard'lar **Keenetic** klasöründe otomatik gelir; üstteki düğmelerle seçili zaman aralığı korunarak geçilir:

| Dashboard | İçerik |
|---|---|
| Genel bakış | Mesh durumu, özet (saldıran IP, yönetici girişi, güncelleme, durmuş servis; tıklayınca ilgili dashboard açılır), internet ve VPN, cihaz ve uygulama bazında trafik |
| Wi-Fi ve mesh | Mesh bağlantısı, Wi-Fi istemcileri, mesh dolaşımı, radyolar, çevredeki Wi-Fi ağları |
| Güvenlik | Giriş koruması, saldıran IP'ler, DoS koruması, yönetici girişleri |
| Sistem ve yazılım | Yazılım ve güncellemeler, CPU / bellek / açık kalma süresi, Ethernet portları, servisler |

### Yalnız exporter (kendi Prometheus / Grafana'nız varsa)

```bash
cp .env.example .env && nano .env      # KEENETIC_* yeterli; GF_ADMIN_PASSWORD ve TELEGRAM_* kullanılmaz
docker compose -f docker-compose.exporter.yml up -d --build
curl -s localhost:9877/metrics | grep keenetic_up    # 1 olmalı
```

Exporter host ağında çalışır, metrikler `:9877`'de. Prometheus'a ekleyin; toplama birkaç saniye sürebildiği için `scrape_timeout` varsayılan 10 sn'den uzun olmalı:

```yaml
scrape_configs:
  - job_name: keenetic
    scrape_interval: 30s
    scrape_timeout: 20s
    static_configs:
      - targets: ["<exporter-ip>:9877"]
```

- **Dashboard'lar:** Grafana → Dashboards → New → Import ile `grafana/dashboards/` altındaki 4 JSON dosyasını (`keenetic-mesh`, `-wifi`, `-security`, `-system`) tek tek içe aktarın; aralarındaki düğmeler `keenetic` etiketiyle bulunur. Paneller Prometheus veri kaynağını `uid: prometheus` ile arar; sizinkinin uid'i farklıysa ya veri kaynağını bu uid ile oluşturun ya da dosyalarda `"uid": "prometheus"` geçen yerleri kendi uid'inizle değiştirin.
- **Uyarılar (isteğe bağlı):** `grafana/provisioning/alerting/rules.yml` Grafana provisioning dosyasıdır; kendi Grafana'nızın `provisioning/alerting/` klasörüne kopyalayın (aynı `uid: prometheus` koşulu geçerli). Telegram için `telegram.yml.example`'ı da ekleyin (bkz. "Telegram uyarıları").

## Metrikler

| Metrik | Açıklama |
|---|---|
| `keenetic_mesh_backhaul_txrate_mbps` | Mesh bağlantısı fiziksel hız |
| `keenetic_mesh_backhaul_rssi_dbm` | Mesh bağlantısı sinyal |
| `keenetic_mesh_backhaul_mcs` / `_spatial_streams` / `_channel_width_mhz` | Bağlantı kalitesi |
| `keenetic_mesh_backhaul_uptime_seconds` | Sıfırlanma = backhaul koptu |
| `keenetic_mesh_backhaul_wireless` | 1 = Wi-Fi, 0 = kablolu backhaul |
| `keenetic_mesh_member_cpu_load`, `_memory_*`, `_associations` | Node sistemi |
| `keenetic_mesh_port_link_up` / `_speed_mbps` | Node Ethernet portları |
| `keenetic_wifi_client_*` | Wi-Fi istemcileri; `device` = bağlı olduğu cihaz (controller ya da mesh üyesi) |
| `keenetic_wifi_neighbor_rssi_dbm` / `_quality` | Çevredeki Wi-Fi ağları (site survey; `scanner` = tarayan cihaz, SSID, BSSID, kanal, genişlik, şifreleme) |
| `keenetic_wifi_neighbor_channel` | Çevredeki ağın kanalı (değer olarak); komşuların kanal değiştirmesi grafikte izlenir |
| `keenetic_radio_channel` / `_channel_width_mhz` / `_channel_width_configured_mhz` | Cihaz başına radyo durumu; gerçek genişlik ayarlanandan düşükse (ör. DFS/radar sonrası 160→80) dashboard'da "Düşük" görünür. `keenetic_radio_temperature_celsius`: radyo sıcaklığı |
| `keenetic_firmware_info` / `_update_available` / `_channel_newer` | Kurulu yazılım, takip edilen kanal (LTS/Kararlı/Önizleme/Geliştirici) ve kanallardaki son sürümler |
| `keenetic_lockout_*` | Giriş koruması (Sistem Güvenliği → Kimlik Doğrulama Güvenliği), cihaz ve protokol (http/telnet/ssh) başına: açık mı, şu an engellenen / takip edilen / son 1 saatte / toplam engellenen IP sayısı, eşik ve süreler |
| `keenetic_conntrack_*` | Bağlantı taşması (DoS) koruması: açık mı, devrede mi, eşik (%), bağlantı sayıları (`scope` = public/private) ve tablo kapasitesi |
| `keenetic_internet_up` / `keenetic_internet_check` | Router'ın internet kontrolü (ağ geçidi, DNS, captive) |
| `keenetic_wan_*` | İnternete çıkan arayüz (PPPoE vb.): bağlı mı, oturum süresi, alınan/gönderilen bayt, hata ve düşen paket sayaçları |
| `keenetic_pingcheck_pass` / `_failures` | Router'ın ping kontrolü profilleri |
| `keenetic_vpn_enabled` / `_up` / `_uptime_seconds` | VPN tünelleri (OpenVPN, WireGuard, IPsec, L2TP, PPTP, SSTP…): ayarda açık mı, bağlı mı, bağlı kalma süresi |
| `keenetic_system_*` | Cihaz başına (controller ve node'lar) CPU yükü, bellek ve açık kalma süresi |
| `keenetic_client_receive_bytes_total` / `_transmit_bytes_total` | Cihaz başına router üzerinden indirilen / yüklenen bayt (internet ve VPN; yerel ağ içi trafik dahil değil). Router açıldığından beri birikir; yalnız router'da kayıtlı cihazlar için tutulur |
| `keenetic_application_receive_bytes_total` / `_transmit_bytes_total` | Uygulama başına indirilen / yüklenen bayt, tüm cihazlar (`app`, `group` etiketleri; kayıtsız cihazlar dahil). Exporter açıldıktan sonrası |
| `keenetic_mesh_roam_events_total` | Mesh dolaşım günlüğünden istemci başına olaylar (`event`: roam = erişim noktası/bant değiştirdi, join = bağlandı, leave = ayrıldı), nereden/nereye (cihaz ve bant) ve yöntem (`ft` = 802.11r, `pmk`). Exporter açıldıktan sonraki olaylar sayılır |
| `keenetic_mesh_roam_event` | Son 100 olay (değer = olay zamanı); dashboard'daki "Son olaylar" tablosu |
| `keenetic_*_uptime_text` | Süreler Türkçe metin olarak (`text` etiketi: "1 gün 17 saat", "14 saat 25 dk"); Grafana'nın süre birimleri yalnız İngilizce olduğu için dashboard bunları gösterir. Değer her zaman 1; hesap için `_uptime_seconds` kullanın |
| `keenetic_security_ip_*` / `keenetic_security_ban_until_seconds` | Router günlüğünden saldıran IP'ler (cihaz ve IP başına): son görülme, engellenme ve kötü niyetli istek sayısı, son istenen yollar, engelin bitiş zamanı. Son 24 saat (`LOG_RETENTION`) |
| `keenetic_service_up` / `_enabled` / `_pid` / `_memory_bytes` | Cihaz başına KeeneticOS servisleri (`kind=servis`) ve servis olmayan arka plan süreçleri (`kind=süreç`, ör. Entware'den tailscaled): çalışıyor mu, ayarlarda açık mı, süreç numarası, bellek |
| `keenetic_application_active` | Router'ın son 3 dakikada trafik saydığı uygulama sayısı; trafik varken 0 kalıyorsa Trafik İzleme sayacı durmuştur |
| `keenetic_admin_login_seconds` | Router günlüğünden yönetici girişleri (zaman; kullanıcı, IP, arayüz, tarayıcı, `scope` = internet / yerel / bulut). Exporter'ın kendi kullanıcısı ve router'ın iç oturumları hariç; exporter'da 1 saat tutulur |
| `keenetic_log_lines_total` / `keenetic_log_read_seconds` | Cihaz başına router günlüğünden okunan satır ve son okuma zamanı |

## Router günlüğü

Exporter her cihazın (controller ve node'lar) günlüğünü RCI'dan (`show log`, `monitor` kullanıcısı yeterli) 30 sn'de bir okur;
router'da syslog ya da başka bir ayar gerekmez. Yalnız yeni satırlar işlenir ve sadece şunlar ayıklanır:

- `Netfilter::Lockout::Manager: "Http": ban remote host <IP> for 15 minutes.` → engellenen IP
- `Core::Scgi::Handler::GetIndex: malicious request: /wp-login.php [<IP>]` → kötü niyetli istek ve istenen yol
- `Core::Security::Authority: started a user session [...]` → yönetici girişi

**Güvenlik** dashboard'undaki **Saldıran IP'ler** ve **Yönetici girişleri** tabloları, Telegram'da IP'li "IP engellendi" ve "Yönetici girişi" uyarıları bunlardan gelir.
Router son yaklaşık 4000 satırı (bir gün kadar) tutar; exporter açılırken bunları da okuduğu için yeniden başlayınca liste kaybolmaz.
Kapatmak için `LOG_INTERVAL=0`. Önceki sürümlerde kullanılan uzak syslog ayarı artık gerekmez, router'dan kaldırılabilir.

## Telegram uyarıları

Uyarılar Grafana'nın kendi uyarı sistemiyle gönderilir ve dosyalardan kurulur (`grafana/provisioning/alerting/`):
`telegram.yml` bağlantıyı ve mesaj biçimini, `rules.yml` kuralları tanımlar.

1. Telegram'da @BotFather → `/newbot` ile bot oluşturun ve verdiği token'ı `.env` içine `TELEGRAM_BOT_TOKEN=...` olarak yazın.
2. Bota herhangi bir mesaj gönderin (bot, kendisine yazmamış birine mesaj atamaz).
3. Örnek dosyayı kopyalayın, sohbet numaranızı bulun ve `chatid: "..."` alanına tırnak içinde yazın:
   ```bash
   cp grafana/provisioning/alerting/telegram.yml.example grafana/provisioning/alerting/telegram.yml
   curl -s "https://api.telegram.org/bot<TOKEN>/getUpdates"   # result[].message.chat.id
   ```
   Numara `.env`'den alınamıyor: Grafana 12.1 ortam değişkeninden gelen sayısal değeri sayıya çeviriyor, `chatid` alanı ise metin bekliyor ("cannot unmarshal number ... chatid" hatası).
4. `docker compose up -d --force-recreate grafana`

Token boşsa ya da ayarlar hatalıysa Grafana açılmaz (`docker logs grafana` içinde "Failed to provision alerting"). `telegram.yml` yoksa kurallar yine çalışır ama uyarılar yalnız Grafana'da (**Alerting**) görünür, mesaj gönderilmez.

| Uyarı | Koşul |
|---|---|
| 🔴 Router'a erişilemiyor | Exporter 5 dk boyunca controller'dan veri alamazsa (`keenetic_up`) ya da exporter'ın kendisi çalışmıyorsa |
| 🔴 Mesh üyesi kayboldu | Son 1 saatte görülen bir üye listeden çıkarsa ya da internete erişemezse (3 dk) |
| 🟠 Mesh bağlantısı yeniden kuruldu | `keenetic_mesh_backhaul_uptime_seconds` son 10 dk'da sıfırlandıysa |
| 🟠 Kanal genişliği düştü | Bir radyo 15 dk boyunca ayarlanandan dar çalışırsa. Süre, yeniden başlatma sonrası ~10 dk'lık DFS dinlemesi uyarı üretmesin diye 15 dk seçildi |
| 🔴 / 🟠 Yönetici girişi | Router günlüğünde "started a user session" satırı gelince, tek mesaj: internetten giriş 🔴, ev ağından ya da VPN'den giriş 🟠. Mobil uygulama ve Keenetic bulutu oturumları (gerçek IP görünmez, çok sık) uyarı üretmez |
| 🔴 IP engellendi | Router günlüğünde "ban remote host" satırı gelince: cihaz, IP, protokol, son istenen yollar ve AbuseIPDB bağlantısı. Engel bitince "Düzeldi" gelir |
| 🔴 Giriş denemesi engellendi | Router bir IP'yi engellediğinde ama günlükten IP bilgisi okunamadıysa (yedek; IP içermez) |
| 🔴 DoS koruması devrede | Bağlantı taşması koruması devreye girdiğinde |
| 🔴 İnternet bağlantısı yok | Router 2 dk boyunca internete erişemezse. Kesinti sırasında gönderilemez, bağlantı gelince iletilir |
| 🟠 Ping kontrolü başarısız, hat açık | PPPoE bağlı ve ağ geçidi yanıt verirken ping kontrolü 3 dk başarısızsa. Router bu durumda IPv4 rotasını kapatıp açar (paket kaybı, VPN kopmaları); genelde kontrol hedefi erişilemiyordur (Otomatik modda captive.keenetic.net) |
| 🟠 İnternet bağlantısı yeniden kuruldu | WAN (PPPoE) oturum süresi son 10 dk'da sıfırlandıysa |
| 🟠 Yeniden başladı | Bir cihazın açık kalma süresi son 10 dk'da sıfırlandıysa |
| 🔴 VPN bağlantısı koptu | Ayarda açık bir tünel 3 dk boyunca bağlı değilse (kapalı tüneller uyarı üretmez) |
| 🟠 Radyo ısınıyor | Bir Wi-Fi radyosu 15 dk boyunca 80 °C üzerindeyse (normalde 50–65 °C) |
| 🏠 Eve geldi | Önceki 4 saatte hiç görülmeyen bir Wi-Fi cihazı ağa bağlanınca, tek mesaj ("Düzeldi" gelmez). Kablolu cihazlar dahil değil; exporter ya da router o 4 saatte çoğunlukla kapalıysa uyarı üretmez |
| 🔴 Servis durdu | Son 1 saatte çalışan, ayarlarda açık bir servis (arayüzden kapattıklarınız hariç) 3 dk durursa ya da servis olmayan bir süreç (ör. tailscaled) kaybolursa. VPN, PPPoE (kendi uyarıları var) ve isteğe bağlı çalışanlar (iperf3, LLDP) hariç |
| 🟠 Servis yeniden başladı | Bir servisin süreç numarası son 10 dk'da değiştiyse, tek mesaj. Mesh'teki herhangi bir cihaz son 15 dk'da yeniden başladıysa üretilmez (controller açılınca mesh üyeleri de servislerini yeniden başlatır) |
| 🟠 Trafik İzleme durdu | İnternetten ortalama 100 kb/s üzeri indirilirken router 30 dk boyunca hiçbir uygulama trafiği saymazsa (servis çalışıyor görünse de sayaç takılmış olabilir) |
| 🔵 Yazılım güncellemesi var | Takip edilen kanalda yeni sürüm çıkarsa (haftada bir hatırlatılır) |

Sorun düzelince "✅ Düzeldi" mesajı gelir (`notify: once` etiketli olay uyarıları hariç; bunlar `telegram.yml`'deki "Telegram (tek sefer)" yoluyla tek mesaj olarak gider. Eski bir `telegram.yml` kullanıyorsanız bu bölümü örnek dosyadan ekleyin). Bir uyarı en fazla günde bir kez tekrarlanır. Kurallar Grafana'da **Alerting → Alert rules** altında görünür; provisioning ile geldikleri için arayüzden değiştirilemez, değişiklik `rules.yml` üzerinden yapılır.

## Giriş yöntemi (ndw4 / ndw2)

KeeneticOS 5.x `x-ndw4-interactive` giriş yöntemini kullanır (Argon2id + HMAC-SHA3-512, 3 aşamalı). Bu firmware'de oluşturulan kullanıcılar eski `x-ndw2` (MD5/SHA256) yöntemiyle **giremez**; şifre doğru olsa da 401 alınır. Exporter router ndw4 sunuyorsa onu kullanır, sunmuyorsa ya da ndw4 başarısız olursa ndw2'ye düşer. Başarılı girişte log'da `RCI oturumu açıldı (ndw4)` görülür.

## Sorun giderme

- **Dashboard boş / `keenetic_up` = 0:** `docker logs keenetic-exporter` ile log'a bakın.
- **`auth başarısız: 401`:** Önce tarayıcıdan aynı kullanıcıyla giriş yapmayı deneyin. Tarayıcıdan girilebiliyorsa sorun giriş yönteminde olabilir; firmware güncellemesinden sonra yöntem değişmiş olabilir. Web arayüzünün `main-*.js` dosyasında `authenticateWithNdw4` / `phase1Crypto` kısmını exporter'daki `_auth_ndw4` ile karşılaştırın.
- **Router log'unda `terminated a user session [monitor#...]`:** Exporter her cihaza tek oturumla bağlanır ve bu oturum sürekli kullanıldığı için kapanmaz. Bu mesaj sık sık görülüyorsa (ör. 5 dk'da bir) oturumlar boşta kalıp kapanıyor demektir; `docker logs keenetic-exporter | grep 'oturumu açıldı'` ile giriş sıklığına bakın.
- **`önceki giriş başarısızdı, N sn sonra tekrar denenecek`:** Hatalı girişten sonra exporter, IP kilitlenmesin diye 15 dk bekler (`KEENETIC_AUTH_BACKOFF`). Bekleme süresini sıfırlamak için container'ı yeniden oluşturun.

## Notlar

- `txrate` PHY hızıdır (link rate); gerçek aktarım genelde bunun %60–70'i kadardır.
- İstemci listesi controller'dan ve her mesh üyesinden arka planda 30 sn'de bir okunur (`CLIENTS_INTERVAL`); 90 sn'den eski veriler gösterilmez.
- Grafana dışında portlar dışarı açılmaz. Gerekirse 3000'i yalnızca yönetim ağına açın.
- Toplama aralığı 30 sn (`prometheus/prometheus.yml`).
- Çevredeki ağ taraması bant başına birkaç saniye sürdüğü için her toplamada yapılmaz; varsayılan 5 dk'da bir (`SITE_SURVEY_INTERVAL`). Kapatmak için `SITE_SURVEY_INTERFACES=` boş bırakılır.
- Tarama ana router'dan ve her mesh üyesinden (IP'leri `show mws member`'dan otomatik alınır) ayrı ayrı yapılır; her cihaz kendi konumundaki ağları görür. Node'lara da aynı `monitor` kullanıcısıyla girilir.
- Radyo durumu (kanal, gerçek/ayarlanan genişlik, sıcaklık) her cihazdan arka planda 1 dk'da bir okunur (`RADIO_INTERVAL`). Mesh bağlantısı (backhaul) için ayrı genişlik ayarı yoktur; controller'ın 5 GHz radyosu hangi genişlikte çalışıyorsa mesh bağlantısı da onu kullanır.
- Yazılım güncellemeleri her cihazda saatte bir kontrol edilir (`FIRMWARE_INTERVAL`, 0 = kapalı). Router her kontrolde Keenetic güncelleme sunucusuna bağlanır. Exporter yalnızca okur; güncelleme kurmaz. Kanal API'de `lts-*`, `stable`, `preview`, `draft` (= Geliştirici) olarak geçer.
- Sistem Güvenliği sayaçları her cihazdan 1 dk'da bir okunur (`SECURITY_INTERVAL`, 0 = kapalı). Cihazda bulunmayan protokoller (ör. node'da SSH) atlanır. Exporter yalnızca okur; koruma ayarlarını değiştirmez.
- Mesh dolaşım günlüğü (`show mws log`, controller son ~1000 olayı tutar) dakikada bir okunur (`ROAM_INTERVAL`, 0 = kapalı). Bu komut GET'te 404 verir; web arayüzü gibi POST ile okunur, yine yalnızca okumadır.
- Uygulama bazında trafik dakikada bir okunur (`APP_INTERVAL`, en fazla 150, 0 = kapalı). Kaynak web arayüzündeki Trafik İzleme ile aynıdır: `show ntce summary` son 3 dakikada trafiği olan uygulamaları, `show ntce chart` her biri için 3 sn'lik dilimlerde kesin baytı verir; exporter yeni dilimleri sayaca ekler. Router bu veriyi uygulama düzeyinde tutar, cihaz × uygulama kırılımı yoktur. Bu komutlar da GET'te 404 verir, POST ile okunur.
- İnternet, WAN ve VPN durumu her toplamada controller'dan okunur. Cihaz başına CPU / bellek / açık kalma süresi 30 sn'de bir okunur (`SYSTEM_INTERVAL`, 0 = kapalı).
- `monitor` kullanıcısı salt okunur olsa da router'ın tüm ayarlarını (`show running-config`: Wi-Fi şifreleri, VPN anahtarları) okuyabilir. Exporter bunları okumaz, ama `.env`'deki şifreyi yönetici şifresi gibi saklayın.
