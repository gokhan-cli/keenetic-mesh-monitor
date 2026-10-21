# Keenetic Mesh Monitor

Keenetic controller'ın RCI API'sinden mesh backhaul (hız, sinyal, MCS, kanal genişliği, akış), extender sistem durumu ve Wi-Fi istemcilerini toplayıp Grafana'da gösterir.

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
Dashboard **Keenetic → Keenetic Mesh** altında otomatik gelir.

## Metrikler

| Metrik | Açıklama |
|---|---|
| `keenetic_mesh_backhaul_txrate_mbps` | Backhaul fiziksel hız |
| `keenetic_mesh_backhaul_rssi_dbm` | Backhaul sinyal |
| `keenetic_mesh_backhaul_mcs` / `_spatial_streams` / `_channel_width_mhz` | Bağlantı kalitesi |
| `keenetic_mesh_backhaul_uptime_seconds` | Sıfırlanma = backhaul koptu |
| `keenetic_mesh_backhaul_wireless` | 1 = Wi-Fi, 0 = kablolu backhaul |
| `keenetic_mesh_member_cpu_load`, `_memory_*`, `_associations` | Extender sistem |
| `keenetic_mesh_port_link_up` / `_speed_mbps` | Extender Ethernet portları |
| `keenetic_wifi_client_*` | Wi-Fi istemcileri; `device` = bağlı olduğu cihaz (controller ya da mesh üyesi) |
| `keenetic_wifi_neighbor_rssi_dbm` / `_quality` | Çevredeki Wi-Fi ağları (site survey; `scanner` = tarayan cihaz, SSID, BSSID, kanal, genişlik, şifreleme) |
| `keenetic_wifi_neighbor_channel` | Çevredeki ağın kanalı (değer olarak); komşuların kanal değiştirmesi grafikte izlenir |
| `keenetic_radio_channel` / `_channel_width_mhz` / `_channel_width_configured_mhz` | Cihaz başına radyo durumu; gerçek genişlik ayarlanandan düşükse (ör. DFS/radar sonrası 160→80) dashboard'da "Düşük" görünür |
| `keenetic_firmware_info` / `_update_available` / `_channel_newer` | Kurulu yazılım, takip edilen kanal (LTS/Kararlı/Önizleme/Geliştirici) ve kanallardaki son sürümler |
| `keenetic_lockout_*` | Giriş koruması (Sistem Güvenliği → Kimlik Doğrulama Güvenliği), cihaz ve protokol (http/telnet/ssh) başına: açık mı, şu an engellenen / takip edilen / son 1 saatte / toplam engellenen IP sayısı, eşik ve süreler |
| `keenetic_conntrack_*` | Bağlantı taşması (DoS) koruması: açık mı, devrede mi, eşik (%), bağlantı sayıları (`scope` = public/private) ve tablo kapasitesi |
| `keenetic_internet_up` / `keenetic_internet_check` | Router'ın internet kontrolü (ağ geçidi, DNS, captive) |
| `keenetic_wan_*` | İnternete çıkan arayüz (PPPoE vb.): bağlı mı, oturum süresi, alınan/gönderilen bayt, hata ve düşen paket sayaçları |
| `keenetic_pingcheck_pass` / `_failures` | Router'ın ping kontrolü profilleri |
| `keenetic_vpn_enabled` / `_up` / `_uptime_seconds` | VPN tünelleri (OpenVPN, WireGuard, IPsec, L2TP, PPTP, SSTP…): ayarda açık mı, bağlı mı, bağlı kalma süresi |
| `keenetic_system_*` | Cihaz başına (controller ve extender'lar) CPU yükü, bellek ve açık kalma süresi |
| `keenetic_mesh_roam_events_total` | Mesh dolaşım günlüğünden istemci başına olaylar (`event`: roam = erişim noktası/bant değiştirdi, join = bağlandı, leave = ayrıldı), nereden/nereye (cihaz ve bant) ve yöntem (`ft` = 802.11r, `pmk`). Exporter açıldıktan sonraki olaylar sayılır |
| `keenetic_mesh_roam_event` | Son 100 olay (değer = olay zamanı); dashboard'daki "Son olaylar" tablosu |
| `keenetic_*_uptime_text` | Süreler Türkçe metin olarak (`text` etiketi: "1 gün 17 saat", "14 saat 25 dk"); Grafana'nın süre birimleri yalnız İngilizce olduğu için dashboard bunları gösterir. Değer her zaman 1; hesap için `_uptime_seconds` kullanın |
| `keenetic_security_ip_*` / `keenetic_security_ban_until_seconds` | Router syslog'undan saldıran IP'ler (cihaz ve IP başına): son görülme, engellenme ve kötü niyetli istek sayısı, son istenen yollar, engelin bitiş zamanı. Son 24 saat (`SYSLOG_RETENTION`) |
| `keenetic_syslog_messages_total` / `_last_message_seconds` | Cihaz başına alınan syslog satırı; sıfırsa router syslog göndermiyor |

## Router günlüğü (syslog)

RCI'da engellenen IP'lerin adresi yok, `monitor` kullanıcısı da günlüğü okuyamıyor. Bu yüzden router'lar günlüklerini exporter'a gönderir:
her cihazda (controller ve extender'lar) **Diagnostik → Sistem günlüğü → uzak sunucu** = bu makinenin IP'si (UDP 514).
Exporter yalnız controller'dan ve mesh üyelerinden gelen satırları kabul eder ve sadece şunları ayıklar:

- `Netfilter::Lockout::Manager: "Http": ban remote host <IP> for 15 minutes.` → engellenen IP
- `Core::Scgi::Handler::GetIndex: malicious request: /wp-login.php [<IP>]` → kötü niyetli istek ve istenen yol

Dashboard'da **Sistem güvenliği → Saldıran IP'ler** tablosu ve Telegram'da IP'li "IP engellendi" uyarısı bunlardan gelir. Liste bellekte tutulur, exporter yeniden başlayınca sıfırlanır. Kapatmak için `SYSLOG_PORT=0`.

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
| 🟠 Backhaul yeniden bağlandı | `keenetic_mesh_backhaul_uptime_seconds` son 10 dk'da sıfırlandıysa |
| 🟠 Kanal genişliği düştü | Bir radyo 15 dk boyunca ayarlanandan dar çalışırsa. Süre, yeniden başlatma sonrası ~10 dk'lık DFS dinlemesi uyarı üretmesin diye 15 dk seçildi |
| 🔴 IP engellendi | Syslog'da "ban remote host" satırı gelince: cihaz, IP, protokol, son istenen yollar ve AbuseIPDB bağlantısı. Engel bitince "Düzeldi" gelir |
| 🔴 Giriş denemesi engellendi | Router bir IP'yi engellediğinde ama syslog'dan IP bilgisi gelmediyse (yedek; IP içermez) |
| 🔴 DoS koruması devrede | Bağlantı taşması koruması devreye girdiğinde |
| 🔴 İnternet bağlantısı yok | Router 2 dk boyunca internete erişemezse. Kesinti sırasında gönderilemez, bağlantı gelince iletilir |
| 🟠 İnternet bağlantısı yeniden kuruldu | WAN (PPPoE) oturum süresi son 10 dk'da sıfırlandıysa |
| 🟠 Yeniden başladı | Bir cihazın açık kalma süresi son 10 dk'da sıfırlandıysa |
| 🔴 VPN bağlantısı koptu | Ayarda açık bir tünel 3 dk boyunca bağlı değilse (kapalı tüneller uyarı üretmez) |
| 🔵 Yazılım güncellemesi var | Takip edilen kanalda yeni sürüm çıkarsa (haftada bir hatırlatılır) |

Sorun düzelince "✅ Düzeldi" mesajı gelir. Bir uyarı en fazla günde bir kez tekrarlanır. Kurallar Grafana'da **Alerting → Alert rules** altında görünür; provisioning ile geldikleri için arayüzden değiştirilemez, değişiklik `rules.yml` üzerinden yapılır.

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
- Tarama ana router'dan ve her mesh üyesinden (IP'leri `show mws member`'dan otomatik alınır) ayrı ayrı yapılır; her cihaz kendi konumundaki ağları görür. Extender'lara da aynı `monitor` kullanıcısıyla girilir.
- Radyo durumu (kanal, gerçek/ayarlanan genişlik, sıcaklık) her cihazdan arka planda 1 dk'da bir okunur (`RADIO_INTERVAL`). Backhaul için ayrı genişlik ayarı yoktur; controller'ın 5 GHz radyosu hangi genişlikte çalışıyorsa backhaul da onu kullanır.
- Yazılım güncellemeleri her cihazda saatte bir kontrol edilir (`FIRMWARE_INTERVAL`, 0 = kapalı). Router her kontrolde Keenetic güncelleme sunucusuna bağlanır. Exporter yalnızca okur; güncelleme kurmaz. Kanal API'de `lts-*`, `stable`, `preview`, `draft` (= Geliştirici) olarak geçer.
- Sistem Güvenliği sayaçları her cihazdan 1 dk'da bir okunur (`SECURITY_INTERVAL`, 0 = kapalı). Cihazda bulunmayan protokoller (ör. extender'da SSH) atlanır. Exporter yalnızca okur; koruma ayarlarını değiştirmez.
- Mesh dolaşım günlüğü (`show mws log`, controller son ~1000 olayı tutar) dakikada bir okunur (`ROAM_INTERVAL`, 0 = kapalı). Bu komut GET'te 404 verir; web arayüzü gibi POST ile okunur, yine yalnızca okumadır.
- İnternet, WAN ve VPN durumu her toplamada controller'dan okunur. Cihaz başına CPU / bellek / açık kalma süresi 30 sn'de bir okunur (`SYSTEM_INTERVAL`, 0 = kapalı).
- `monitor` kullanıcısı salt okunur olsa da router'ın tüm ayarlarını (`show running-config`: Wi-Fi şifreleri, VPN anahtarları) okuyabilir. Exporter bunları okumaz, ama `.env`'deki şifreyi yönetici şifresi gibi saklayın.
