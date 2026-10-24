#!/usr/bin/env python3
"""
Keenetic Mesh (MWS) Prometheus exporter.

Controller router'ın RCI API'sinden mesh üyelerini (extender'lar), backhaul
bağlantı bilgilerini ve controller'a bağlı Wi-Fi istemcilerini okur.

Kaynaklar:
  /rci/show/mws/member   -> extender'lar, backhaul (txrate, rssi, mcs, ht ...)
  /rci/show/associations -> controller ve mesh üyelerindeki Wi-Fi istemcileri
  /rci/show/ip/hotspot   -> MAC -> cihaz adı eşlemesi
  /rci/show/internet/status, show/interface -> internet, WAN (PPPoE) ve VPN tünelleri
  /rci/show/system       -> cihaz başına CPU, bellek, açık kalma süresi
  /rci/show/mws/log      -> mesh dolaşım günlüğü (istemci geçişleri, bağlanma/ayrılma)
  syslog (UDP 514)       -> engellenen IP'ler ve kötü niyetli istekler
"""
import base64
import calendar
import hashlib
import hmac
import ipaddress
import json
import logging
import os
import re
import socket
import threading
import time
from datetime import datetime
from urllib.parse import urlparse

import requests
from argon2.low_level import Type as Argon2Type, hash_secret_raw
from prometheus_client import REGISTRY, start_http_server
from prometheus_client.core import CounterMetricFamily, GaugeMetricFamily

HOST = os.environ.get("KEENETIC_HOST", "http://192.168.1.1").rstrip("/")
LOGIN = os.environ.get("KEENETIC_LOGIN", "monitor")
PASSWORD = os.environ.get("KEENETIC_PASSWORD", "")
PORT = int(os.environ.get("EXPORTER_PORT", "9877"))
TIMEOUT = float(os.environ.get("KEENETIC_TIMEOUT", "8"))
COLLECT_CLIENTS = os.environ.get("COLLECT_CLIENTS", "true").lower() == "true"
# İstemci listesinin controller ve her mesh üyesinden okunma aralığı (sn)
CLIENTS_INTERVAL = int(os.environ.get("CLIENTS_INTERVAL", "30"))
# HTTPS + IP adresiyle bağlanırken router sertifikası IP için geçerli değildir
VERIFY_TLS = os.environ.get("KEENETIC_VERIFY_TLS", "false").lower() == "true"
# Çevredeki Wi-Fi ağlarının taranacağı radyolar (boş = kapalı) ve tarama aralığı (sn).
# Tarama bant başına birkaç saniye sürer, her toplamada yapılmaz.
SURVEY_INTERFACES = [i.strip() for i in os.environ.get(
    "SITE_SURVEY_INTERFACES", "WifiMaster0,WifiMaster1").split(",") if i.strip()]
SURVEY_INTERVAL = int(os.environ.get("SITE_SURVEY_INTERVAL", "300"))
# Durumu izlenecek radyolar (boş = kapalı) ve okuma aralığı (sn)
RADIO_INTERFACES = [i.strip() for i in os.environ.get(
    "RADIO_INTERFACES", "WifiMaster0,WifiMaster1").split(",") if i.strip()]
RADIO_INTERVAL = int(os.environ.get("RADIO_INTERVAL", "60"))
# Yazılım güncellemesi kontrol aralığı (sn, 0 = kapalı). Router her kontrolde
# Keenetic güncelleme sunucusuna gider; sık yapmaya gerek yok.
FIRMWARE_INTERVAL = int(os.environ.get("FIRMWARE_INTERVAL", "3600"))
# Giriş koruması (brute-force) ve bağlantı taşması (DoS) sayaçları okuma aralığı (sn, 0 = kapalı)
SECURITY_INTERVAL = int(os.environ.get("SECURITY_INTERVAL", "60"))
# Sistem Güvenliği sayfasındaki protokoller; cihazda olmayanlar (404) atlanır
LOCKOUT_PROTOCOLS = ["http", "telnet", "ssh"]
# Cihaz başına CPU / bellek / açık kalma süresi okuma aralığı (sn, 0 = kapalı)
SYSTEM_INTERVAL = int(os.environ.get("SYSTEM_INTERVAL", "30"))
# Mesh dolaşım günlüğü okuma aralığı (sn, 0 = kapalı) ve tabloda tutulan son olay sayısı
ROAM_INTERVAL = int(os.environ.get("ROAM_INTERVAL", "60"))
ROAM_RECENT = 100
WIFI_BANDS = {0: "2.4 GHz", 1: "5 GHz", 2: "6 GHz"}
# Servis / süreç durumu (show processes) okuma aralığı (sn, 0 = kapalı)
SERVICE_INTERVAL = int(os.environ.get("SERVICE_INTERVAL", "60"))
# Uygulama bazında trafik (show ntce summary/chart) okuma aralığı (sn, 0 = kapalı). Router
# 3 sn'lik dilimleri son 3 dakika için tutar; aralık 180'den küçük olmalı
APP_INTERVAL = min(int(os.environ.get("APP_INTERVAL", "60")), 150)
APP_GROUPS = {
    "Uncategorized": "Sınıflandırılmamış", "Encrypted": "Şifreli", "Cloud and CDN Services": "Bulut ve CDN",
    "Artificial Intelligence": "Yapay zekâ", "Advertisement and Analytic Services": "Reklam ve analiz",
    "Network Management": "Ağ yönetimi", "Organizers": "Düzenleyiciler", "Mail": "E-posta",
    "Development Tools and Services": "Geliştirme araçları", "M2M and IoT": "Akıllı cihazlar (IoT)",
    "Tunnel": "Tünel / VPN", "Messaging": "Mesajlaşma", "Social Networking": "Sosyal ağ",
    "Video Streaming": "Video yayını", "Audio Streaming": "Müzik ve ses", "Gaming": "Oyun",
    "Web Browsing": "Web", "File Transfer": "Dosya aktarımı", "Software Updates": "Yazılım güncellemeleri",
    "VoIP": "Sesli/görüntülü arama", "Remote Access": "Uzaktan erişim", "Shopping": "Alışveriş",
    "News": "Haber", "Peer to Peer": "P2P", "Search Engines": "Arama motorları",
    "Social": "Sosyal", "App-Stores and OS Updates": "Uygulama mağazaları ve güncellemeler",
    "Business": "İş uygulamaları", "Enterprise Services": "Kurumsal servisler", "Voice over IP": "İnternet telefonu",
}
# VPN sayılan arayüz türleri (show/interface "type")
VPN_TYPES = {"openvpn", "wireguard", "ipsec", "ike", "l2tp", "pptp", "sstp", "openconnect", "zerotier"}
# Router'ların uzak syslog'u (Diagnostik → Sistem günlüğü) için UDP port (0 = kapalı)
SYSLOG_PORT = int(os.environ.get("SYSLOG_PORT", "514"))
# Saldıran IP'nin son görülmesinden sonra listede kalma süresi (sn)
SYSLOG_RETENTION = int(os.environ.get("SYSLOG_RETENTION", "86400"))
SYSLOG_MAX_IPS = 200
# Yönetici girişlerinin metrikte kalma süresi (sn)
SYSLOG_LOGIN_RETENTION = 3600
# Taramada controller'ın görünen adı (extender'lar mesh'teki adlarıyla görünür)
CONTROLLER_NAME = os.environ.get("CONTROLLER_NAME", "Ana router")
# Başarısız girişten sonra yeniden deneme süresi (sn)
AUTH_BACKOFF = int(os.environ.get("KEENETIC_AUTH_BACKOFF", "900"))

# Router'ın otomatik kayıtta eklediği " - Home network - 2026-10-14 19:54" eki
AUTO_NAME_SUFFIX = re.compile(r" - [^-]+ - \d{4}-\d{2}-\d{2} \d{2}:\d{2}$")

# "<11>Oct 20 12:17:38 Keenetic-node-1 ndm: <mesaj>"
SYSLOG_LINE = re.compile(r"^<\d+>(?:\w{3} [ \d]\d \d\d:\d\d:\d\d )?(\S+) [^:]+: (.*)$", re.S)
# Netfilter::Lockout::Manager: "Http": ban remote host 203.0.113.7 for 15 minutes.
SYSLOG_BAN = re.compile(r'Lockout::Manager: "(\w+)": ban remote host (\S+) for (\d+) minute')
# Core::Scgi::Handler::GetIndex: malicious request: /wp-login.php [203.0.113.7].
SYSLOG_MALICIOUS = re.compile(r"malicious request: (.*) \[([0-9A-Fa-f.:]+)\]\.?$")
# Core::Security::Authority: started a user session [admin#904(password) from
# https://{http/rci}@203.0.113.7:PPPoE0/ agent Edge 155.0.0 on Windows 10 via browser-direct].
SYSLOG_LOGIN = re.compile(r"started a user session \[([^#\s]+)#\d+\((\w+)\) from ([\w+]+)://\{[^}]*\}@(.+):([^:/]*)/ "
                          r"agent (.*?) on (.*?) via ([\w-]+)\]")
# Keenetic bulutu üzerinden gelen oturumlar: mobil uygulama ve uzaktan yönetim
# (gerçek kaynak IP görünmez, bulut sunucusunun adresi görünür)
CLOUD_VIA = {"mobile-app", "rmm-cloud"}

log = logging.getLogger("keenetic-exporter")
logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"),
                    format="%(asctime)s %(levelname)s %(message)s")


class KeeneticClient:
    """RCI oturumu: challenge/response ile giriş, cookie ile devam.

    Cihaz başına tek oturum tüm thread'lerce paylaşılır (bkz. client()).
    requests.Session thread-safe olmadığından her istek kilitle yapılır.
    """

    def __init__(self, host, login, password):
        self.host, self.login, self.password = host, login, password
        self.lock = threading.RLock()
        self.s = requests.Session()
        self.auth_blocked_until = 0
        self.s.verify = VERIFY_TLS
        if not VERIFY_TLS:
            requests.packages.urllib3.disable_warnings()

    def _auth(self):
        # Başarısız girişten sonra bekle: Keenetic art arda hatalı girişte IP'yi kilitler
        wait = self.auth_blocked_until - time.time()
        if wait > 0:
            raise RuntimeError(f"önceki giriş başarısızdı, {int(wait)} sn sonra tekrar denenecek")
        r = self.s.get(f"{self.host}/auth", timeout=TIMEOUT)
        if r.status_code == 200:
            return
        if r.status_code != 401:
            raise RuntimeError(f"auth: beklenmeyen durum {r.status_code}")
        # Yeni firmware'ler x-ndw4 sunar; bu firmware'de oluşturulan kullanıcılar
        # yalnızca ndw4 ile girebilir (web arayüzü de önce ndw4'ü dener)
        if "x-ndw4-interactive" in r.headers.get("WWW-Authenticate", ""):
            try:
                self._auth_ndw4()
                self.auth_blocked_until = 0
                log.info("RCI oturumu açıldı (ndw4): %s", self.host)
                return
            except Exception as e:
                log.warning("ndw4 girişi başarısız, ndw2 deneniyor: %s", e)
                r = self.s.get(f"{self.host}/auth", timeout=TIMEOUT)
                if r.status_code == 200:
                    return
        realm = r.headers["X-NDM-Realm"]
        challenge = r.headers["X-NDM-Challenge"]
        md5 = hashlib.md5(f"{self.login}:{realm}:{self.password}".encode()).hexdigest()
        sha = hashlib.sha256(f"{challenge}{md5}".encode()).hexdigest()
        r = self.s.post(f"{self.host}/auth",
                        json={"login": self.login, "password": sha},
                        timeout=TIMEOUT)
        if r.status_code != 200:
            self.auth_blocked_until = time.time() + AUTH_BACKOFF
            raise RuntimeError(f"auth başarısız: {r.status_code} "
                               f"(kullanıcı/şifre/yetki kontrol edin; {AUTH_BACKOFF} sn beklenecek)")
        self.auth_blocked_until = 0
        log.info("RCI oturumu açıldı: %s", self.host)

    def _auth_ndw4(self):
        """x-ndw4-interactive: Argon2id + HMAC-SHA3-512, SCRAM benzeri 3 aşama."""
        def hmac512(key, msg):
            return hmac.new(key, msg if isinstance(msg, bytes) else msg.encode(), "sha3_512").digest()

        def ndm_data(resp, phase):
            if resp.status_code != 401 or not resp.headers.get("X-NDM-Data"):
                raise RuntimeError(f"ndw4 {phase}: beklenmeyen durum {resp.status_code}")
            return json.loads(base64.b64decode(resp.headers["X-NDM-Data"]))

        url = f"{self.host}/auth"
        cnonce = base64.b64encode(os.urandom(16)).decode()
        d = ndm_data(self.s.post(url, json={"login": self.login, "nonce": cnonce},
                                 timeout=TIMEOUT), "aşama 1")
        salt, snonce, it, mem = d["salt"], d["nonce"], int(d["iter"]), int(d["memcost"])
        key = hash_secret_raw(self.password.encode(), base64.b64decode(salt), time_cost=it,
                              memory_cost=mem, parallelism=1, hash_len=64, type=Argon2Type.ID)
        client_key = hmac512(key, "NDW4 Interactive Client Key")
        stored_key = hashlib.sha3_512(client_key).digest()
        server_key = hmac512(key, "NDW4 Interactive Server Key")
        auth_msg = (f"login1={self.login},nonce1={cnonce};"
                    f"iter2={it},memcost2={mem},nonce2={snonce},salt2={salt};"
                    f"login3={self.login},nonce3={snonce}")
        proof = bytes(a ^ b for a, b in zip(client_key, hmac512(stored_key, auth_msg)))

        d = ndm_data(self.s.post(url, json={"login": self.login, "nonce": snonce,
                                            "proof": base64.b64encode(proof).decode()},
                                 timeout=TIMEOUT), "aşama 2")
        sig = d["signature"]
        if not hmac.compare_digest(hmac512(server_key, auth_msg), base64.b64decode(sig)):
            raise RuntimeError("ndw4: sunucu imzası doğrulanamadı (şifre yanlış)")
        sig_proof = bytes(a ^ b for a, b in zip(
            client_key, hmac512(stored_key, f"{auth_msg};signature4={sig}")))
        r = self.s.post(url, json={"login": self.login, "nonce": snonce,
                                   "signature-proof": base64.b64encode(sig_proof).decode()},
                        timeout=TIMEOUT)
        if r.status_code != 200:
            raise RuntimeError(f"ndw4 aşama 3: durum {r.status_code}")

    def run_continued(self, path, data=None, limit=90):
        """Uzun süren komutlar (ör. components list) önce {"continued": true} döner;
        web arayüzü gibi aynı yola GET atarak sonuç gelene kadar beklenir."""
        url = f"{self.host}/rci/{path.strip('/')}"
        with self.lock:
            r = self.s.post(url, json=data or {}, timeout=TIMEOUT)
            if r.status_code == 401:
                self._auth()
                r = self.s.post(url, json=data or {}, timeout=TIMEOUT)
            r.raise_for_status()
            d = r.json()
        t0 = time.time()
        while isinstance(d, dict) and d.get("continued"):
            if time.time() - t0 > limit:
                raise RuntimeError(f"{path}: {limit} sn içinde tamamlanmadı")
            time.sleep(1)  # beklerken kilit diğer thread'lere açık
            with self.lock:
                r = self.s.get(url, timeout=TIMEOUT)
                r.raise_for_status()
                d = r.json()
        return d

    def get(self, path):
        url = f"{self.host}/rci/{path.strip('/')}"
        with self.lock:
            r = self.s.get(url, timeout=TIMEOUT)
            if r.status_code == 401:
                self._auth()
                r = self.s.get(url, timeout=TIMEOUT)
            r.raise_for_status()
            return r.json()

    def post(self, path, data=None):
        """Bazı komutlar (ör. show mws log) GET'te 404 verir, web arayüzü gibi
        POST ile okunur. Yine yalnız okuma: yol bir show komutudur."""
        url = f"{self.host}/rci/{path.strip('/')}"
        with self.lock:
            r = self.s.post(url, json=data or {}, timeout=TIMEOUT)
            if r.status_code == 401:
                self._auth()
                r = self.s.post(url, json=data or {}, timeout=TIMEOUT)
            r.raise_for_status()
            return r.json()


_clients, _clients_lock = {}, threading.Lock()


def client(host):
    """Cihaz başına paylaşılan oturum. Ayrı oturumlar seyrek çalışan işlerde
    (site survey, yazılım kontrolü) boşta kalıp router tarafından kapatılıyor
    ve her turda yeniden giriş gerekiyordu."""
    with _clients_lock:
        if host not in _clients:
            _clients[host] = KeeneticClient(host, LOGIN, PASSWORD)
        return _clients[host]


def member_name(mem):
    return mem.get("name") or mem.get("known-host") or mem.get("model") or mem.get("ip")


def as_list(data, key):
    """RCI bazen liste, bazen {key: [...]} ya da tek nesne döndürür."""
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        inner = data.get(key)
        if isinstance(inner, list):
            return inner
        if isinstance(inner, dict):
            return [inner]
        if data and key not in data:
            return [data]
    return []


# Web arayüzündeki kanal adları (API'de sandbox adı: lts-4.3, stable, preview, draft)
CHANNEL_TITLES = {"lts": "LTS", "stable": "Kararlı", "preview": "Önizleme", "draft": "Geliştirici"}


def channel_title(sandbox):
    return CHANNEL_TITLES.get(sandbox.split("-", 1)[0], sandbox)


def version_key(v):
    """'5.02.B.0.0-0' gibi sürümleri karşılaştırılabilir yapar (A alfa < B beta < C kararlı)."""
    return tuple(int(p) if p.isdigit() else ord(p) - 1000 for p in re.findall(r"\d+|[A-Z]", str(v)))


def tr_duration(seconds):
    """Süreyi Türkçe yazar: "1 gün 17 saat", "14 saat 20 dk", "35 dk".
    Grafana'nın süre birimleri yalnız İngilizce. Metin etiket olarak verildiği için
    her değişiklik yeni bir seri açar; bu yüzden 1 saati geçince 5 dk'lık adımlarla
    (aşağı yuvarlanır), 1 günü geçince saatlik değişir."""
    m = int(seconds) // 60
    d, h = divmod(m // 60, 24)
    if d:
        return f"{d} gün {h} saat" if h else f"{d} gün"
    if h:
        m5 = m % 60 // 5 * 5
        return f"{h} saat {m5} dk" if m5 else f"{h} saat"
    return f"{m} dk" if m else "1 dk'dan az"


def num(v):
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


class MeshCollector:
    def __init__(self, client, survey, radio, clients, firmware, security, syslog, system, roam, apps, services):
        self.c = client
        self.apps = apps
        self.services = services
        self.roam = roam
        self.hosts = []  # son show/ip/hotspot listesi
        self.system = system
        self.syslog = syslog
        self.security = security
        self.firmware = firmware
        self.survey = survey
        self.radio = radio
        self.clients = clients

    def _hostnames(self):
        """MAC -> cihaz adı. Aynı liste cihaz başına trafik için de kullanılır."""
        try:
            self.hosts = as_list(self.c.get("show/ip/hotspot"), "host")
        except Exception as e:  # isim eşlemesi opsiyonel
            log.debug("hotspot okunamadı: %s", e)
            self.hosts = []
        return {h.get("mac", "").lower(): (AUTO_NAME_SUFFIX.sub("", h.get("name") or "")
                                           or h.get("hostname") or "")
                for h in self.hosts if h.get("mac")}

    def _host_traffic(self, names):
        """Router üzerinden geçen trafik (internet, VPN); aynı ağdaki cihazlar
        arası yerel trafik dahil değil. Sayaçlar router açıldığından beri birikir,
        cihaz bağlanıp kopunca sıfırlanmaz."""
        L = ["mac", "name"]
        rx = CounterMetricFamily("keenetic_client_receive_bytes", "Cihazın router üzerinden aldığı (indirdiği) bayt", labels=L)
        tx = CounterMetricFamily("keenetic_client_transmit_bytes", "Cihazın router üzerinden gönderdiği (yüklediği) bayt", labels=L)
        for h in self.hosts:
            mac = h.get("mac", "").lower()
            r, t = num(h.get("rxbytes")), num(h.get("txbytes"))
            if not mac or not (r or t):
                continue
            lv = [mac, names.get(mac) or mac]
            rx.add_metric(lv, r or 0)
            tx.add_metric(lv, t or 0)
        yield rx
        yield tx

    def collect(self):
        up = GaugeMetricFamily("keenetic_up", "RCI erişimi başarılı mı (1/0)")
        dur = GaugeMetricFamily("keenetic_scrape_duration_seconds", "Toplama süresi")
        t0 = time.time()
        try:
            members = as_list(self.c.get("show/mws/member"), "member")
            names = self._hostnames()
        except Exception as e:
            log.error("toplama hatası: %s", e)
            up.add_metric([], 0)
            yield up
            return
        up.add_metric([], 1)
        yield up
        yield from self._members(members, names)
        yield from self._host_traffic(names)
        yield from self._internet()
        if SYSTEM_INTERVAL:
            yield from self._system()
        if ROAM_INTERVAL:
            yield from self._roam()
        if APP_INTERVAL:
            yield from self._apps()
        if SERVICE_INTERVAL:
            yield from self._services()
        if COLLECT_CLIENTS:
            yield from self._clients(names)
        if SURVEY_INTERFACES:
            yield from self._neighbors()
        if RADIO_INTERFACES:
            yield from self._radios()
        if FIRMWARE_INTERVAL:
            yield from self._firmware()
        if SECURITY_INTERVAL:
            yield from self._security()
        if SYSLOG_PORT:
            yield from self._syslog()
        dur.add_metric([], time.time() - t0)
        yield dur

    # ---------- mesh üyeleri ----------
    def _members(self, members, names):
        L = ["mac", "name"]
        info = GaugeMetricFamily("keenetic_mesh_member_info", "Mesh üyesi bilgisi",
                                 labels=L + ["model", "ip", "firmware", "uplink", "mode", "security"])
        m = {k: GaugeMetricFamily(f"keenetic_mesh_{k}", h, labels=L) for k, h in {
            "member_cpu_load": "Extender CPU yükü (%)",
            "member_memory_used_kb": "Extender bellek kullanımı (kB)",
            "member_memory_total_kb": "Extender toplam bellek (kB)",
            "member_uptime_seconds": "Extender çalışma süresi",
            "member_associations": "Extender'a bağlı istemci sayısı",
            "backhaul_wireless": "Backhaul kablosuz mu (1) kablolu mu (0)",
            "backhaul_txrate_mbps": "Backhaul fiziksel bağlantı hızı (Mbps)",
            "backhaul_rssi_dbm": "Backhaul sinyal gücü (dBm)",
            "backhaul_mcs": "Backhaul MCS indeksi",
            "backhaul_spatial_streams": "Backhaul uzamsal akış sayısı",
            "backhaul_channel_width_mhz": "Backhaul kanal genişliği (MHz)",
            "backhaul_guard_interval_ns": "Backhaul guard interval (ns)",
            "backhaul_uptime_seconds": "Backhaul bağlantı süresi",
            "backhaul_cost": "Backhaul STP yol maliyeti",
        }.items()}
        port_up = GaugeMetricFamily("keenetic_mesh_port_link_up", "Extender Ethernet port bağlantısı (1/0)",
                                    labels=L + ["port"])
        port_speed = GaugeMetricFamily("keenetic_mesh_port_speed_mbps", "Extender Ethernet port hızı (Mbps)",
                                       labels=L + ["port"])
        inet = GaugeMetricFamily("keenetic_mesh_member_internet_available", "Extender internete erişebiliyor mu",
                                 labels=L)

        for mem in members:
            mac = (mem.get("mac") or mem.get("cid") or "unknown").lower()
            name = mem.get("name") or mem.get("known-host") or names.get(mac) or mem.get("model") or mac
            lv = [mac, name]
            bh = mem.get("backhaul") or {}
            sysi = mem.get("system") or {}
            fw = mem.get("fw") or mem.get("firmware") or mem.get("version") or ""
            if isinstance(fw, (dict, list)):
                fw = ""
            uplink = str(bh.get("uplink", ""))
            info.add_metric(lv + [str(mem.get("model", "")), str(mem.get("ip", "")), str(fw),
                                  uplink, str(bh.get("mode", "")), str(bh.get("security", ""))], 1)

            def put(key, val):
                v = num(val)
                if v is not None:
                    m[key].add_metric(lv, v)

            put("member_cpu_load", sysi.get("cpuload"))
            mem_s = str(sysi.get("memory", ""))
            if "/" in mem_s:
                used, total = mem_s.split("/", 1)
                put("member_memory_used_kb", used)
                put("member_memory_total_kb", total)
            put("member_uptime_seconds", sysi.get("uptime"))
            put("member_associations", mem.get("associations"))

            m["backhaul_wireless"].add_metric(lv, 1 if "wifi" in uplink.lower() else 0)
            put("backhaul_txrate_mbps", bh.get("txrate"))
            put("backhaul_rssi_dbm", bh.get("rssi"))
            put("backhaul_mcs", bh.get("mcs"))
            put("backhaul_spatial_streams", bh.get("txss"))
            put("backhaul_channel_width_mhz", bh.get("ht"))
            put("backhaul_guard_interval_ns", bh.get("gi"))
            put("backhaul_uptime_seconds", bh.get("uptime"))
            put("backhaul_cost", bh.get("cost"))

            if "internet-available" in mem:
                inet.add_metric(lv, 1 if mem.get("internet-available") else 0)
            for p in mem.get("port") or []:
                label = str(p.get("label", "?"))
                is_up = p.get("link") == "up"
                port_up.add_metric(lv + [label], 1 if is_up else 0)
                if is_up and num(p.get("speed")) is not None:
                    port_speed.add_metric(lv + [label], num(p.get("speed")))

        yield info
        yield from m.values()
        yield port_up
        yield port_speed
        yield inet

    # ---------- controller'daki Wi-Fi istemcileri ----------
    def _clients(self, names):
        L = ["device", "mac", "name", "ap", "mode"]
        m = {k: GaugeMetricFamily(f"keenetic_wifi_client_{k}", h, labels=L) for k, h in {
            "txrate_mbps": "İstemci bağlantı hızı (Mbps)",
            "rssi_dbm": "İstemci sinyal gücü (dBm)",
            "mcs": "İstemci MCS",
            "spatial_streams": "İstemci akış sayısı",
            "channel_width_mhz": "İstemci kanal genişliği (MHz)",
            "uptime_seconds": "İstemci bağlantı süresi",
        }.items()}
        # Kapanan/çıkarılan bir node'un istemcileri asılı kalmasın
        fresh = time.time() - 3 * CLIENTS_INTERVAL
        for device, (stations, at) in self.clients.snapshot().items():
            if at < fresh:
                continue
            self._stations(m, device, stations, names)
        yield from m.values()

    @staticmethod
    def _stations(m, device, stations, names):
        for st in stations:
            mac = st.get("mac", "").lower()
            lv = [device, mac, names.get(mac) or mac, str(st.get("ap", "")), str(st.get("mode", ""))]
            for key, field in (("txrate_mbps", "txrate"), ("rssi_dbm", "rssi"), ("mcs", "mcs"),
                               ("spatial_streams", "txss"), ("channel_width_mhz", "ht"),
                               ("uptime_seconds", "uptime")):
                v = num(st.get(field))
                if v is not None:
                    m[key].add_metric(lv, v)

    # ---------- çevredeki Wi-Fi ağları (site survey) ----------
    def _neighbors(self):
        L = ["scanner", "band", "bssid", "ssid", "channel", "bandwidth", "encryption", "standard", "mesh"]
        rssi = GaugeMetricFamily("keenetic_wifi_neighbor_rssi_dbm", "Çevredeki ağın sinyal gücü (dBm)",
                                 labels=L)
        quality = GaugeMetricFamily("keenetic_wifi_neighbor_quality", "Çevredeki ağın sinyal kalitesi (%)",
                                    labels=L)
        # Kanal değer olarak da verilir: komşunun kanal değiştirmesi grafikte izlenebilsin
        channel = GaugeMetricFamily("keenetic_wifi_neighbor_channel", "Çevredeki ağın kullandığı kanal",
                                    labels=["scanner", "band", "bssid", "ssid"])
        age = GaugeMetricFamily("keenetic_wifi_neighbor_survey_age_seconds", "Son taramadan bu yana geçen süre",
                                labels=["scanner"])
        seen = set()
        for scanner, (cells, at) in self.survey.snapshot().items():
            age.add_metric([scanner], time.time() - at)
            self._cells(scanner, cells, rssi, quality, channel, seen)
        yield rssi
        yield quality
        yield channel
        yield age

    # ---------- radyolar (cihaz başına gerçek kanal / genişlik) ----------
    def _radios(self):
        L = ["device", "interface", "band"]
        m = {k: GaugeMetricFamily(f"keenetic_radio_{k}", h, labels=L) for k, h in {
            "up": "Radyo açık ve çalışıyor (1/0)",
            "channel": "Kullanılan kanal",
            "channel_width_mhz": "Gerçek kanal genişliği (MHz)",
            "channel_width_configured_mhz": "Ayarlanan kanal genişliği (MHz)",
            "bitrate_mbps": "Radyonun bildirdiği azami bit hızı (Mbps)",
            "temperature_celsius": "Radyo sıcaklığı (°C)",
            "dfs_cac": "DFS CAC değeri (router'ın ham değeri)",
            "dfs_nop": "DFS non-occupancy değeri (router'ın ham değeri, >0 = radar etkisi)",
        }.items()}
        for device, (radios, _) in self.radio.snapshot().items():
            for r in radios:
                st = r["state"]
                ch = num(st.get("channel"))
                lv = [device, r["interface"], "2.4 GHz" if ch is not None and ch <= 14 else "5 GHz"]

                def put(key, val, scale=1):
                    v = num(val)
                    if v is not None:
                        m[key].add_metric(lv, v * scale)

                m["up"].add_metric(lv, 1 if st.get("state") == "up" and st.get("hwstate") == "on" else 0)
                put("channel", ch)
                put("channel_width_mhz", st.get("bandwidth"))
                put("channel_width_configured_mhz", r["configured_width"])
                put("bitrate_mbps", st.get("bitrate"), 1e-6)
                put("temperature_celsius", st.get("temperature"))
                dfs = st.get("dfs") or {}
                put("dfs_cac", dfs.get("cac"))
                put("dfs_nop", dfs.get("nop"))
        yield from m.values()

    # ---------- sistem güvenliği ----------
    def _security(self):
        L = ["device", "protocol"]
        lock = {k: GaugeMetricFamily(f"keenetic_lockout_{k}", h, labels=L) for k, h in {
            "enabled": "Giriş koruması açık mı (1/0)",
            "current_blocked": "Şu anda engellenen IP sayısı",
            "current_quarantine": "Hatalı giriş nedeniyle takip edilen IP sayısı",
            "blocked_last_hour": "Son 1 saatte engellenen IP sayısı",
            "blocked_total": "Router açıldığından beri engellenen IP sayısı",
            "threshold": "Engelleme için başarısız deneme eşiği",
            "duration_minutes": "Kilitleme süresi (dk)",
            "observation_window_minutes": "Başarısız denemelerin sayıldığı aralık (dk)",
        }.items()}
        ct = {k: GaugeMetricFamily(f"keenetic_conntrack_{k}", h, labels=["device"]) for k, h in {
            "lockout_enabled": "Bağlantı taşması (DoS) koruması açık mı (1/0)",
            "lockout_active": "DoS koruması şu anda devrede mi (1/0)",
            "lockout_time_left_seconds": "DoS korumasının kalan süresi (sn)",
            "lockout_threshold_percent": "Genel bağlantılar için koruma eşiği (%)",
            "max": "Bağlantı tablosu kapasitesi",
        }.items()}
        conns = GaugeMetricFamily("keenetic_conntrack_connections", "Bağlantı sayısı (scope: public = internetten, private = yerel ağdan)",
                                  labels=["device", "scope"])
        now = time.time()
        for device, (sec, at) in self.security.snapshot().items():
            if now - at > 3 * SECURITY_INTERVAL:
                continue  # cihaza ulaşılamıyor; eski sayıları gösterme
            for proto, d in sec["lockout"].items():
                lv = [device, proto]
                st, rc = d["state"], d["config"]
                lock["enabled"].add_metric(lv, 1 if rc.get("enable") else 0)
                for key, src in [("current_blocked", "current-blocked"),
                                 ("current_quarantine", "current-quarantine"),
                                 ("blocked_last_hour", "total-blocked-per-hour"),
                                 ("blocked_total", "total-blocked")]:
                    v = num(st.get(src))
                    if v is not None:
                        lock[key].add_metric(lv, v)
                for key, src in [("threshold", "threshold"), ("duration_minutes", "duration"),
                                 ("observation_window_minutes", "observation-window")]:
                    v = num(rc.get(src))
                    if v is not None:
                        lock[key].add_metric(lv, v)
            c = sec.get("conntrack")
            if c:
                st, rc = c["state"], c["config"]
                lv = [device]
                ct["lockout_enabled"].add_metric(lv, 1 if st.get("enabled") else 0)
                ct["lockout_active"].add_metric(lv, 1 if st.get("active") else 0)
                for key, v in [("lockout_time_left_seconds", st.get("time-left")),
                               ("lockout_threshold_percent", (rc.get("threshold") or {}).get("public")),
                               ("max", st.get("max-size"))]:
                    v = num(v)
                    if v is not None:
                        ct[key].add_metric(lv, v)
                usage = st.get("usage") or {}
                for scope, src in [("public", "public-count"), ("private", "private-count")]:
                    v = num(usage.get(src))
                    if v is not None:
                        conns.add_metric([device, scope], v)
        yield from lock.values()
        yield from ct.values()
        yield conns

    def _internet(self):
        """İnternet durumu, WAN arayüzü ve VPN tünelleri (yalnız controller)."""
        try:
            st = self.c.get("show/internet/status")
            ifs = self.c.get("show/interface")
            pings = as_list(self.c.get("show/ping-check"), "pingcheck")
        except Exception as e:  # opsiyonel veri; mesh metrikleri etkilenmesin
            log.warning("internet durumu okunamadı: %s", e)
            return
        inet = GaugeMetricFamily("keenetic_internet_up", "Router'a göre internet erişimi var mı (1/0)")
        inet.add_metric([], 1 if st.get("internet") else 0)
        chk = GaugeMetricFamily("keenetic_internet_check", "Router'ın internet kontrolleri (1/0)", labels=["check"])
        for check, key in [("gateway", "gateway-accessible"), ("dns", "dns-accessible"),
                           ("captive", "captive-accessible")]:
            if key in st:
                chk.add_metric([check], 1 if st[key] else 0)
        yield inet
        yield chk

        ping = GaugeMetricFamily("keenetic_pingcheck_pass", "Ping kontrolü başarılı mı (1/0)",
                                 labels=["profile", "interface"])
        pfail = GaugeMetricFamily("keenetic_pingcheck_failures", "Ping kontrolündeki ardışık başarısızlık",
                                  labels=["profile", "interface"])
        for prof in pings:
            for name, d in (prof.get("interface") or {}).items():
                lv = [prof.get("profile", ""), name]
                ping.add_metric(lv, 1 if d.get("status") == "pass" else 0)
                v = num(d.get("failcount"))
                if v is not None:
                    pfail.add_metric(lv, v)
        yield ping
        yield pfail

        wan = (st.get("gateway") or {}).get("interface") or next(
            (k for k, v in ifs.items() if isinstance(v, dict) and v.get("defaultgw")), None)
        wl = ["interface"]
        winfo = GaugeMetricFamily("keenetic_wan_info", "İnternete çıkan arayüz", labels=wl + ["description", "type", "via"])
        wup = GaugeMetricFamily("keenetic_wan_up", "WAN bağlı mı (1/0)", labels=wl)
        wtime = GaugeMetricFamily("keenetic_wan_uptime_seconds", "WAN bağlantısının süresi (PPPoE'de oturum süresi)", labels=wl)
        wtext = GaugeMetricFamily("keenetic_wan_uptime_text", "WAN bağlantı süresi, Türkçe metin (text etiketi)",
                                  labels=wl + ["text"])
        cnt = {k: CounterMetricFamily(f"keenetic_wan_{k}", h, labels=wl) for k, h in {
            "receive_bytes": "WAN alınan bayt", "transmit_bytes": "WAN gönderilen bayt",
            "receive_errors": "WAN alma hataları", "transmit_errors": "WAN gönderme hataları",
            "receive_drops": "WAN alınırken düşen paketler", "transmit_drops": "WAN gönderilirken düşen paketler",
        }.items()}
        w = ifs.get(wan) if wan else None
        if isinstance(w, dict):
            winfo.add_metric([wan, w.get("description", ""), w.get("type", ""), w.get("via", "")], 1)
            wup.add_metric([wan], 1 if w.get("connected") == "yes" else 0)
            if num(w.get("uptime")) is not None:
                wtime.add_metric([wan], num(w.get("uptime")))
                wtext.add_metric([wan, tr_duration(num(w.get("uptime")))], 1)
            try:
                stat = self.c.get(f"show/interface/stat?name={wan}")
                for k, src in [("receive_bytes", "rxbytes"), ("transmit_bytes", "txbytes"),
                               ("receive_errors", "rxerrors"), ("transmit_errors", "txerrors"),
                               ("receive_drops", "rxdropped"), ("transmit_drops", "txdropped")]:
                    if num(stat.get(src)) is not None:
                        cnt[k].add_metric([wan], num(stat[src]))
            except Exception as e:
                log.debug("WAN sayaçları okunamadı: %s", e)
        yield winfo
        yield wup
        yield wtime
        yield wtext
        yield from cnt.values()

        vl = ["interface", "name", "type"]
        ven = GaugeMetricFamily("keenetic_vpn_enabled", "VPN tüneli açık mı (ayar, 1/0)", labels=vl)
        vup = GaugeMetricFamily("keenetic_vpn_up", "VPN tüneli bağlı mı (1/0)", labels=vl)
        vtime = GaugeMetricFamily("keenetic_vpn_uptime_seconds", "VPN tünelinin bağlı kalma süresi", labels=vl)
        vtext = GaugeMetricFamily("keenetic_vpn_uptime_text", "VPN bağlı kalma süresi, Türkçe metin (text etiketi)",
                                  labels=vl + ["text"])
        for name, v in ifs.items():
            if not isinstance(v, dict) or str(v.get("type", "")).lower() not in VPN_TYPES:
                continue
            lv = [name, v.get("description") or name, v.get("type", "")]
            ven.add_metric(lv, 1 if v.get("state") == "up" else 0)
            vup.add_metric(lv, 1 if v.get("connected") == "yes" else 0)
            if num(v.get("uptime")) is not None and v.get("connected") == "yes":
                vtime.add_metric(lv, num(v.get("uptime")))
                vtext.add_metric(lv + [tr_duration(num(v.get("uptime")))], 1)
        yield ven
        yield vup
        yield vtime
        yield vtext

    def _system(self):
        L = ["device"]
        fam = {k: GaugeMetricFamily(f"keenetic_system_{k}", h, labels=L) for k, h in {
            "cpu_load_percent": "CPU yükü (%, son ~30 sn ortalaması)",
            "cpu_load_max_percent": "CPU yükü (%, son ~30 sn en yüksek)",
            "memory_used_bytes": "Kullanılan bellek",
            "memory_total_bytes": "Toplam bellek",
            "uptime_seconds": "Cihazın açık kalma süresi",
        }.items()}
        uptext = GaugeMetricFamily("keenetic_system_uptime_text", "Açık kalma süresi, Türkçe metin (text etiketi)",
                                   labels=L + ["text"])
        now = time.time()
        for device, (d, at) in self.system.snapshot().items():
            if now - at > 3 * SYSTEM_INTERVAL:
                continue  # cihaza ulaşılamıyor; eski değeri gösterme
            sysi, busy = d["system"], (d.get("cpustat") or {}).get("busy") or {}
            for k, v in [("cpu_load_percent", busy.get("avg", sysi.get("cpuload"))),
                         ("cpu_load_max_percent", busy.get("max")),
                         ("uptime_seconds", sysi.get("uptime"))]:
                if num(v) is not None:
                    fam[k].add_metric([device], num(v))
            if num(sysi.get("uptime")) is not None:
                uptext.add_metric([device, tr_duration(num(sysi["uptime"]))], 1)
            mem = str(sysi.get("memory", ""))  # "kullanılan/toplam" kB
            if "/" in mem:
                used, total = (num(x) for x in mem.split("/", 1))
                if used is not None and total:
                    fam["memory_used_bytes"].add_metric([device], used * 1024)
                    fam["memory_total_bytes"].add_metric([device], total * 1024)
        yield from fam.values()
        yield uptext

    def _roam(self):
        L = ["mac", "name", "event", "from_device", "from_band", "to_device", "to_band", "method"]
        total = CounterMetricFamily("keenetic_mesh_roam_events",
                                    "Mesh olayları (event: roam = erişim noktası değiştirdi, join = bağlandı, "
                                    "leave = ayrıldı); exporter açıldıktan sonrakiler", labels=L)
        recent = GaugeMetricFamily("keenetic_mesh_roam_event", "Son mesh olayları; değer = olay zamanı (unix)",
                                   labels=["id", "mac", "name", "event", "from", "to", "method"])
        counts, events, names = self.roam.snapshot()
        for key, n in counts.items():
            mac = key[0]
            total.add_metric([mac, names.get(mac) or mac] + list(key[1:]), n)
        for ev in events:
            _, event, fdev, fband, tdev, tband, method = ev["key"]
            recent.add_metric([str(ev["id"]), ev["mac"], names.get(ev["mac"]) or ev["mac"], event,
                               " · ".join(x for x in (fdev, fband) if x), " · ".join(x for x in (tdev, tband) if x),
                               method], ev["time"])
        yield total
        yield recent

    def _apps(self):
        L = ["app", "group"]
        rx = CounterMetricFamily("keenetic_application_receive_bytes",
                                 "Uygulamadan alınan (indirilen) bayt, tüm cihazlar; exporter açıldıktan sonrası",
                                 labels=L)
        tx = CounterMetricFamily("keenetic_application_transmit_bytes",
                                 "Uygulamaya gönderilen (yüklenen) bayt, tüm cihazlar; exporter açıldıktan sonrası",
                                 labels=L)
        for (app, group), (r, t) in self.apps.snapshot().items():
            rx.add_metric([app, group], r)
            tx.add_metric([app, group], t)
        yield rx
        yield tx
        active = GaugeMetricFamily("keenetic_application_active",
                                   "Router'ın son 3 dakikada trafik saydığı uygulama sayısı (0 = Trafik İzleme sayacı "
                                   "durmuş olabilir)")
        n, at = self.apps.active
        if at and time.time() - at < 3 * APP_INTERVAL:
            active.add_metric([], n)
        yield active

    def _services(self):
        L = ["device", "service", "kind"]
        up = GaugeMetricFamily("keenetic_service_up", "Servis / süreç çalışıyor mu (1/0)", labels=L)
        enabled = GaugeMetricFamily("keenetic_service_enabled",
                                    "Servis ayarlarda açık mı (1/0); kapalıyken durması uyarı üretmez", labels=L)
        pid = GaugeMetricFamily("keenetic_service_pid", "Sürecin numarası; değişirse yeniden başlamıştır", labels=L)
        mem = GaugeMetricFamily("keenetic_service_memory_bytes", "Sürecin kullandığı bellek (RSS)", labels=L)
        now = time.time()
        for device, (items, at) in self.services.snapshot().items():
            if now - at > 3 * SERVICE_INTERVAL:
                continue  # cihaza ulaşılamıyor; eski değeri gösterme
            for (name, kind), x in items.items():
                lv = [device, name, kind]
                up.add_metric(lv, x["up"])
                if x["enabled"] is not None:
                    enabled.add_metric(lv, x["enabled"])
                if x["up"] and x["pid"]:
                    pid.add_metric(lv, x["pid"])
                    mem.add_metric(lv, x["rss"])
        yield from (up, enabled, pid, mem)

    def _syslog(self):
        L = ["device", "ip"]
        seen = GaugeMetricFamily("keenetic_security_ip_last_seen_seconds",
                                 "Saldıran IP'nin günlükte son görüldüğü zaman (unix)", labels=L)
        bans = GaugeMetricFamily("keenetic_security_ip_bans", "IP'nin engellenme sayısı", labels=L)
        bad = GaugeMetricFamily("keenetic_security_ip_malicious_requests",
                                "Router'ın kötü niyetli saydığı istek sayısı", labels=L)
        info = GaugeMetricFamily("keenetic_security_ip_info",
                                 "Son engellendiği protokol ve son istediği yollar", labels=L + ["protocol", "paths"])
        until = GaugeMetricFamily("keenetic_security_ban_until_seconds", "Engelin bittiği/biteceği zaman (unix)",
                                  labels=["device", "protocol", "ip"])
        msgs = CounterMetricFamily("keenetic_syslog_messages", "Alınan syslog satırı", labels=["device"])
        last = GaugeMetricFamily("keenetic_syslog_last_message_seconds", "Son syslog satırının zamanı (unix)",
                                 labels=["device"])
        login = GaugeMetricFamily("keenetic_admin_login_seconds",
                                  "Router'a yönetici girişi zamanı (unix; exporter'ın kendi kullanıcısı hariç)",
                                  labels=["device", "user", "ip", "interface", "client", "scope"])
        ips, devices, logins = self.syslog.snapshot()
        for (device, ip), st in ips.items():
            lv = [device, ip]
            seen.add_metric(lv, st["last"])
            bans.add_metric(lv, st["bans"])
            bad.add_metric(lv, st["malicious"])
            info.add_metric(lv + [st["protocol"], ", ".join(st["paths"])], 1)
            if st["ban_until"]:
                until.add_metric([device, st["protocol"], ip], st["ban_until"])
        for device, (n, at) in devices.items():
            msgs.add_metric([device], n)
            last.add_metric([device], at)
        # Aynı etiketlerle birden çok giriş: en yenisi kalır (liste eskiden yeniye)
        keys = ("device", "user", "ip", "interface", "client", "scope")
        for lv, at in {tuple(x[k] for k in keys): x["at"] for x in logins}.items():
            login.add_metric(list(lv), at)
        yield from (seen, bans, bad, info, until, msgs, last, login)

    # ---------- yazılım sürümleri / güncellemeler ----------
    def _firmware(self):
        info = GaugeMetricFamily("keenetic_firmware_info", "Kurulu yazılım (değer her zaman 1)",
                                 labels=["device", "channel", "sandbox", "installed", "title"])
        upd = GaugeMetricFamily("keenetic_firmware_update_available",
                                "Cihazın takip ettiği kanalda güncelleme var mı (1/0)",
                                labels=["device", "channel", "available"])
        chan = GaugeMetricFamily("keenetic_firmware_channel_newer",
                                 "Kanaldaki son sürüm kurulu sürümden yeni mi (1/0)",
                                 labels=["device", "channel", "sandbox", "version"])
        age = GaugeMetricFamily("keenetic_firmware_check_age_seconds", "Son güncelleme kontrolünden bu yana",
                                labels=["device"])
        for device, (fw, at) in self.firmware.snapshot().items():
            age.add_metric([device], time.time() - at)
            cur = channel_title(fw["sandbox"])
            info.add_metric([device, cur, fw["sandbox"], fw["installed"], fw["title"]], 1)
            upd.add_metric([device, cur, fw["available"]],
                           1 if version_key(fw["available"]) > version_key(fw["installed"]) else 0)
            for sb in fw["sandboxes"]:
                chan.add_metric([device, channel_title(sb["name"]), sb["name"], sb["version"]],
                                1 if version_key(sb["version"]) > version_key(fw["installed"]) else 0)
        yield info
        yield upd
        yield chan
        yield age

    @staticmethod
    def _cells(scanner, cells, rssi, quality, channel, seen):
        for ap in cells:
            ch = num(ap.get("channel"))
            lv = [scanner,
                  "2.4 GHz" if ch is not None and ch <= 14 else "5 GHz",
                  str(ap.get("address", "")).lower(),
                  ap.get("essid") or "(gizli)",
                  str(int(ch)) if ch is not None else "",
                  str(ap.get("bandwidth", "")),
                  str(ap.get("encryption", "")),
                  str(ap.get("ieee", "")),
                  "1" if "mws" in ap or "mws-primary" in ap else "0"]
            if tuple(lv) in seen:  # aynı seriyi iki kez yazmak scrape'i bozar
                continue
            seen.add(tuple(lv))
            if ch is not None and ("ch",) + tuple(lv[:4]) not in seen:
                seen.add(("ch",) + tuple(lv[:4]))
                channel.add_metric(lv[:4], ch)
            for fam, field in ((rssi, "rssi"), (quality, "quality")):
                v = num(ap.get(field))
                if v is not None:
                    fam.add_metric(lv, v)


class DeviceWorker(threading.Thread):
    """Controller ve her mesh üyesini arka planda periyodik sorgular.

    Yavaş RCI çağrıları scrape'i bekletmesin diye ayrı thread'de çalışır;
    cihaz oturumu diğer işlerle paylaşılır. Alt sınıflar poll(client) ile
    cihaz başına sonucu döndürür.
    """

    def __init__(self, name, interval):
        super().__init__(daemon=True, name=name)
        self.interval = interval
        self.lock = threading.Lock()
        self.results = {}  # cihaz adı -> (poll sonucu, zaman)

    def snapshot(self):
        with self.lock:
            return dict(self.results)

    def _devices(self):
        devices = [(CONTROLLER_NAME, HOST)]
        scheme = HOST.split("://", 1)[0] if "://" in HOST else "http"
        try:
            members = as_list(client(HOST).get("show/mws/member"), "member")
        except Exception as e:
            log.warning("%s: mesh üyeleri okunamadı: %s", self.name, e)
            members = []
        for mem in members:
            ip = mem.get("ip")
            if ip:
                devices.append((member_name(mem), f"{scheme}://{ip}"))
        return devices

    def poll(self, client):
        raise NotImplementedError

    def run(self):
        while True:
            for name, host in self._devices():
                try:
                    result = self.poll(client(host))
                except Exception as e:  # opsiyonel veri; eski sonuç korunur
                    log.warning("%s %s (%s) okunamadı: %s", self.name, name, host, e)
                    continue
                with self.lock:
                    self.results[name] = (result, time.time())
            time.sleep(self.interval)


class SurveyWorker(DeviceWorker):
    """Site survey: cihaz/bant başına birkaç saniye sürer."""

    def __init__(self):
        super().__init__("site-survey", SURVEY_INTERVAL)

    def poll(self, client):
        cells = []
        for iface in SURVEY_INTERFACES:
            cells += as_list(client.get(f"show/site-survey?name={iface}"), "ap_cell")
        return cells


class ClientsWorker(DeviceWorker):
    """Her cihaza (controller + mesh üyeleri) bağlı Wi-Fi istemcileri."""

    def __init__(self):
        super().__init__("clients", CLIENTS_INTERVAL)

    def poll(self, client):
        return as_list(client.get("show/associations"), "station")


class FirmwareWorker(DeviceWorker):
    """Kurulu yazılım, takip edilen kanal ve kanallardaki son sürümler."""

    def __init__(self):
        super().__init__("firmware", FIRMWARE_INTERVAL)

    def poll(self, client):
        lst = client.run_continued("components/list")
        base = (lst.get("component") or {}).get("base") or {}
        # "local" = çalışan yazılım; "firmware" = kanaldaki sürüm (güncelleme
        # varken kurulu olandan farklıdır). base.installed yeniden başlatmadan
        # sonra bir süre eski sürümü gösterebiliyor; bu yüzden önce "local".
        local = lst.get("local") or {}
        installed = local.get("version") or base.get("installed", "")
        sandboxes = client.run_continued("components/list-sandboxes").get("sandbox") or []
        return {"sandbox": str(local.get("sandbox") or lst.get("sandbox", "")),
                "installed": installed,
                "available": base.get("version") or installed,
                "title": local.get("title", ""),
                "sandboxes": [s for s in sandboxes if s.get("name") and s.get("version")]}


class SecurityWorker(DeviceWorker):
    """Sistem Güvenliği sayfası: giriş koruması ve bağlantı taşması koruması."""

    def __init__(self):
        super().__init__("security", SECURITY_INTERVAL)
        self.missing = set()  # (host, yol): cihazda olmayan komutlar, tekrar sorulmaz

    def _get(self, client, path):
        if (client.host, path) in self.missing:
            return None
        try:
            return client.get(path)
        except requests.HTTPError as e:
            if e.response is not None and e.response.status_code == 404:
                self.missing.add((client.host, path))
                return None
            raise

    def poll(self, client):
        lockout = {}
        for proto in LOCKOUT_PROTOCOLS:
            st = self._get(client, f"show/ip/{proto}/lockout-policy")
            if st is not None:
                lockout[proto] = {"state": st,
                                  "config": self._get(client, f"show/rc/ip/{proto}/lockout-policy") or {}}
        conntrack = None
        st = self._get(client, "show/ip/conntrack/lockout")
        if st is not None:
            conntrack = {"state": st, "config": self._get(client, "show/rc/ip/conntrack/lockout") or {}}
        return {"lockout": lockout, "conntrack": conntrack}


class RoamWorker(DeviceWorker):
    """Mesh dolaşım günlüğü (show mws log). Controller son ~1000 olayı tutar:
    istemcinin erişim noktası değiştirmesi (802.11r "ft" ya da "pmk" önbelleğiyle),
    bağlanması ve ayrılması. Erişim noktası MAC'i cihaz adına çevrilir."""

    def __init__(self):
        super().__init__("roam", ROAM_INTERVAL)
        self.last_id = None
        self.counts = {}   # (mac, olay, nereden, bant, nereye, bant, yöntem) -> sayı
        self.events = []   # son olaylar, en yenisi sonda
        self.names = {}    # istemci MAC -> ad
        self.aps, self.aps_at = {}, 0  # erişim noktası MAC -> cihaz adı

    def snapshot(self):
        with self.lock:
            return dict(self.counts), list(self.events), dict(self.names)

    def _ap_map(self):
        if self.aps and time.time() - self.aps_at < 600:
            return self.aps
        aps = {}
        for name, host in self._devices():
            try:
                for v in client(host).get("show/interface").values():
                    if isinstance(v, dict) and v.get("type") == "AccessPoint" and v.get("mac"):
                        aps[v["mac"].lower()] = name
            except Exception as e:  # eski eşleme korunur
                log.warning("roam: %s erişim noktaları okunamadı: %s", name, e)
        self.aps, self.aps_at = {**self.aps, **aps}, time.time()
        return self.aps

    @staticmethod
    def _utc_offset(clock):
        """Router saat dilimi (günlük zamanları yereldir ve yıl içermez)."""
        tz = (clock.get("tz") or [{}])[0]
        off = tz.get("stdoffset", 0)
        if clock.get("dst") == "active":
            off += tz.get("dstoffset", 0)
        return off

    @staticmethod
    def _when(ts, offset):
        now = time.time()
        year = time.gmtime(now + offset).tm_year
        for y in (year, year - 1):  # yılbaşından hemen sonra geçen yılın kayıtları
            try:
                t = calendar.timegm(datetime.strptime(f"{y} {ts}", "%Y %b %d %H:%M:%S").timetuple()) - offset
            except ValueError:
                return now
            if t <= now + 86400:
                return t
        return now

    def _event(self, it, aps, offset):
        ap, left = (it.get("ap") or "").lower(), it.get("left") or {}
        lap = (left.get("ap") or "").lower()
        event = "roam" if ap and lap else ("join" if ap else "leave")
        key = (it.get("mac", "").lower(), event,
               aps.get(lap, lap) if lap else "", WIFI_BANDS.get(left.get("band"), "") if lap else "",
               aps.get(ap, ap) if ap else "", WIFI_BANDS.get(it.get("band"), "") if ap else "",
               it.get("roam") or "")
        return {"id": it.get("id", 0), "mac": key[0], "key": key, "time": self._when(it.get("timestamp", ""), offset)}

    def run(self):
        while True:
            try:
                self._poll()
            except Exception as e:  # opsiyonel veri; bir sonraki turda tekrar
                log.warning("roam: dolaşım günlüğü okunamadı: %s", e)
            time.sleep(self.interval)

    def _poll(self):
        c = client(HOST)
        entries = sorted(((c.post("show/mws/log").get("log") or {}).values()), key=lambda x: x.get("id", 0))
        offset = self._utc_offset(c.get("show/clock/date"))
        aps = self._ap_map()
        names = {h["mac"].lower(): AUTO_NAME_SUFFIX.sub("", h.get("name") or "") or h.get("hostname") or ""
                 for h in as_list(c.get("show/ip/hotspot"), "host") if h.get("mac")}
        first = self.last_id is None
        if not first and entries and entries[-1].get("id", 0) < self.last_id:
            self.last_id = 0  # router yeniden başladı, numaralar baştan
        new = [it for it in entries if first or it.get("id", 0) > self.last_id]
        with self.lock:
            for it in new:
                ev = self._event(it, aps, offset)
                # İlk okumadaki geçmiş sayılmaz (exporter yeniden başlayınca sayaç sıçramasın),
                # ama seri 0'dan başlasın ki sonraki ilk olay da increase()'te görünsün
                self.counts[ev["key"]] = self.counts.get(ev["key"], 0) + (0 if first else 1)
                self.events.append(ev)
            self.events = self.events[-ROAM_RECENT:]
            self.names = names
            if entries:
                self.last_id = entries[-1].get("id", 0)
        if new and not first:
            log.debug("roam: %d yeni olay", len(new))


class AppWorker(DeviceWorker):
    """Uygulama bazında trafik, web arayüzündeki Trafik İzleme ile aynı kaynak
    (yalnız controller; mesh üyelerinin trafiği de oradan geçer). show ntce summary
    son 3 dakikada trafiği olan uygulamaları, show ntce chart her biri için 3 sn'lik
    dilimlerde kesin baytı verir; son okumadan bu yana tamamlanan dilimler sayaca
    eklenir. Kayıtsız cihazlar dahildir; cihaz başına kırılım yoktur."""

    def __init__(self):
        super().__init__("apps", APP_INTERVAL)
        self.last_t = None  # sayılan son dilimin zamanı (router açık kalma süresi, sn)
        self.counts = {}    # (uygulama, grup) -> birikmiş [rx, tx]
        self.active = (0, 0)  # (trafikli uygulama sayısı, okuma zamanı)

    def snapshot(self):
        with self.lock:
            return {k: tuple(v) for k, v in self.counts.items()}

    @staticmethod
    def _app_name(a):
        if a.get("id-num") == 0:
            return "Sınıflandırılmamış"
        # "Google FCM (encrypted, google)" -> "Google FCM", "Cloudflare (application)" -> "Cloudflare"
        return re.sub(r"( \([^)]*\))+$", "", a.get("long") or "") or a.get("short") or "?"

    def run(self):
        while True:
            try:
                self._poll()
            except Exception as e:  # opsiyonel veri; bir sonraki turda tekrar
                log.warning("apps: uygulama trafiği okunamadı: %s", e)
            time.sleep(self.interval)

    def _poll(self):
        c = client(HOST)
        apps = {}
        for a in c.post("show/ntce/summary", {"application": True, "attrib": "sumbytes", "detail": 0,
                                               "count": 1000}).get("application") or []:
            # "type" kalemleri (diğerleri) kimliksiz özet satırıdır; özet trafiği olmayan
            # uygulamaları da listeler, grafik ise çok kalemde eksik döner
            if "id-num" in a and num(a.get("sumbytes")):
                group = a.get("group-long") or ""
                apps[a["id-num"]] = (self._app_name(a), APP_GROUPS.get(group, group))
        self.active = (len(apps), time.time())
        if not apps:
            return
        bars = c.post("show/ntce/chart", {"applications": True, "attributes": "rxbytes,txbytes", "detail": 0,
                                          "items": ",".join(str(i) for i in apps)}).get("bar") or []
        # id -> {dilim zamanı: [rx, tx]}
        data = {}
        for b in bars:
            d = data.setdefault(b.get("id-num"), {})
            for attr in b.get("bars") or []:
                i = 0 if attr.get("attribute") == "rxbytes" else 1
                for p in attr.get("data") or []:
                    d.setdefault(p["t"], [0, 0])[i] = num(p.get("v")) or 0
        times = {t for d in data.values() for t in d}
        if not times:
            return
        newest = max(times)  # en yeni dilim henüz dolmamış olabilir; sonraki turda sayılır
        with self.lock:
            for key in apps.values():
                self.counts.setdefault(key, [0, 0])
            if self.last_t is not None and self.last_t <= newest:
                # ilk okumada ya da router yeniden başlayınca geçmiş sayılmaz, seriler 0'dan başlar
                for id_, d in data.items():
                    key = apps.get(id_)
                    if key is None:
                        continue
                    for t, (r, x) in d.items():
                        if self.last_t < t < newest:
                            self.counts[key][0] += r
                            self.counts[key][1] += x
            self.last_t = max((t for t in times if t < newest), default=newest)


class ServiceWorker(DeviceWorker):
    """KeeneticOS servisleri (show processes "object"/"service") ve Entware gibi
    servis olmayan arka plan süreçleri (init'in çocukları, ör. tailscaled)."""

    def __init__(self):
        super().__init__("services", SERVICE_INTERVAL)

    def poll(self, client):
        items = {}  # (ad, tür) -> durum; aynı adlı birden çok süreç toplanır
        for p in as_list(client.get("show/processes"), "process"):
            obj, svc = p.get("object"), p.get("service")
            pid = num(p.get("pid")) or 0
            if obj:
                key = (obj.get("id") or "?", "servis")
                if svc:
                    running = svc.get("state") == "STARTED" and bool(svc.get("alive"))
                    # "started" = kullanıcı/ayar servisi açık istiyor (arayüzden kapatınca false
                    # olur); "configured" ayarın var olduğunu söyler, kapatınca da true kalır
                    configured = 1 if svc.get("configured") and svc.get("started") else 0
                else:
                    running, configured = obj.get("state") == "RUNNING", None
            elif p.get("comm") and p.get("ppid") == "1":
                key, running, configured = (p["comm"], "süreç"), pid > 0, None
            else:
                continue
            rss = (num(str(p.get("vm-rss", "")).split()[0] if p.get("vm-rss") else None) or 0) * 1024
            x = items.setdefault(key, {"up": 0, "enabled": configured, "pid": 0, "rss": 0})
            if running:
                x["up"] = 1
                if pid > 0:
                    x["pid"] = min(x["pid"] or pid, pid)
                    x["rss"] += rss
        return items


class SystemWorker(DeviceWorker):
    """Cihaz başına CPU, bellek ve açık kalma süresi (controller dahil)."""

    def __init__(self):
        super().__init__("system", SYSTEM_INTERVAL)

    def poll(self, client):
        try:
            cpustat = client.get("show/system/cpustat")
        except Exception:  # eski yazılımlarda yok; cpuload yeter
            cpustat = None
        return {"system": client.get("show/system"), "cpustat": cpustat}


class SyslogWorker(threading.Thread):
    """Router'ların uzak syslog'unu dinler; giriş korumasının engellediği IP'leri
    ve kötü niyetli istekleri (IP ve istenen yolla) tutar. RCI'da bu bilgi yok,
    monitor kullanıcısı günlüğü de okuyamıyor."""

    def __init__(self):
        super().__init__(daemon=True, name="syslog")
        self.lock = threading.Lock()
        self.ips = {}      # (cihaz, ip) -> durum
        self.devices = {}  # cihaz -> (satır sayısı, son satır zamanı)
        self.logins = []   # yönetici girişleri (en yeni sonda)
        self.names, self.names_at = {}, 0  # kaynak IP -> cihaz adı

    def _device(self, addr):
        """Yalnız controller ve mesh üyelerinden gelen satırlar kabul edilir;
        ağdaki başka biri sahte engel satırı gönderip uyarı ürettiremez."""
        age = time.time() - self.names_at
        if age > 300 or (addr not in self.names and age > 60):
            self.names_at = time.time()
            names = {urlparse(HOST).hostname: CONTROLLER_NAME}
            try:
                for mem in as_list(client(HOST).get("show/mws/member"), "member"):
                    if mem.get("ip"):
                        names[mem["ip"]] = member_name(mem)
                self.names = names
            except Exception as e:  # eski eşleme korunur
                log.warning("syslog: mesh üyeleri okunamadı: %s", e)
                self.names = {**self.names, **names}
        return self.names.get(addr)

    def _ip(self, device, ip, now):
        st = self.ips.setdefault((device, ip), {"bans": 0, "malicious": 0, "protocol": "",
                                                "ban_until": 0, "paths": []})
        st["last"] = now
        return st

    def handle(self, data, addr):
        device = self._device(addr)
        if device is None:
            log.debug("syslog: bilinmeyen kaynak %s", addr)
            return
        text = data.decode("utf-8", "replace").strip()
        m = SYSLOG_LINE.match(text)
        msg = m.group(2) if m else text
        now = time.time()
        with self.lock:
            n, _ = self.devices.get(device, (0, 0))
            self.devices[device] = (n + 1, now)
            if b := SYSLOG_BAN.search(msg):
                proto, ip, minutes = b.group(1).lower(), b.group(2), int(b.group(3))
                st = self._ip(device, ip, now)
                st["bans"] += 1
                st["protocol"], st["ban_until"] = proto, now + minutes * 60
                log.info("%s: %s %s için %d dk engellendi", device, ip, proto, minutes)
            elif r := SYSLOG_MALICIOUS.search(msg):
                path, ip = r.group(1)[:80], r.group(2)
                st = self._ip(device, ip, now)
                st["malicious"] += 1
                if path in st["paths"]:
                    st["paths"].remove(path)
                st["paths"] = (st["paths"] + [path])[-5:]
            elif (g := SYSLOG_LOGIN.search(msg)) and g.group(1) != LOGIN:
                self.logins = (self.logins + [self._login(device, g, now)])[-50:]

    @staticmethod
    def _login(device, g, now):
        user, scheme, ip, iface, agent, os_, via = g.group(1, 3, 4, 5, 6, 7, 8)
        if via in CLOUD_VIA or scheme.startswith(("coala", "sndns")):
            scope = "bulut"
        else:
            try:
                scope = "internet" if ipaddress.ip_address(ip.strip("[]")).is_global else "yerel"
            except ValueError:
                scope = "internet"
        client = ", ".join(x for x in (agent, os_) if x != "unknown")
        via = {"browser-direct": "tarayıcı", "mobile-app": "mobil uygulama",
               "rmm-cloud": "Keenetic bulutu"}.get(via, via)
        log.info("%s: %s girişi, %s (%s)", device, user, ip, scope)
        return {"device": device, "user": user, "ip": ip, "interface": iface,
                "client": f"{client} ({via})" if client else via, "scope": scope, "at": now}

    def snapshot(self):
        now = time.time()
        with self.lock:
            for key, st in list(self.ips.items()):
                if now - st["last"] > SYSLOG_RETENTION and st["ban_until"] < now:
                    del self.ips[key]
            if len(self.ips) > SYSLOG_MAX_IPS:
                for key, _ in sorted(self.ips.items(), key=lambda kv: kv[1]["last"])[:-SYSLOG_MAX_IPS]:
                    del self.ips[key]
            self.logins = [x for x in self.logins if now - x["at"] < SYSLOG_LOGIN_RETENTION]
            return ({k: {**v, "paths": list(v["paths"])} for k, v in self.ips.items()},
                    dict(self.devices), list(self.logins))

    def run(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("0.0.0.0", SYSLOG_PORT))
        log.info("Syslog :%d/udp dinleniyor", SYSLOG_PORT)
        while True:
            data, (addr, _) = sock.recvfrom(8192)
            try:
                self.handle(data, addr)
            except Exception as e:
                log.warning("syslog satırı işlenemedi: %s", e)


class RadioWorker(DeviceWorker):
    """Radyoların gerçek kanal/genişlik durumu ve ayarlanan genişlik."""

    def __init__(self):
        super().__init__("radio", RADIO_INTERVAL)

    def poll(self, client):
        radios = []
        for iface in RADIO_INTERFACES:
            st = client.get(f"show/interface?name={iface}")
            rc = client.get(f"show/rc/interface?name={iface}").get(iface) or {}
            # "160", "40-below" / "40-above" (2.4 GHz'te ikincil kanal yönü) gibi gelir
            width = re.match(r"\d+", str((rc.get("channel") or {}).get("width", "")))
            radios.append({"interface": iface, "state": st,
                           "configured_width": width.group() if width else None})
        return radios


if __name__ == "__main__":
    if not PASSWORD:
        log.warning("KEENETIC_PASSWORD boş")
    survey, radio, clients, firmware = SurveyWorker(), RadioWorker(), ClientsWorker(), FirmwareWorker()
    security, syslog, system, roam = SecurityWorker(), SyslogWorker(), SystemWorker(), RoamWorker()
    apps, services = AppWorker(), ServiceWorker()
    REGISTRY.register(MeshCollector(client(HOST), survey, radio, clients, firmware, security, syslog, system, roam,
                                    apps, services))
    if SERVICE_INTERVAL:
        services.start()
    if APP_INTERVAL:
        apps.start()
    if ROAM_INTERVAL:
        roam.start()
    if SYSTEM_INTERVAL:
        system.start()
    if SYSLOG_PORT:
        syslog.start()
    if SECURITY_INTERVAL:
        security.start()
    if FIRMWARE_INTERVAL:
        firmware.start()
    if COLLECT_CLIENTS:
        clients.start()
    if SURVEY_INTERFACES:
        survey.start()
    if RADIO_INTERFACES:
        radio.start()
    start_http_server(PORT)
    log.info("Exporter :%d/metrics üzerinde, hedef %s", PORT, HOST)
    while True:
        time.sleep(3600)
