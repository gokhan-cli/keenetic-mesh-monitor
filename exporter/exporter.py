#!/usr/bin/env python3
"""
Keenetic Mesh (MWS) Prometheus exporter.

Controller router'ın RCI API'sinden mesh üyelerini (extender'lar), backhaul
bağlantı bilgilerini ve controller'a bağlı Wi-Fi istemcilerini okur.

Kaynaklar:
  /rci/show/mws/member   -> extender'lar, backhaul (txrate, rssi, mcs, ht ...)
  /rci/show/associations -> controller ve mesh üyelerindeki Wi-Fi istemcileri
  /rci/show/ip/hotspot   -> MAC -> cihaz adı eşlemesi
  syslog (UDP 514)       -> engellenen IP'ler ve kötü niyetli istekler
"""
import base64
import hashlib
import hmac
import json
import logging
import os
import re
import socket
import threading
import time
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
# Router'ların uzak syslog'u (Diagnostik → Sistem günlüğü) için UDP port (0 = kapalı)
SYSLOG_PORT = int(os.environ.get("SYSLOG_PORT", "514"))
# Saldıran IP'nin son görülmesinden sonra listede kalma süresi (sn)
SYSLOG_RETENTION = int(os.environ.get("SYSLOG_RETENTION", "86400"))
SYSLOG_MAX_IPS = 200
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


def num(v):
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


class MeshCollector:
    def __init__(self, client, survey, radio, clients, firmware, security, syslog):
        self.c = client
        self.syslog = syslog
        self.security = security
        self.firmware = firmware
        self.survey = survey
        self.radio = radio
        self.clients = clients

    def _hostnames(self):
        try:
            hosts = as_list(self.c.get("show/ip/hotspot"), "host")
            return {h.get("mac", "").lower(): (AUTO_NAME_SUFFIX.sub("", h.get("name") or "")
                                               or h.get("hostname") or "")
                    for h in hosts if h.get("mac")}
        except Exception as e:  # isim eşlemesi opsiyonel
            log.debug("hotspot okunamadı: %s", e)
            return {}

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
        ips, devices = self.syslog.snapshot()
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
        yield from (seen, bans, bad, info, until, msgs, last)

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


class SyslogWorker(threading.Thread):
    """Router'ların uzak syslog'unu dinler; giriş korumasının engellediği IP'leri
    ve kötü niyetli istekleri (IP ve istenen yolla) tutar. RCI'da bu bilgi yok,
    monitor kullanıcısı günlüğü de okuyamıyor."""

    def __init__(self):
        super().__init__(daemon=True, name="syslog")
        self.lock = threading.Lock()
        self.ips = {}      # (cihaz, ip) -> durum
        self.devices = {}  # cihaz -> (satır sayısı, son satır zamanı)
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

    def snapshot(self):
        now = time.time()
        with self.lock:
            for key, st in list(self.ips.items()):
                if now - st["last"] > SYSLOG_RETENTION and st["ban_until"] < now:
                    del self.ips[key]
            if len(self.ips) > SYSLOG_MAX_IPS:
                for key, _ in sorted(self.ips.items(), key=lambda kv: kv[1]["last"])[:-SYSLOG_MAX_IPS]:
                    del self.ips[key]
            return ({k: {**v, "paths": list(v["paths"])} for k, v in self.ips.items()},
                    dict(self.devices))

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
    security, syslog = SecurityWorker(), SyslogWorker()
    REGISTRY.register(MeshCollector(client(HOST), survey, radio, clients, firmware, security, syslog))
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
