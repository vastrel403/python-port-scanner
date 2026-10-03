# VASTREL

**Network Security Scanner**

Menü tabanlı, hızlı ve sade bir port tarayıcı. nmap motorunu kullanır; nmap kurulu değilse yerleşik çok thread'li Python TCP motoruna geçer. Sonuçları terminalde tablo olarak gösterir ve tek tıkla açılan siyah temalı, animasyonlu bir HTML rapor üretir.

> **Yasal uyarı:** Bu araç yalnızca sahibi olduğunuz veya yazılı izin aldığınız sistemlerde kullanılmalıdır. İzinsiz tarama yasa dışı olabilir. Her taramadan önce yetki onayı istenir; sorumluluk kullanıcıya aittir.

---

## Özellikler

- **İki motor:** nmap (servis/sürüm tespiti, UDP, SYN, script, OS tespiti) ve nmap gerektirmeyen yerleşik Python TCP tarayıcı (banner yakalama dahil)
- **Hazır profiller:** Hızlı, Standart, Tam, Özel, Gizli SYN, UDP, Python TCP
- **Esnek hedef girişi:** tek IP, alan adı, CIDR, IP aralığı, birden fazla hedef ve dosyadan okuma
- **Terminal tablosu:** açık portlar çerçeveli tablo olarak listelenir
- **HTML rapor:** tamamen siyah tema, fare efektleri, animasyonlar, canlı arama filtresi, mobil uyumlu ve yazdırmaya uygun
- **Dışa aktarma:** HTML, JSON ve CSV (CSV formül enjeksiyonuna karşı korunur)
- **Tarama geçmişi:** oturum boyunca yapılan taramalar listelenir, tekrar görüntülenir veya dışa aktarılır
- **Güvenlik önlemleri:** hedef doğrulama, argüman enjeksiyonu engeli, yetki onayı

## Önizleme

```
127.0.0.1
┌─────────────┬─────────┬───────────┬───────────────────────┐
│       PORT  │  DURUM  │  SERVİS   │  SÜRÜM / BANNER       │
├─────────────┼─────────┼───────────┼───────────────────────┤
│    22/tcp   │  open   │  ssh      │  OpenSSH 9.6          │
│    80/tcp   │  open   │  http     │  nginx 1.24           │
└─────────────┴─────────┴───────────┴───────────────────────┘
```

> Ekran görüntüsü eklemek için dosyaları `docs/` klasörüne koyup buraya bağlayabilirsiniz.

## Kurulum

**Gereksinimler**

- Python 3.9 veya üzeri
- [`rich`](https://pypi.org/project/rich/) ve [`python-nmap`](https://pypi.org/project/python-nmap/)
- [nmap](https://nmap.org/download) (isteğe bağlı, Python TCP profili için gerekmez)

```bash
git clone https://github.com/vastrel403/python-port-scanner.git
cd python-port-scanner
pip install rich python-nmap
```

nmap kurulumu:

| Sistem  | Komut                   |
|---------|-------------------------|
| Debian / Ubuntu | `sudo apt install nmap` |
| macOS   | `brew install nmap`     |
| Windows | [nmap.org/download](https://nmap.org/download) |

## Kullanım

```bash
python3 scan.py
```

Gizli SYN ve UDP profilleri ile OS tespiti root/yönetici yetkisi ister:

```bash
sudo python3 scan.py
```

### Ana menü

| No | İşlem        | Açıklama                                         |
|----|--------------|--------------------------------------------------|
| 1  | Hedef        | Taranacak IP, alan adı, CIDR veya aralığı belirle |
| 2  | Tarama       | Profil seç ve taramayı başlat                    |
| 3  | Ağ keşfi     | Ağdaki canlı cihazları bul (ping sweep)          |
| 4  | Ayarlar      | Zamanlama, thread, zaman aşımı, tarama seçenekleri |
| 5  | Geçmiş       | Önceki taramaları görüntüle                      |
| 6  | Dışa aktar   | HTML, JSON veya CSV olarak kaydet                |
| 0  | Çıkış        |                                                  |

### Hedef formatları

```
192.168.1.10          tek IP
scanme.nmap.org       alan adı
192.168.1.0/24        CIDR
192.168.1.1-50        aralık
10.0.0.1, 10.0.0.5    birden fazla (virgül veya boşluk)
@hedefler.txt         dosyadan (satır başına bir hedef, # yorum)
```

### Tarama profilleri

| No | Profil      | Açıklama                              | Motor  | Root |
|----|-------------|---------------------------------------|--------|------|
| 1  | Hızlı       | En popüler 100 port                   | nmap   | -    |
| 2  | Standart    | Port 1-1024                           | nmap   | -    |
| 3  | Tam         | Tüm portlar (1-65535)                 | nmap   | -    |
| 4  | Özel        | Kendi port listen (örn. `22,80,8000-8100`) | nmap | -  |
| 5  | Gizli SYN   | Yarı açık (`-sS`) tarama, 1-1024      | nmap   | Evet |
| 6  | UDP         | En popüler 50 UDP portu               | nmap   | Evet |
| 7  | Python TCP  | nmap'siz, çok thread'li, banner yakalar | Python | -  |

### Ayarlar

Zamanlama (`-T0` ile `-T5`), sürüm tespiti, script taraması, OS tespiti, ping atlama, thread sayısı, zaman aşımı, rapor klasörü ve otomatik rapor seçeneği ayarlar menüsünden değiştirilir.

## Raporlar

Tarama bittiğinde HTML rapor otomatik olarak `vastrel_reports/` klasörüne yazılır ve tarayıcıda açılır (Firefox bulunursa Firefox, yoksa varsayılan tarayıcı). Raporlar tek dosyadır; sunucu gerektirmez.

Rapor yazı tiplerini Google Fonts'tan yükler. İnternet yoksa sistem yazı tipine geçer, görünüm bozulmaz.

## Proje yapısı

```
.
├── scan.py      # tarayıcı: motorlar, rapor, menü akışı
├── menu.py      # menü ve arayüz bileşenleri
└── vastrel_reports/   # oluşturulan raporlar (ilk taramada oluşur)
```

## Notlar

- Python TCP profili yalnızca TCP bağlantı taraması yapar. Servis adı port numarasına, sürüm bilgisi yakalanan banner'a dayanır.
- `/22`'den büyük ağlar Python TCP motorunda atlanır. Büyük ağlar için nmap profillerini kullanın.
- Sonuçlar tarama anındaki durumu yansıtır. Güvenlik duvarı ve IDS sistemleri sonuçları etkileyebilir.

## Lisans

Lisans bilgisi için `LICENSE` dosyasına bakın.

---

<sub>Made by Vastrel</sub>
