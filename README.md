# WebGüvenliği - Subdomain Scanner Web Uygulaması

Subdomain ve Port Scanner araçının modern web arayüzü. Python dilinden kurtulun, tarayıcıda kolayca kullanın! 🚀

## 📋 Özellikler

✨ **Çoklu Kaynak Entegrasyonu:**
- 🎫 **Certspotter** - SSL Sertifika Logarından Subdomain Tespiti
- 🔒 **SSL Certificate** - Aktif SSL Bağlantısından Subdomain Çıkarma
- ⚡ **RapidDNS** - DNS Kayıtlarından Hızlı Tarama
- 📡 **Sublist3r API** - Aggregate Subdomain Veritabanları
- 🛰️ **Omnisint/Sonar** - Sonar.omnisint.io Entegrasyonu

🎨 **Modern Web Arayüzü:**
- Responsive Design (Mobil Uyumlu)
- Real-Time İlerleme Göstergesi
- Canlı Tarama Mesajları
- Kaynak Özeti Istatistikleri
- Arama ve Filtreleme İşlevleri

📊 **Sonuç İşleme:**
- Subdomain Doğrulama (DNS & HTTP)
- Aktif/Pasif Durumu Tespiti
- HTTP Status Kontrollü
- CSV Dışa Aktarma
- Detaylı Sonuç Tablosu

## 🚀 Kurulum

### 1. Repository'yi Klonla
```bash
git clone https://github.com/st-seclab/webguvenligi-sub_scanner.git
cd webguvenligi-sub_scanner
```

### 2. Bağımlılıkları Yükle
```bash
pip install -r requirements.txt
```

### 3. Uygulamayı Çalıştır
```bash
python app.py
```

### 4. Web Arayüzüne Erişim
```
http://localhost:5000
```

## 📖 Kullanım

### Web Arayüzü Kullanarak

1. **Domain Girin:** Arayüzüne domain adını yazın (örn: `example.com`)
2. **Taramayı Başlat:** "🚀 Taramayı Başlat" butonuna tıkla
3. **Sonuçları İzle:** Real-time ilerleme ve mesajları göz
4. **Sonuçları Görüntüle:** Tarama tamamlandığında detaylı tabloyu gör
5. **Dışa Aktar:** "💾 CSV İndir" ile sonuçları indir

### Komut Satırı Kullanarak (Eski Yöntem)

```bash
python subdomain_finder.py example.com
python subdomain_finder.py -d example.com  # Debug modu
```

## 📁 Proje Yapısı

```
webguvenligi-sub_scanner/
├── app.py                      # Flask backend
├── subdomain_finder.py         # Orijinal CLI araç
├── requirements.txt            # Python bağımlılıkları
├── templates/
│   └── index.html             # Web arayüzü (HTML)
├── static/
│   ├── css/
│   │   └── style.css          # Stillemeler
│   └── js/
│       └── app.js             # Frontend lojik
└── README.md                   # Bu dosya
```

## 🔌 API Endpoints

### POST `/api/scan`
Subdomain taraması başlat

**Request:**
```json
{
  "domain": "example.com"
}
```

**Response:**
```json
{
  "status": "started",
  "domain": "example.com"
}
```

### GET `/api/status`
Tarama durumunu al

**Response:**
```json
{
  "running": true,
  "domain": "example.com",
  "progress": 25,
  "message": "SSL sertifikaları taranıyor...",
  "results": {...},
  "sources": {"certspotter": 5, "ssl": 2, ...}
}
```

### GET `/api/export`
Sonuçları CSV formatında dışa aktar

**Response:**
```json
{
  "filename": "subdomains_example.com.csv",
  "content": "SUBDOMAIN,DURUM,HTTP STATUS\n..."
}
```

## 🔍 Tarama Kaynakları

| Kaynak | API | Hız | Doğruluk |
|--------|-----|-----|----------|
| Certspotter | ✅ | ⚡⚡⚡ | ⭐⭐⭐⭐⭐ |
| SSL Sertifika | ✅ | ⚡⚡⚡⚡ | ⭐⭐⭐⭐ |
| RapidDNS | ✅ | ⚡⚡⚡ | ⭐⭐⭐⭐ |
| Sublist3r | ✅ | ⚡⚡ | ⭐⭐⭐ |
| Omnisint | ✅ | ⚡⚡⚡ | ⭐⭐⭐⭐ |

## ⚙️ Yapılandırma

Flask uygulaması varsayılan olarak aşağıdaki ayarlarla çalışır:

```python
# app.py içinde
app.run(
    debug=True,           # Debug modu
    host='0.0.0.0',      # Tüm interface'lerde dinle
    port=5000            # Port 5000
)
```

**Üretim ortamı için:**
```bash
# Gunicorn kullanarak
gunicorn -w 4 -b 0.0.0.0:8000 app:app
```

## 🛡️ Güvenlik Notları

⚠️ **Bu araç yalnızca yasal amaçlarla kullanılmalıdır:**

- ✅ Kendi domainlerinizi tarayabilirsiniz
- ✅ İzne sahip olduğunuz sistemleri tarayabilirsiniz
- ❌ İzinsiz tarama yapmanız durumunda yasal sonuçlar olabilir
- ❌ Ticari amaçlarla izinsiz kullanım yasaktır

## 📋 Sorumluluğu Reddetme

Bu yazılım eğitim amaçlarıyla sağlanmaktadır. Yazılımcı herhangi bir zarar, hasarlı aktivite veya kötü niyetli kullanımdan sorumlu değildir.

## 🤝 Katkıda Bulunma

Katkılarınız hoşlanır! Lütfen:

1. Fork edin
2. Feature branch oluşturun (`git checkout -b feature/amazing-feature`)
3. Değişikliklerinizi commit edin (`git commit -m 'Add amazing feature'`)
4. Branch'e push edin (`git push origin feature/amazing-feature`)
5. Pull Request açın

## 📄 Lisans

Bu proje MIT Lisansı altında yayınlanmıştır.

## 👥 Yazar

**WebGüvenliği Team**
- 👤 sAMeTTurk

## 📞 İletişim

- 📧 Email: [GitHub Profile]
- 🐙 GitHub: [@st-seclab](https://github.com/st-seclab)

## 🔗 Kaynaklar

- [Certspotter API](https://certspotter.com/api/v1/issuances)
- [RapidDNS](https://dns.bufferover.run)
- [Sublist3r](https://api.sublist3r.com)
- [Omnisint Sonar](https://sonar.omnisint.io)
- [Flask Documentation](https://flask.palletsprojects.com/)

---

**⭐ Bu projeyi beğendiyseniz yıldız vermeyi unutmayın!**

**Made with ❤️ by WebGüvenliği Team**
