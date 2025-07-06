# Yemek Sözlük

Yemek kültürünün dijital sözlüğü - Ekşi sözlük tarzında bir web uygulaması.

## 🚀 Özellikler

### ✅ Mevcut Özellikler
- **Kullanıcı Yönetimi**: Kayıt olma, giriş yapma, profil düzenleme
- **E-posta Doğrulama**: Kayıt sırasında e-posta doğrulama kodu
- **Şifre Sıfırlama**: E-posta ile şifre sıfırlama
- **Başlık ve Entry Sistemi**: Başlık açma, entry girme, düzenleme, silme
- **Beğeni Sistemi**: Entry'leri beğenme/beğenmekten vazgeçme
- **Takip Sistemi**: Kullanıcıları takip etme
- **Mesajlaşma**: Kullanıcılar arası özel mesajlaşma
- **Bildirim Sistemi**: Beğeni, takip, mesaj bildirimleri
- **Arama**: Başlık arama ve otomatik tamamlama
- **Şikayet Sistemi**: Uygunsuz entry'leri şikayet etme
- **Admin/Moderator Paneli**: Yönetim paneli
- **Paylaşma**: Entry'leri sosyal medyada paylaşma

### 🔧 Teknik Özellikler
- **Flask Framework**: Python web framework
- **SQLite Veritabanı**: Hafif ve hızlı veritabanı
- **Responsive Tasarım**: Mobil uyumlu arayüz
- **AJAX Arama**: Gerçek zamanlı arama
- **E-posta Entegrasyonu**: SMTP ile e-posta gönderimi

## 📋 Kurulum

### 1. Gereksinimler
```bash
python3 -m venv venv
source venv/bin/activate  # Linux/Mac
# veya
venv\Scripts\activate  # Windows
```

### 2. Bağımlılıkları Yükleyin
```bash
pip install flask
```

### 3. Veritabanını Oluşturun
```bash
python3 yemeksozluk.py
```

### 4. Admin Kullanıcısı Oluşturun
```bash
python3 create_admin.py
```

### 5. E-posta Ayarlarını Yapılandırın
`yemeksozluk.py` dosyasında e-posta ayarlarını güncelleyin:
```python
app.config['MAIL_USERNAME'] = 'your-email@gmail.com'
app.config['MAIL_PASSWORD'] = 'your-app-password'
```

### 6. Uygulamayı Çalıştırın
```bash
python3 yemeksozluk.py
```

## 👥 Kullanıcı Rolleri

### 🔴 Admin
- Tüm yetkilere sahip
- Kullanıcıları banlama
- Moderator atama
- Sistem istatistiklerini görme

### 🟡 Moderator
- Şikayetleri inceleme
- Entry silme/düzenleme
- Kullanıcıları uyarama/banlama

### 🟢 Normal Kullanıcı
- Entry girme/düzenleme/silme
- Beğeni ve takip
- Mesajlaşma
- Şikayet etme

## 📧 E-posta Doğrulama

Kayıt sırasında kullanıcılara doğrulama kodu gönderilir. E-posta ayarlarını yapılandırmadan önce:

1. Gmail'de "2 Adımlı Doğrulama" aktif edin
2. "Uygulama Şifreleri" oluşturun
3. Bu şifreyi `MAIL_PASSWORD` olarak kullanın

## 🔐 Güvenlik

- Şifreler SHA-256 ile hashlenir
- E-posta doğrulama zorunlu
- Admin/moderator yetki kontrolü
- SQL injection koruması
- XSS koruması

## 🎨 Arayüz

- Bootstrap 4 ile modern tasarım
- Font Awesome ikonları
- Responsive grid sistemi
- Kullanıcı dostu navigasyon

## 📱 Özellikler

### Arama
- Gerçek zamanlı arama
- Otomatik tamamlama
- Başlık ve entry sayısı gösterimi

### Paylaşma
- Native sharing API desteği
- Fallback kopyala-yapıştır
- Sosyal medya uyumlu

### Şikayet Sistemi
- Spam, uygunsuz içerik, taciz kategorileri
- Moderator inceleme süreci
- Otomatik bildirimler

## 🚀 Gelecek Özellikler

- [ ] Google OAuth entegrasyonu
- [ ] Resim yükleme
- [ ] Mobil uygulama
- [ ] API endpoints
- [ ] Çoklu dil desteği
- [ ] Gelişmiş arama filtreleri

## 📞 Destek

Sorunlarınız için issue açabilir veya pull request gönderebilirsiniz.

## 📄 Lisans

Bu proje MIT lisansı altında lisanslanmıştır. 