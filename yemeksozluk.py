from flask import Flask, render_template, request, redirect, url_for, session, flash, g, jsonify
import sqlite3
import hashlib
from datetime import datetime, timedelta
import math # Sayfa sayısı hesaplamak için eklendi
import secrets
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from contextlib import contextmanager

app = Flask(__name__)
app.config['SECRET_KEY'] = 'cokgizlibirkey'
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'your-email@gmail.com'  # Gmail adresiniz
app.config['MAIL_PASSWORD'] = 'your-app-password'     # Gmail uygulama şifresi
DATABASE = 'yemeksozluk.db'
ENTRIES_PER_PAGE = 10 # Her sayfada gösterilecek entry sayısı

@contextmanager
def get_db_connection():
    conn = sqlite3.connect(DATABASE, timeout=20.0)
    conn.row_factory = sqlite3.Row
    # Enable foreign key support
    conn.execute('PRAGMA foreign_keys = ON')
    try:
        yield conn
    finally:
        conn.close()

def init_db():
    with get_db_connection() as conn:
        conn.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                email TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                bio TEXT DEFAULT '',
                kayit_tarihi TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                email_verified INTEGER DEFAULT 0,
                verification_code TEXT,
                is_admin INTEGER DEFAULT 0,
                is_moderator INTEGER DEFAULT 0,
                is_banned INTEGER DEFAULT 0
            )
        ''')
        conn.execute('''
            CREATE TABLE IF NOT EXISTS basliklar (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                baslik_adi TEXT NOT NULL UNIQUE,
                entry_count INTEGER DEFAULT 0
            )
        ''')
        conn.execute('''
            CREATE TABLE IF NOT EXISTS entryler (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                entry_metni TEXT NOT NULL,
                baslik_id INTEGER NOT NULL,
                yazar_id INTEGER NOT NULL,
                tarih TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                is_deleted INTEGER DEFAULT 0,
                FOREIGN KEY (baslik_id) REFERENCES basliklar(id),
                FOREIGN KEY (yazar_id) REFERENCES users(id)
            )
        ''')
        conn.execute('''
            CREATE TABLE IF NOT EXISTS follows (
                follower_id INTEGER NOT NULL,
                followed_id INTEGER NOT NULL,
                PRIMARY KEY (follower_id, followed_id),
                FOREIGN KEY (follower_id) REFERENCES users(id),
                FOREIGN KEY (followed_id) REFERENCES users(id)
            )
        ''')
        # Likes tablosu
        conn.execute('''
            CREATE TABLE IF NOT EXISTS likes (
                user_id INTEGER NOT NULL,
                entry_id INTEGER NOT NULL,
                PRIMARY KEY (user_id, entry_id),
                FOREIGN KEY (user_id) REFERENCES users(id),
                FOREIGN KEY (entry_id) REFERENCES entryler(id)
            )
        ''')
        # Notifications tablosu
        conn.execute('''
            CREATE TABLE IF NOT EXISTS notifications (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL, -- Bildirimi alacak kullanıcı
                sender_id INTEGER,        -- Bildirimi yapan kullanıcı (opsiyonel, örn: beğenen/takip eden)
                type TEXT NOT NULL,       -- 'like', 'follow', 'message', 'report', 'admin_action'
                content TEXT NOT NULL,    -- Bildirim metni
                link TEXT,                -- Bildirime tıklayınca gidilecek link (örn: entry'nin veya profilin linki)
                is_read INTEGER DEFAULT 0, -- 0: okunmadı, 1: okundu
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id),
                FOREIGN KEY (sender_id) REFERENCES users(id)
            )
        ''')
        # Messages tablosu
        conn.execute('''
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sender_id INTEGER NOT NULL,
                receiver_id INTEGER NOT NULL,
                message_text TEXT NOT NULL,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                is_read INTEGER DEFAULT 0, -- 0: okunmadı, 1: okundu
                FOREIGN KEY (sender_id) REFERENCES users(id),
                FOREIGN KEY (receiver_id) REFERENCES users(id)
            )
        ''')
        # Reports tablosu (YENİ)
        conn.execute('''
            CREATE TABLE IF NOT EXISTS reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                reporter_id INTEGER NOT NULL,
                entry_id INTEGER NOT NULL,
                report_type TEXT NOT NULL, -- 'spam', 'inappropriate', 'harassment', 'other'
                report_reason TEXT NOT NULL,
                status TEXT DEFAULT 'pending', -- 'pending', 'reviewed', 'resolved'
                moderator_id INTEGER,
                action_taken TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (reporter_id) REFERENCES users(id),
                FOREIGN KEY (entry_id) REFERENCES entryler(id),
                FOREIGN KEY (moderator_id) REFERENCES users(id)
            )
        ''')
        # Password reset tokens tablosu (YENİ)
        conn.execute('''
            CREATE TABLE IF NOT EXISTS password_reset_tokens (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                token TEXT NOT NULL UNIQUE,
                expires_at DATETIME NOT NULL,
                used INTEGER DEFAULT 0,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        ''')
        conn.commit()

with app.app_context():
    init_db()

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def is_logged_in():
    return 'logged_in' in session and session['logged_in']

# Bildirim ekleme fonksiyonu
def add_notification(user_id, sender_id, type, content, link=None):
    with get_db_connection() as conn:
        conn.execute('INSERT INTO notifications (user_id, sender_id, type, content, link) VALUES (?, ?, ?, ?, ?)',
                     (user_id, sender_id, type, content, link))
        conn.commit()

# Her istek öncesi okunmamış bildirim ve mesaj sayısını almak için (GÜNCELLENDİ)
@app.before_request
def before_request():
    g.unread_notifications_count = 0
    g.unread_messages_count = 0
    if is_logged_in():
        with get_db_connection() as conn:
            user_id = session['user_id']
            
            # Okunmamış bildirim sayısı
            notifications_count = conn.execute('SELECT COUNT(*) FROM notifications WHERE user_id = ? AND is_read = 0', (user_id,)).fetchone()[0]
            g.unread_notifications_count = notifications_count

            # Okunmamış mesaj sayısı
            messages_count = conn.execute('SELECT COUNT(*) FROM messages WHERE receiver_id = ? AND is_read = 0', (user_id,)).fetchone()[0]
            g.unread_messages_count = messages_count
            

@app.route('/')
def index():
    with get_db_connection() as conn:
        gundem = conn.execute('''
            SELECT b.id, b.baslik_adi, COUNT(e.id) as entry_sayisi
            FROM basliklar b
            LEFT JOIN entryler e ON b.id = e.baslik_id
            GROUP BY b.id
            ORDER BY entry_sayisi DESC
            LIMIT 10
        ''').fetchall()

        son = conn.execute('''
            SELECT b.id, b.baslik_adi
            FROM basliklar b
            JOIN entryler e ON b.id = e.baslik_id
            GROUP BY b.id, b.baslik_adi
            ORDER BY MAX(e.tarih) DESC
            LIMIT 10
        ''').fetchall()
        
        # İstatistikleri hesapla
        baslik_sayisi = conn.execute('SELECT COUNT(*) FROM basliklar').fetchone()[0]
        entry_sayisi = conn.execute('SELECT COUNT(*) FROM entryler').fetchone()[0]
        kullanici_sayisi = conn.execute('SELECT COUNT(*) FROM users').fetchone()[0]
        
        stats = {
            'baslik_sayisi': baslik_sayisi,
            'entry_sayisi': entry_sayisi,
            'kullanici_sayisi': kullanici_sayisi
        }
        
    return render_template('index.html', gundem=gundem, son=son, stats=stats, is_logged_in=is_logged_in())

@app.route('/baslik/<int:baslik_id>')
@app.route('/baslik/<int:baslik_id>/<int:page>')
def baslik_detay(baslik_id, page=1):
    with get_db_connection() as conn:
        baslik = conn.execute('SELECT * FROM basliklar WHERE id = ?', (baslik_id,)).fetchone()
        if baslik is None:
            flash('Başlık bulunamadı!', 'error')
            return redirect(url_for('index'))

        total_entries_count = conn.execute('SELECT COUNT(id) FROM entryler WHERE baslik_id = ?', (baslik_id,)).fetchone()[0]
        total_pages = math.ceil(total_entries_count / ENTRIES_PER_PAGE)

        if page < 1:
            page = 1
        elif page > total_pages and total_pages > 0:
            page = total_pages
        elif total_entries_count == 0:
            page = 1
        
        offset = (page - 1) * ENTRIES_PER_PAGE

        entryler_data = conn.execute(f'''
            SELECT e.*, u.username 
            FROM entryler e
            JOIN users u ON e.yazar_id = u.id
            WHERE e.baslik_id = ? 
            ORDER BY e.tarih ASC
            LIMIT {ENTRIES_PER_PAGE} OFFSET {offset}
        ''', (baslik_id,)).fetchall()

        entry_list = []
        if is_logged_in():
            user_id = session['user_id']
            for entry in entryler_data:
                liked = conn.execute('SELECT 1 FROM likes WHERE user_id = ? AND entry_id = ?', 
                                     (user_id, entry['id'])).fetchone() is not None
                entry_dict = dict(entry) # Row objesini dict'e çevir
                entry_dict['liked_by_user'] = liked
                entry_list.append(entry_dict)
        else:
            for entry in entryler_data:
                entry_dict = dict(entry)
                entry_dict['liked_by_user'] = False
                entry_list.append(entry_dict)

    return render_template('baslik_detay.html', 
                           baslik=baslik, 
                           entryler=entry_list, 
                           is_logged_in=is_logged_in(),
                           current_page=page,
                           total_pages=total_pages,
                           baslik_id=baslik_id)

@app.route('/kayit_ol', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']

        if not username or not email or not password:
            flash('Lütfen tüm alanları doldurun!', 'error')
            return render_template('register.html', username=username, email=email)

        password_hash = hash_password(password)

        with get_db_connection() as conn:
            try:
                conn.execute('INSERT INTO users (username, email, password_hash, email_verified) VALUES (?, ?, ?, 1)', 
                             (username, email, password_hash))
                conn.commit()
                
                flash('Kaydınız başarıyla oluşturuldu! Şimdi giriş yapabilirsiniz.', 'success')
                return redirect(url_for('login'))
                
            except sqlite3.IntegrityError:
                flash('Kullanıcı adı veya e-posta zaten mevcut.', 'error')
                return render_template('register.html', username=username, email=email)

    return render_template('register.html', username='', email='')

@app.route('/password_reset_request', methods=['GET', 'POST'])
def password_reset_request():
    if request.method == 'POST':
        email = request.form['email']
        
        with get_db_connection() as conn:
            user = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
            
            if user:
                # Eski token'ları temizle
                conn.execute('DELETE FROM password_reset_tokens WHERE user_id = ?', (user['id'],))
                
                # Yeni token oluştur
                reset_token = generate_reset_token()
                expires_at = datetime.now() + timedelta(hours=1)
                
                conn.execute('INSERT INTO password_reset_tokens (user_id, token, expires_at) VALUES (?, ?, ?)',
                            (user['id'], reset_token, expires_at))
                conn.commit()
                
                # Şifre sıfırlama e-postası gönder
                if send_password_reset_email(email, user['username'], reset_token):
                    flash('Şifre sıfırlama linki e-posta adresinize gönderildi.', 'success')
                else:
                    flash('E-posta gönderilemedi. Lütfen daha sonra tekrar deneyin.', 'error')
            else:
                flash('Bu e-posta adresi ile kayıtlı kullanıcı bulunamadı.', 'error')
    
    return render_template('password_reset_request.html')

@app.route('/password_reset_confirm/<token>', methods=['GET', 'POST'])
def password_reset_confirm(token):
    with get_db_connection() as conn:
        reset_token = conn.execute('''
            SELECT prt.*, u.username 
            FROM password_reset_tokens prt
            JOIN users u ON prt.user_id = u.id
            WHERE prt.token = ? AND prt.expires_at > ? AND prt.used = 0
        ''', (token, datetime.now())).fetchone()
        
        if not reset_token:
            flash('Geçersiz veya süresi dolmuş şifre sıfırlama linki.', 'error')
            return redirect(url_for('login'))
        
        if request.method == 'POST':
            new_password = request.form['new_password']
            confirm_password = request.form['confirm_password']
            
            if new_password != confirm_password:
                flash('Şifreler eşleşmiyor!', 'error')
                return render_template('password_reset_confirm.html', token=token)
            
            if len(new_password) < 6:
                flash('Şifre en az 6 karakter olmalıdır!', 'error')
                return render_template('password_reset_confirm.html', token=token)
            
            # Şifreyi güncelle
            password_hash = hash_password(new_password)
            conn.execute('UPDATE users SET password_hash = ? WHERE id = ?', (password_hash, reset_token['user_id']))
            conn.execute('UPDATE password_reset_tokens SET used = 1 WHERE id = ?', (reset_token['id'],))
            conn.commit()
            
            flash('Şifreniz başarıyla güncellendi!', 'success')
            return redirect(url_for('login'))
        
    return render_template('password_reset_confirm.html', token=token)

@app.route('/giris_yap', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        with get_db_connection() as conn:
            user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()

        if user and user['password_hash'] == hash_password(password):
            # Ban kontrolü
            if user['is_banned']:
                flash('Hesabınız askıya alınmıştır. Lütfen yönetici ile iletişime geçin.', 'error')
                return render_template('login.html')
            
            session['logged_in'] = True
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['is_admin'] = user['is_admin']
            session['is_moderator'] = user['is_moderator']
            flash('Başarıyla giriş yaptınız!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Kullanıcı adı veya şifre hatalı.', 'error')
    return render_template('login.html')

@app.route('/cikis_yap')
def logout():
    session.clear()
    flash('Başarıyla çıkış yaptınız!', 'success')
    return redirect(url_for('index'))

@app.route('/arama', methods=['GET', 'POST'])
def arama():
    if request.method == 'POST':
        arama_terimi = request.form['arama_terimi'].strip()
        if not arama_terimi:
            flash('Arama terimi boş olamaz!', 'error')
            return redirect(url_for('index'))

        with get_db_connection() as conn:
            baslik = conn.execute('SELECT * FROM basliklar WHERE baslik_adi = ? COLLATE NOCASE', (arama_terimi,)).fetchone()
            if baslik:
                return redirect(url_for('baslik_detay', baslik_id=baslik['id']))
            else:
                flash(f"'{arama_terimi}' başlıklı içerik bulunamadı. Yeni bir başlık oluşturabilirsiniz.", 'info')
                return render_template('yeni_baslik.html', default_baslik_adi=arama_terimi)
    return redirect(url_for('index'))

@app.route('/yeni_baslik', methods=['GET', 'POST'])
def yeni_baslik():
    if not is_logged_in():
        flash('Yeni başlık oluşturmak için giriş yapmalısınız.', 'warning')
        return redirect(url_for('login'))

    if request.method == 'POST':
        baslik_adi = request.form['baslik_adi'].strip()

        if not baslik_adi:
            flash("Başlık adı boş olamaz!", 'error')
            return render_template('yeni_baslik.html', default_baslik_adi=baslik_adi)

        # Büyük harfleri küçük harfe çevir
        baslik_adi = baslik_adi.lower()

        with get_db_connection() as conn:
            try:
                existing_baslik = conn.execute('SELECT id FROM basliklar WHERE baslik_adi = ? COLLATE NOCASE', (baslik_adi,)).fetchone()
                if existing_baslik:
                    flash("Bu başlık zaten mevcut! Lütfen farklı bir başlık deneyin.", 'error')
                    return render_template('yeni_baslik.html', default_baslik_adi=baslik_adi)

                # Başlığı oluştur
                conn.execute('INSERT INTO basliklar (baslik_adi) VALUES (?)', (baslik_adi,))
                conn.commit()
                yeni_baslik_id = conn.execute('SELECT id FROM basliklar WHERE baslik_adi = ?', (baslik_adi,)).fetchone()[0]
                
                flash('Başlık başarıyla oluşturuldu! Şimdi ilk entrynizi girebilirsiniz.', 'success')
                return redirect(url_for('yeni_entry', baslik_id=yeni_baslik_id))
                
            except sqlite3.IntegrityError:
                flash("Bu başlık zaten mevcut! Lütfen farklı bir başlık deneyin.", 'error')
                return render_template('yeni_baslik.html', default_baslik_adi=baslik_adi)
    return render_template('yeni_baslik.html', default_baslik_adi='')

@app.route('/yeni_entry/<int:baslik_id>', methods=['GET', 'POST'])
def yeni_entry(baslik_id):
    if not is_logged_in():
        flash('Entry girmek için giriş yapmalısınız.', 'warning')
        return redirect(url_for('login'))

    with get_db_connection() as conn:
        baslik = conn.execute('SELECT * FROM basliklar WHERE id = ?', (baslik_id,)).fetchone()
        if baslik is None:
            flash('Başlık bulunamadı!', 'error')
            return redirect(url_for('index'))

        if request.method == 'POST':
            entry_metni = request.form['entry_metni'].strip()
            yazar_id = session['user_id']

            if not entry_metni:
                flash("Entry metni boş olamaz!", 'error')
                return render_template('yeni_entry.html', baslik=baslik)

            # Büyük harfleri küçük harfe çevir
            entry_metni = entry_metni.lower()

            conn.execute('INSERT INTO entryler (entry_metni, baslik_id, yazar_id) VALUES (?, ?, ?)', 
                         (entry_metni, baslik_id, yazar_id))
            conn.commit()
            
            flash('Entry başarıyla eklendi!', 'success')
            return redirect(url_for('baslik_detay', baslik_id=baslik_id))
    return render_template('yeni_entry.html', baslik=baslik)

@app.route('/profil/<username>')
def profil(username):
    with get_db_connection() as conn:
        user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        if not user:
            flash('Kullanıcı bulunamadı!', 'error')
            return redirect(url_for('index'))
        
        is_following = False
        if is_logged_in():
            # Kendi profili değilse takip durumunu kontrol et
            if session['user_id'] != user['id']:
                follow_check = conn.execute('SELECT 1 FROM follows WHERE follower_id = ? AND followed_id = ?',
                                             (session['user_id'], user['id'])).fetchone()
                if follow_check:
                    is_following = True

        # Kullanıcının entry'lerini çek
        entryler_data = conn.execute('''
            SELECT e.id, e.entry_metni, e.tarih, e.yazar_id, b.baslik_adi, b.id as baslik_id, u.username
            FROM entryler e
            JOIN basliklar b ON e.baslik_id = b.id
            JOIN users u ON e.yazar_id = u.id
            WHERE e.yazar_id = ?
            ORDER BY e.tarih DESC
            LIMIT 10
        ''', (user['id'],)).fetchall()

        entry_list = []
        if is_logged_in():
            current_user_id = session['user_id']
            for entry in entryler_data:
                liked = conn.execute('SELECT 1 FROM likes WHERE user_id = ? AND entry_id = ?', 
                                     (current_user_id, entry['id'])).fetchone() is not None
                entry_dict = dict(entry) # Row objesini dict'e çevir
                entry_dict['liked_by_user'] = liked
                entry_list.append(entry_dict)
        else:
            for entry in entryler_data:
                entry_dict = dict(entry)
                entry_dict['liked_by_user'] = False
                entry_list.append(entry_dict)

    return render_template('profil.html', user=user, entryler=entry_list,
                           is_logged_in=is_logged_in(), is_following=is_following)

@app.route('/profil_duzenle', methods=['GET', 'POST'])
def profil_duzenle():
    if not is_logged_in():
        return redirect(url_for('login'))
    
    with get_db_connection() as conn:
        user = conn.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
        
        if request.method == 'POST':
            yeni_bio = request.form['bio']
            conn.execute('UPDATE users SET bio = ? WHERE id = ?', (yeni_bio, session['user_id']))
            conn.commit()
            
            flash('Profiliniz güncellendi!', 'success')
            return redirect(url_for('profil', username=session['username']))
    
    return render_template('profil_duzenle.html', user=user)

@app.route('/takip_et/<int:user_id>')
def takip_et(user_id):
    if not is_logged_in():
        flash('Birini takip etmek için giriş yapmalısınız.', 'warning')
        return redirect(url_for('login'))

    if session['user_id'] == user_id:
        flash('Kendinizi takip edemezsiniz!', 'error')
        return redirect(url_for('profil', username=session['username']))

    with get_db_connection() as conn:
        try:
            conn.execute('INSERT INTO follows (follower_id, followed_id) VALUES (?, ?)',
                         (session['user_id'], user_id))
            conn.commit()
            
            followed_user = conn.execute('SELECT username FROM users WHERE id = ?', (user_id,)).fetchone()
            if followed_user:
                flash(f"{followed_user['username']} adlı kullanıcıyı takip etmeye başladınız.", 'success')
                # Takip bildirimi ekle
                add_notification(user_id, session['user_id'], 'follow', 
                                 f"{session['username']} sizi takip etmeye başladı.", 
                                 url_for('profil', username=session['username']))
            else:
                flash('Takip işlemi başarılı.', 'success')
            
        except sqlite3.IntegrityError:
            flash('Bu kullanıcıyı zaten takip ediyorsunuz.', 'info')
        
    with get_db_connection() as conn_temp:
        followed_username_row = conn_temp.execute('SELECT username FROM users WHERE id = ?', (user_id,)).fetchone()
    if followed_username_row:
        return redirect(url_for('profil', username=followed_username_row['username']))
    else:
        return redirect(url_for('index'))

@app.route('/takipten_cik/<int:user_id>')
def takipten_cik(user_id):
    if not is_logged_in():
        flash('Birini takipten çıkmak için giriş yapmalısınız.', 'warning')
        return redirect(url_for('login'))

    with get_db_connection() as conn:
        try:
            conn.execute('DELETE FROM follows WHERE follower_id = ? AND followed_id = ?',
                         (session['user_id'], user_id))
            conn.commit()

            unfollowed_user = conn.execute('SELECT username FROM users WHERE id = ?', (user_id,)).fetchone()
            if unfollowed_user:
                flash(f"{unfollowed_user['username']} adlı kullanıcıyı takipten çıktınız.", 'info')
            else:
                flash('Takipten çıkma işlemi başarılı.', 'info')

        finally:
            pass

    with get_db_connection() as conn_temp:
        unfollowed_username_row = conn_temp.execute('SELECT username FROM users WHERE id = ?', (user_id,)).fetchone()
    if unfollowed_username_row:
        return redirect(url_for('profil', username=unfollowed_username_row['username']))
    else:
        return redirect(url_for('index'))

@app.route('/takip_ettiklerim')
def takip_ettiklerim():
    if not is_logged_in():
        flash('Takip ettiklerinizi görmek için giriş yapmalısınız.', 'warning')
        return redirect(url_for('login'))

    user_id = session['user_id']
    with get_db_connection() as conn:
        takip_edilen_entryler_data = conn.execute('''
            SELECT e.entry_metni, e.tarih, b.baslik_adi, b.id as baslik_id, u.username, e.id as entry_id, e.yazar_id
            FROM entryler e
            JOIN basliklar b ON e.baslik_id = b.id
            JOIN users u ON e.yazar_id = u.id
            WHERE e.yazar_id IN (SELECT followed_id FROM follows WHERE follower_id = ?)
            ORDER BY e.tarih DESC
            LIMIT 20
        ''', (user_id,)).fetchall()
        
        # Beğeni bilgilerini ekle
        entry_list = []
        for entry in takip_edilen_entryler_data:
            liked = conn.execute('SELECT 1 FROM likes WHERE user_id = ? AND entry_id = ?', 
                                 (user_id, entry['entry_id'])).fetchone() is not None
            entry_dict = dict(entry)
            entry_dict['liked_by_user'] = liked
            entry_list.append(entry_dict)
    
    return render_template('takip_ettiklerim.html', takip_edilen_entryler=entry_list, is_logged_in=is_logged_in())

# Beğeni Rotaları
@app.route('/entry_begen/<int:entry_id>')
def entry_begen(entry_id):
    if not is_logged_in():
        flash('Entry beğenmek için giriş yapmalısınız.', 'warning')
        return redirect(url_for('login'))

    user_id = session['user_id']
    with get_db_connection() as conn:
        # Entry'nin varlığını ve yazarını kontrol et
        entry_info = conn.execute('SELECT yazar_id, baslik_id FROM entryler WHERE id = ?', (entry_id,)).fetchone()
        if not entry_info:
            flash('Beğenmek istediğiniz entry bulunamadı.', 'error')
            return redirect(request.referrer or url_for('index'))

        entry_owner_id = entry_info['yazar_id']
        entry_baslik_id = entry_info['baslik_id']

        # Kendi entry'ni beğenmeyi engelle
        if user_id == entry_owner_id:
            flash('Kendi entrynizi beğenemezsiniz!', 'error')
            return redirect(request.referrer or url_for('index'))

        try:
            conn.execute('INSERT INTO likes (user_id, entry_id) VALUES (?, ?)', (user_id, entry_id))
            conn.commit()
            flash('Entry beğenildi!', 'success')
            
            # Beğeni bildirimi ekle
            # Entry'nin sahibine bildirim gönderiyoruz
            liker_username = session['username']
            add_notification(entry_owner_id, user_id, 'like', 
                             f"{liker_username} entry'nizi beğendi.", 
                             url_for('baslik_detay', baslik_id=entry_baslik_id, _anchor=f'entry-{entry_id}')) # Entry'ye doğrudan yönlendir
        except sqlite3.IntegrityError:
            flash('Bu entryi zaten beğenmişsiniz.', 'info')
    
    return redirect(request.referrer or url_for('index'))

@app.route('/entry_begenmekten_vazgec/<int:entry_id>')
def entry_begenmekten_vazgec(entry_id):
    if not is_logged_in():
        flash('Beğeniyi kaldırmak için giriş yapmalısınız.', 'warning')
        return redirect(url_for('login'))

    user_id = session['user_id']
    with get_db_connection() as conn:
        try:
            conn.execute('DELETE FROM likes WHERE user_id = ? AND entry_id = ?', (user_id, entry_id))
            conn.commit()
            flash('Beğeni kaldırıldı.', 'info')
        finally:
            pass
    
    return redirect(request.referrer or url_for('index'))

@app.route('/begenilenler')
def begenilenler():
    if not is_logged_in():
        flash('Beğendiğiniz entryleri görmek için giriş yapmalısınız.', 'warning')
        return redirect(url_for('login'))

    user_id = session['user_id']
    with get_db_connection() as conn:
        begenilen_entryler = conn.execute('''
            SELECT e.entry_metni, e.tarih, b.baslik_adi, b.id as baslik_id, u.username, e.id as entry_id, e.yazar_id
            FROM likes l
            JOIN entryler e ON l.entry_id = e.id
            JOIN basliklar b ON e.baslik_id = b.id
            JOIN users u ON e.yazar_id = u.id
            WHERE l.user_id = ?
            ORDER BY e.tarih DESC
        ''', (user_id,)).fetchall()

    return render_template('begenilenler.html', begenilen_entryler=begenilen_entryler, is_logged_in=is_logged_in())

# Ayarlar ve Şifre Değiştirme Rotası
@app.route('/ayarlar', methods=['GET', 'POST'])
def ayarlar():
    if not is_logged_in():
        flash('Ayarlarınızı düzenlemek için giriş yapmalısınız.', 'warning')
        return redirect(url_for('login'))

    with get_db_connection() as conn:
        user_id = session['user_id']
        current_user = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()

        if request.method == 'POST':
            current_password = request.form['current_password']
            new_password = request.form['new_password']
            confirm_password = request.form['confirm_password']

            # Mevcut şifreyi doğrula
            if hash_password(current_password) != current_user['password_hash']:
                flash('Mevcut şifreniz yanlış.', 'error')
                return render_template('ayarlar.html', is_logged_in=is_logged_in())

            # Yeni şifreler eşleşiyor mu kontrol et
            if new_password != confirm_password:
                flash('Yeni şifreler eşleşmiyor.', 'error')
                return render_template('ayarlar.html', is_logged_in=is_logged_in())
            
            # Yeni şifrenin boş olup olmadığını kontrol et
            if not new_password:
                flash('Yeni şifre boş olamaz.', 'error')
                return render_template('ayarlar.html', is_logged_in=is_logged_in())

            # Yeni şifreyi hashle ve güncelle
            hashed_new_password = hash_password(new_password)
            conn.execute('UPDATE users SET password_hash = ? WHERE id = ?', (hashed_new_password, user_id))
            conn.commit()
            
            flash('Şifreniz başarıyla değiştirildi!', 'success')
            return redirect(url_for('profil', username=session['username']))

    return render_template('ayarlar.html', is_logged_in=is_logged_in())

# Bildirimler Rotası
@app.route('/bildirimler')
def bildirimler():
    if not is_logged_in():
        flash('Bildirimleri görmek için giriş yapmalısınız.', 'warning')
        return redirect(url_for('login'))

    user_id = session['user_id']
    with get_db_connection() as conn:
        notifications = conn.execute('''
            SELECT n.*, u.username as sender_username
            FROM notifications n
            LEFT JOIN users u ON n.sender_id = u.id
            WHERE n.user_id = ?
            ORDER BY n.timestamp DESC
        ''', (user_id,)).fetchall()

        # Bildirimleri okundu olarak işaretle
        conn.execute('UPDATE notifications SET is_read = 1 WHERE user_id = ? AND is_read = 0', (user_id,))
        conn.commit()

    return render_template('bildirimler.html', notifications=notifications, is_logged_in=is_logged_in())

# Mesajlaşma Rotaları (YENİ EKLENDİ)
@app.route('/mesajlar')
def mesajlar():
    if not is_logged_in():
        flash('Mesajları görmek için giriş yapmalısınız.', 'warning')
        return redirect(url_for('login'))

    user_id = session['user_id']
    with get_db_connection() as conn:
        # Kullanıcının gelen ve giden tüm mesajlaştığı kişileri bul
        # Son mesajı ve okunmamış mesaj sayısını getir
        conversations = conn.execute(f'''
            SELECT 
                CASE 
                    WHEN m.sender_id = ? THEN m.receiver_id 
                    ELSE m.sender_id 
                END AS other_user_id,
                MAX(m.timestamp) AS last_message_timestamp
            FROM messages m
            WHERE m.sender_id = ? OR m.receiver_id = ?
            GROUP BY other_user_id
            ORDER BY last_message_timestamp DESC
        ''', (user_id, user_id, user_id)).fetchall()

        conversation_list = []
        for conv in conversations:
            other_user_id = conv['other_user_id']
            other_user = conn.execute('SELECT id, username FROM users WHERE id = ?', (other_user_id,)).fetchone()
            
            if other_user:
                # Okunmamış mesaj sayısı (bu kullanıcıdan bana gelen ve okunmamış olanlar)
                unread_count = conn.execute('''
                    SELECT COUNT(*) FROM messages
                    WHERE sender_id = ? AND receiver_id = ? AND is_read = 0
                ''', (other_user_id, user_id)).fetchone()[0]

                # Son mesajı al
                last_message = conn.execute('''
                    SELECT message_text, sender_id FROM messages
                    WHERE (sender_id = ? AND receiver_id = ?) OR (sender_id = ? AND receiver_id = ?)
                    ORDER BY timestamp DESC
                    LIMIT 1
                ''', (user_id, other_user_id, other_user_id, user_id)).fetchone()

                conversation_list.append({
                    'other_user_id': other_user['id'],
                    'other_username': other_user['username'],
                    'unread_count': unread_count,
                    'last_message': last_message['message_text'] if last_message else 'Henüz mesaj yok.',
                    'last_message_sender': 'Siz' if last_message and last_message['sender_id'] == user_id else other_user['username'] if last_message else ''
                })

    return render_template('mesajlar.html', conversations=conversation_list, is_logged_in=is_logged_in())

@app.route('/mesajlar/<int:other_user_id>', methods=['GET', 'POST'])
def sohbet(other_user_id):
    if not is_logged_in():
        flash('Mesaj göndermek/almak için giriş yapmalısınız.', 'warning')
        return redirect(url_for('login'))

    user_id = session['user_id']
    if user_id == other_user_id:
        flash('Kendinize mesaj gönderemezsiniz.', 'error')
        return redirect(url_for('mesajlar'))

    with get_db_connection() as conn:
        other_user = conn.execute('SELECT id, username FROM users WHERE id = ?', (other_user_id,)).fetchone()

        if not other_user:
            flash('Mesaj göndermek istediğiniz kullanıcı bulunamadı.', 'error')
            return redirect(url_for('mesajlar'))

        entry_info = None
        entry_id = request.args.get('entry_id', type=int)
        if entry_id:
            entry_info = conn.execute('''
                SELECT e.id, e.entry_metni, b.baslik_adi, b.id as baslik_id
                FROM entryler e
                JOIN basliklar b ON e.baslik_id = b.id
                WHERE e.id = ?
            ''', (entry_id,)).fetchone()

        if request.method == 'POST':
            message_text = request.form['message_text'].strip()
            if not message_text:
                flash('Mesaj boş olamaz!', 'error')
                return redirect(url_for('sohbet', other_user_id=other_user_id, entry_id=entry_id) if entry_id else url_for('sohbet', other_user_id=other_user_id))
            # Eğer entry_id varsa ilk mesajın başına entry bilgisini ekle
            if entry_info and not conn.execute('''SELECT 1 FROM messages WHERE ((sender_id=? AND receiver_id=?) OR (sender_id=? AND receiver_id=?)) AND message_text LIKE ?''', (user_id, other_user_id, other_user_id, user_id, f'%Entry ID: {entry_info["id"]}%')).fetchone():
                message_text = f"[Entry ID: {entry_info['id']}] {entry_info['baslik_adi']} başlığı: {entry_info['entry_metni']}\n---\n" + message_text
            conn.execute('INSERT INTO messages (sender_id, receiver_id, message_text) VALUES (?, ?, ?)',
                         (user_id, other_user_id, message_text))
            conn.commit()

            # Mesaj bildirimi ekle
            add_notification(other_user_id, user_id, 'message', 
                             f"{session['username']} size bir mesaj gönderdi.", 
                             url_for('sohbet', other_user_id=user_id)) # Bildirime tıklayınca o sohbet sayfasına gider

            flash('Mesajınız gönderildi.', 'success')
            return redirect(url_for('sohbet', other_user_id=other_user_id, entry_id=entry_id) if entry_id else url_for('sohbet', other_user_id=other_user_id))

        # Gelen tüm mesajları ve gönderilen mesajları çek
        messages = conn.execute('''
            SELECT m.*, s.username as sender_username, r.username as receiver_username
            FROM messages m
            JOIN users s ON m.sender_id = s.id
            JOIN users r ON m.receiver_id = r.id
            WHERE (m.sender_id = ? AND m.receiver_id = ?) 
               OR (m.sender_id = ? AND m.receiver_id = ?)
            ORDER BY m.timestamp ASC
        ''', (user_id, other_user_id, other_user_id, user_id)).fetchall()

        # Gelen ve okunmamış mesajları okundu olarak işaretle
        conn.execute('UPDATE messages SET is_read = 1 WHERE receiver_id = ? AND sender_id = ? AND is_read = 0',
                     (user_id, other_user_id))
        conn.commit()

    return render_template('sohbet.html', messages=messages, other_user=other_user, is_logged_in=is_logged_in(), entry_info=entry_info)

# Entry Düzenleme Rotaları (YENİ EKLENDİ)
@app.route('/entry_duzenle/<int:entry_id>', methods=['GET', 'POST'])
def entry_duzenle(entry_id):
    if not is_logged_in():
        flash('Entry düzenlemek için giriş yapmalısınız.', 'warning')
        return redirect(url_for('login'))

    with get_db_connection() as conn:
        entry = conn.execute('''
            SELECT e.*, b.baslik_adi, b.id as baslik_id, u.username
            FROM entryler e
            JOIN basliklar b ON e.baslik_id = b.id
            JOIN users u ON e.yazar_id = u.id
            WHERE e.id = ?
        ''', (entry_id,)).fetchone()

        if entry is None:
            flash('Entry bulunamadı!', 'error')
            return redirect(url_for('index'))

        # Sadece entry'nin yazarı düzenleyebilir
        if entry['yazar_id'] != session['user_id']:
            flash('Bu entry\'yi düzenleme yetkiniz yok!', 'error')
            return redirect(url_for('baslik_detay', baslik_id=entry['baslik_id']))

        if request.method == 'POST':
            yeni_entry_metni = request.form['entry_metni'].strip()
            
            if not yeni_entry_metni:
                flash("Entry metni boş olamaz!", 'error')
                return render_template('entry_duzenle.html', entry=entry)

            # Büyük harfleri küçük harfe çevir
            yeni_entry_metni = yeni_entry_metni.lower()

            conn.execute('UPDATE entryler SET entry_metni = ? WHERE id = ?', 
                         (yeni_entry_metni, entry_id))
            conn.commit()
            
            flash('Entry başarıyla güncellendi!', 'success')
            return redirect(url_for('baslik_detay', baslik_id=entry['baslik_id']))

    return render_template('entry_duzenle.html', entry=entry)

@app.route('/entry_sil/<int:entry_id>')
def entry_sil(entry_id):
    if not is_logged_in():
        flash('Entry silmek için giriş yapmalısınız.', 'warning')
        return redirect(url_for('login'))

    with get_db_connection() as conn:
        entry = conn.execute('''
            SELECT e.*, b.baslik_adi, b.id as baslik_id
            FROM entryler e
            JOIN basliklar b ON e.baslik_id = b.id
            WHERE e.id = ?
        ''', (entry_id,)).fetchone()

        if entry is None:
            flash('Entry bulunamadı!', 'error')
            return redirect(url_for('index'))

        # Sadece entry'nin yazarı silebilir
        if entry['yazar_id'] != session['user_id']:
            flash('Bu entry\'yi silme yetkiniz yok!', 'error')
            return redirect(url_for('baslik_detay', baslik_id=entry['baslik_id']))

        # Entry'yi sil
        conn.execute('DELETE FROM entryler WHERE id = ?', (entry_id,))
        # Entry'ye ait beğenileri de sil
        conn.execute('DELETE FROM likes WHERE entry_id = ?', (entry_id,))
        conn.commit()
        
        flash('Entry başarıyla silindi!', 'success')
        return redirect(url_for('baslik_detay', baslik_id=entry['baslik_id']))

@app.route('/arama_ajax', methods=['POST'])
def arama_ajax():
    import json
    data = request.get_json()
    query = data.get('query', '').strip()
    
    if len(query) < 2:
        return jsonify({'results': []})
    
    with get_db_connection() as conn:
        results = conn.execute('''
            SELECT b.id, b.baslik_adi, COUNT(e.id) as entry_count
            FROM basliklar b
            LEFT JOIN entryler e ON b.id = e.baslik_id
            WHERE b.baslik_adi LIKE ? COLLATE NOCASE
            GROUP BY b.id, b.baslik_adi
            ORDER BY entry_count DESC, b.baslik_adi ASC
            LIMIT 10
        ''', (f'%{query}%',)).fetchall()
    
    search_results = []
    for result in results:
        search_results.append({
            'id': result['id'],
            'title': result['baslik_adi'],
            'entry_count': result['entry_count'],
            'url': url_for('baslik_detay', baslik_id=result['id'])
        })
    
    return jsonify({'results': search_results})

def send_email(to_email, subject, body):
    """E-posta gönderme fonksiyonu"""
    try:
        msg = MIMEMultipart()
        msg['From'] = app.config['MAIL_USERNAME']
        msg['To'] = to_email
        msg['Subject'] = subject
        
        msg.attach(MIMEText(body, 'html'))
        
        server = smtplib.SMTP(app.config['MAIL_SERVER'], app.config['MAIL_PORT'])
        server.starttls()
        server.login(app.config['MAIL_USERNAME'], app.config['MAIL_PASSWORD'])
        text = msg.as_string()
        server.sendmail(app.config['MAIL_USERNAME'], to_email, text)
        server.quit()
        return True
    except Exception as e:
        print(f"E-posta gönderme hatası: {e}")
        return False

def send_password_reset_email(email, username, reset_token):
    """Şifre sıfırlama e-postası gönderme"""
    reset_url = url_for('password_reset_confirm', token=reset_token, _external=True)
    subject = "Yemek Sözlük - Şifre Sıfırlama"
    body = f"""
    <html>
    <body>
        <h2>Şifre Sıfırlama Talebi</h2>
        <p>Merhaba {username},</p>
        <p>Şifrenizi sıfırlamak için aşağıdaki linke tıklayın:</p>
        <p><a href="{reset_url}" style="background-color: #007bff; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">Şifremi Sıfırla</a></p>
        <p>Bu link 1 saat geçerlidir.</p>
        <p>Eğer bu talebi siz yapmadıysanız, lütfen dikkate almayın.</p>
        <br>
        <p>Saygılarımızla,<br>Yemek Sözlük Ekibi</p>
    </body>
    </html>
    """
    return send_email(email, subject, body)

def generate_reset_token():
    """Şifre sıfırlama token'ı oluştur"""
    return secrets.token_urlsafe(32)

@app.route('/entry_sikayet/<int:entry_id>', methods=['GET', 'POST'])
def entry_sikayet(entry_id):
    if not is_logged_in():
        flash('Şikayet etmek için giriş yapmalısınız.', 'warning')
        return redirect(url_for('login'))

    with get_db_connection() as conn:
        entry = conn.execute('''
            SELECT e.*, b.baslik_adi, u.username
            FROM entryler e
            JOIN basliklar b ON e.baslik_id = b.id
            JOIN users u ON e.yazar_id = u.id
            WHERE e.id = ?
        ''', (entry_id,)).fetchone()

        if entry is None:
            flash('Entry bulunamadı!', 'error')
            return redirect(url_for('index'))

        if request.method == 'POST':
            report_type = request.form['report_type']
            report_reason = request.form['report_reason'].strip()

            if not report_reason:
                flash('Şikayet nedeni boş olamaz!', 'error')
                return render_template('entry_sikayet.html', entry=entry)

            # Şikayet kaydet
            conn.execute('''
                INSERT INTO reports (reporter_id, entry_id, report_type, report_reason)
                VALUES (?, ?, ?, ?)
            ''', (session['user_id'], entry_id, report_type, report_reason))
            conn.commit()

            # Moderator'lara bildirim gönder
            moderators = conn.execute('SELECT id FROM users WHERE is_moderator = 1 OR is_admin = 1').fetchall()
            for moderator in moderators:
                add_notification(moderator['id'], session['user_id'], 'report',
                               f"Yeni bir şikayet: {entry['username']} kullanıcısının entry'si şikayet edildi.",
                               url_for('moderator_panel'))

            flash('Şikayetiniz başarıyla gönderildi. Teşekkürler!', 'success')
            return redirect(url_for('baslik_detay', baslik_id=entry['baslik_id']))

    return render_template('entry_sikayet.html', entry=entry)

@app.route('/admin_panel')
def admin_panel():
    if not is_logged_in() or not session.get('is_admin'):
        flash('Bu sayfaya erişim yetkiniz yok!', 'error')
        return redirect(url_for('index'))

    with get_db_connection() as conn:
        # İstatistikler
        total_users = conn.execute('SELECT COUNT(*) FROM users').fetchone()[0]
        total_entries = conn.execute('SELECT COUNT(*) FROM entryler').fetchone()[0]
        total_reports = conn.execute('SELECT COUNT(*) FROM reports WHERE status = "pending"').fetchone()[0]
        
        # Son şikayetler
        recent_reports = conn.execute('''
            SELECT r.*, e.entry_metni, u1.username as reporter_username, u2.username as entry_author
            FROM reports r
            JOIN entryler e ON r.entry_id = e.id
            JOIN users u1 ON r.reporter_id = u1.id
            JOIN users u2 ON e.yazar_id = u2.id
            ORDER BY r.timestamp DESC
            LIMIT 10
        ''').fetchall()
    
    return render_template('admin_panel.html', 
                         total_users=total_users,
                         total_entries=total_entries,
                         total_reports=total_reports,
                         recent_reports=recent_reports,
                         is_logged_in=is_logged_in())

@app.route('/moderator_panel')
def moderator_panel():
    if not is_logged_in() or not (session.get('is_moderator') or session.get('is_admin')):
        flash('Bu sayfaya erişim yetkiniz yok!', 'error')
        return redirect(url_for('index'))

    with get_db_connection() as conn:
        # Bekleyen şikayetler
        pending_reports = conn.execute('''
            SELECT r.*, e.entry_metni, u1.username as reporter_username, u2.username as entry_author
            FROM reports r
            JOIN entryler e ON r.entry_id = e.id
            JOIN users u1 ON r.reporter_id = u1.id
            JOIN users u2 ON e.yazar_id = u2.id
            WHERE r.status = 'pending'
            ORDER BY r.timestamp DESC
        ''').fetchall()
    
    return render_template('moderator_panel.html', pending_reports=pending_reports, is_logged_in=is_logged_in())

@app.route('/moderator_action/<int:report_id>', methods=['POST'])
def moderator_action(report_id):
    if not is_logged_in() or not (session.get('is_moderator') or session.get('is_admin')):
        flash('Bu işlemi yapma yetkiniz yok!', 'error')
        return redirect(url_for('index'))

    action = request.form['action']
    moderator_note = request.form.get('moderator_note', '')

    with get_db_connection() as conn:
        report = conn.execute('''
            SELECT r.*, e.entry_metni, e.baslik_id, b.baslik_adi, u.username as entry_author, u.id as entry_author_id
            FROM reports r
            JOIN entryler e ON r.entry_id = e.id
            JOIN basliklar b ON e.baslik_id = b.id
            JOIN users u ON e.yazar_id = u.id
            WHERE r.id = ?
        ''', (report_id,)).fetchone()
        
        if not report:
            flash('Şikayet bulunamadı!', 'error')
            return redirect(url_for('moderator_panel'))

        if action == 'delete_entry':
            # Entry'yi sil
            conn.execute('UPDATE entryler SET is_deleted = 1 WHERE id = ?', (report['entry_id'],))
            action_taken = 'Entry silindi'
            
        elif action == 'warn_user':
            action_taken = 'Kullanıcı uyarıldı'
            
        elif action == 'ban_user':
            # Kullanıcıyı banla
            conn.execute('UPDATE users SET is_banned = 1 WHERE id = ?', (report['entry_author_id'],))
            action_taken = 'Kullanıcı banlandı'
            
        elif action == 'dismiss':
            action_taken = 'Şikayet reddedildi'
            
        else:
            flash('Geçersiz işlem!', 'error')
            return redirect(url_for('moderator_panel'))

        # Şikayeti güncelle
        conn.execute('''
            UPDATE reports 
            SET status = 'resolved', moderator_id = ?, action_taken = ?
            WHERE id = ?
        ''', (session['user_id'], action_taken, report_id))
        
        conn.commit()

    # Bildirimleri ayrı bağlantıda gönder
    if action in ['delete_entry', 'warn_user', 'ban_user']:
        notification_content = f"'{report['baslik_adi']}' başlığındaki entry'niz moderatör tarafından "
        
        if action == 'delete_entry':
            notification_content += "silindi."
        elif action == 'warn_user':
            notification_content += "uyarı aldı."
        elif action == 'ban_user':
            notification_content += "nedeniyle hesabınız askıya alınmıştır."
            
        if moderator_note:
            notification_content += f" Sebep: {moderator_note}"
        
        notification_link = url_for('bildirimler') if action != 'ban_user' else url_for('index')
        add_notification(report['entry_author_id'], session['user_id'], 'admin_action',
                       notification_content, notification_link)

    flash(f'İşlem başarıyla tamamlandı: {action_taken}', 'success')
    return redirect(url_for('moderator_panel'))

if __name__ == '__main__':
    app.run(debug=True)
