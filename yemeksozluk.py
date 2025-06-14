from flask import Flask, render_template, request, redirect, url_for, session, flash, g
import sqlite3
import hashlib
from datetime import datetime
import math # Sayfa sayısı hesaplamak için eklendi

app = Flask(__name__)
app.config['SECRET_KEY'] = 'cokgizlibirkey'
DATABASE = 'yemeksozluk.db'
ENTRIES_PER_PAGE = 10 # Her sayfada gösterilecek entry sayısı

def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    conn.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            email TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            bio TEXT DEFAULT '',
            kayit_tarihi TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.execute('''
        CREATE TABLE IF NOT EXISTS basliklar (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            baslik_adi TEXT NOT NULL UNIQUE
        )
    ''')
    conn.execute('''
        CREATE TABLE IF NOT EXISTS entryler (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            entry_metni TEXT NOT NULL,
            baslik_id INTEGER NOT NULL,
            yazar_id INTEGER NOT NULL,
            tarih TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
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
            type TEXT NOT NULL,       -- 'like', 'follow', 'message' (şimdilik bu 3 tip)
            content TEXT NOT NULL,    -- Bildirim metni
            link TEXT,                -- Bildirime tıklayınca gidilecek link (örn: entry'nin veya profilin linki)
            is_read INTEGER DEFAULT 0, -- 0: okunmadı, 1: okundu
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (sender_id) REFERENCES users(id)
        )
    ''')
    # Messages tablosu (YENİ EKLENDİ)
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
    conn.commit()
    conn.close()

with app.app_context():
    init_db()

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def is_logged_in():
    return 'logged_in' in session and session['logged_in']

# Bildirim ekleme fonksiyonu
def add_notification(user_id, sender_id, type, content, link=None):
    conn = get_db_connection()
    conn.execute('INSERT INTO notifications (user_id, sender_id, type, content, link) VALUES (?, ?, ?, ?, ?)',
                 (user_id, sender_id, type, content, link))
    conn.commit()
    conn.close()

# Her istek öncesi okunmamış bildirim ve mesaj sayısını almak için (GÜNCELLENDİ)
@app.before_request
def before_request():
    g.unread_notifications_count = 0
    g.unread_messages_count = 0
    if is_logged_in():
        conn = get_db_connection()
        user_id = session['user_id']
        
        # Okunmamış bildirim sayısı
        notifications_count = conn.execute('SELECT COUNT(*) FROM notifications WHERE user_id = ? AND is_read = 0', (user_id,)).fetchone()[0]
        g.unread_notifications_count = notifications_count

        # Okunmamış mesaj sayısı
        messages_count = conn.execute('SELECT COUNT(*) FROM messages WHERE receiver_id = ? AND is_read = 0', (user_id,)).fetchone()[0]
        g.unread_messages_count = messages_count
        
        conn.close()

@app.route('/')
def index():
    conn = get_db_connection()
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
    conn.close()
    return render_template('index.html', gundem=gundem, son=son, is_logged_in=is_logged_in())

@app.route('/baslik/<int:baslik_id>')
@app.route('/baslik/<int:baslik_id>/<int:page>')
def baslik_detay(baslik_id, page=1):
    conn = get_db_connection()
    baslik = conn.execute('SELECT * FROM basliklar WHERE id = ?', (baslik_id,)).fetchone()
    if baslik is None:
        conn.close()
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

    conn.close()
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

        conn = get_db_connection()
        try:
            conn.execute('INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)', 
                         (username, email, password_hash))
            conn.commit()
            flash('Kaydınız başarıyla oluşturuldu, şimdi giriş yapabilirsiniz!', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Kullanıcı adı veya e-posta zaten mevcut.', 'error')
            return render_template('register.html', username=username, email=email)
        finally:
            conn.close()
    return render_template('register.html', username='', email='')

@app.route('/giris_yap', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        conn.close()

        if user and user['password_hash'] == hash_password(password):
            session['logged_in'] = True
            session['user_id'] = user['id']
            session['username'] = user['username']
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

        conn = get_db_connection()
        baslik = conn.execute('SELECT * FROM basliklar WHERE baslik_adi = ? COLLATE NOCASE', (arama_terimi,)).fetchone()
        if baslik:
            conn.close()
            return redirect(url_for('baslik_detay', baslik_id=baslik['id']))
        else:
            conn.close()
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

        if any(c.isupper() for c in baslik_adi):
            flash("Başlık yalnızca küçük harf içermelidir.", 'error')
            return render_template('yeni_baslik.html', default_baslik_adi=baslik_adi)

        conn = get_db_connection()
        try:
            existing_baslik = conn.execute('SELECT id FROM basliklar WHERE baslik_adi = ? COLLATE NOCASE', (baslik_adi,)).fetchone()
            if existing_baslik:
                flash("Bu başlık zaten mevcut! Lütfen farklı bir başlık deneyin.", 'error')
                return render_template('yeni_baslik.html', default_baslik_adi=baslik_adi)

            conn.execute('INSERT INTO basliklar (baslik_adi) VALUES (?)', (baslik_adi,))
            conn.commit()
            yeni_baslik_id = conn.execute('SELECT id FROM basliklar WHERE baslik_adi = ?', (baslik_adi,)).fetchone()[0]
            conn.close()
            flash('Başlık başarıyla oluşturuldu, şimdi ilk entrynizi girebilirsiniz!', 'success')
            return redirect(url_for('yeni_entry', baslik_id=yeni_baslik_id))
        except sqlite3.IntegrityError:
            conn.close()
            flash("Bu başlık zaten mevcut! Lütfen farklı bir başlık deneyin.", 'error')
            return render_template('yeni_baslik.html', default_baslik_adi=baslik_adi)
    return render_template('yeni_baslik.html', default_baslik_adi='')

@app.route('/yeni_entry/<int:baslik_id>', methods=['GET', 'POST'])
def yeni_entry(baslik_id):
    if not is_logged_in():
        flash('Entry girmek için giriş yapmalısınız.', 'warning')
        return redirect(url_for('login'))

    conn = get_db_connection()
    baslik = conn.execute('SELECT * FROM basliklar WHERE id = ?', (baslik_id,)).fetchone()
    if baslik is None:
        conn.close()
        flash('Başlık bulunamadı!', 'error')
        return redirect(url_for('index'))

    if request.method == 'POST':
        entry_metni = request.form['entry_metni'].strip()
        yazar_id = session['user_id']

        if not entry_metni:
            flash("Entry metni boş olamaz!", 'error')
            conn.close()
            return render_template('yeni_entry.html', baslik=baslik)

        if any(c.isupper() for c in entry_metni):
            flash("Entry yalnızca küçük harf içermelidir.", 'error')
            conn.close()
            return render_template('yeni_entry.html', baslik=baslik)

        conn.execute('INSERT INTO entryler (entry_metni, baslik_id, yazar_id) VALUES (?, ?, ?)', 
                     (entry_metni, baslik_id, yazar_id))
        conn.commit()
        conn.close()
        flash('Entry başarıyla eklendi!', 'success')
        return redirect(url_for('baslik_detay', baslik_id=baslik_id))
    conn.close()
    return render_template('yeni_entry.html', baslik=baslik)

@app.route('/profil/<username>')
def profil(username):
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
    if not user:
        flash('Kullanıcı bulunamadı!', 'error')
        conn.close()
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
        SELECT e.id, e.entry_metni, e.tarih, b.baslik_adi, b.id as baslik_id, u.username
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

    conn.close()
    return render_template('profil.html', user=user, entryler=entry_list,
                           is_logged_in=is_logged_in(), is_following=is_following)

@app.route('/profil_duzenle', methods=['GET', 'POST'])
def profil_duzenle():
    if not is_logged_in():
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    
    if request.method == 'POST':
        yeni_bio = request.form['bio']
        conn.execute('UPDATE users SET bio = ? WHERE id = ?', (yeni_bio, session['user_id']))
        conn.commit()
        conn.close()
        flash('Profiliniz güncellendi!', 'success')
        return redirect(url_for('profil', username=session['username']))
    
    conn.close()
    return render_template('profil_duzenle.html', user=user)

@app.route('/takip_et/<int:user_id>')
def takip_et(user_id):
    if not is_logged_in():
        flash('Birini takip etmek için giriş yapmalısınız.', 'warning')
        return redirect(url_for('login'))

    if session['user_id'] == user_id:
        flash('Kendinizi takip edemezsiniz!', 'error')
        return redirect(url_for('profil', username=session['username']))

    conn = get_db_connection()
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
    finally:
        conn.close()
        
    conn_temp = get_db_connection()
    followed_username_row = conn_temp.execute('SELECT username FROM users WHERE id = ?', (user_id,)).fetchone()
    conn_temp.close()
    if followed_username_row:
        return redirect(url_for('profil', username=followed_username_row['username']))
    else:
        return redirect(url_for('index'))

@app.route('/takipten_cik/<int:user_id>')
def takipten_cik(user_id):
    if not is_logged_in():
        flash('Birini takipten çıkmak için giriş yapmalısınız.', 'warning')
        return redirect(url_for('login'))

    conn = get_db_connection()
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
        conn.close()

    conn_temp = get_db_connection()
    unfollowed_username_row = conn_temp.execute('SELECT username FROM users WHERE id = ?', (user_id,)).fetchone()
    conn_temp.close()
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
    conn = get_db_connection()
    
    takip_edilen_entryler = conn.execute('''
        SELECT e.entry_metni, e.tarih, b.baslik_adi, b.id as baslik_id, u.username
        FROM entryler e
        JOIN basliklar b ON e.baslik_id = b.id
        JOIN users u ON e.yazar_id = u.id
        WHERE e.yazar_id IN (SELECT followed_id FROM follows WHERE follower_id = ?)
        ORDER BY e.tarih DESC
        LIMIT 20
    ''', (user_id,)).fetchall()
    
    conn.close()
    return render_template('takip_ettiklerim.html', takip_edilen_entryler=takip_edilen_entryler, is_logged_in=is_logged_in())

# Beğeni Rotaları
@app.route('/entry_begen/<int:entry_id>')
def entry_begen(entry_id):
    if not is_logged_in():
        flash('Entry beğenmek için giriş yapmalısınız.', 'warning')
        return redirect(url_for('login'))

    user_id = session['user_id']
    conn = get_db_connection()
    
    # Entry'nin varlığını ve yazarını kontrol et
    entry_info = conn.execute('SELECT yazar_id, baslik_id FROM entryler WHERE id = ?', (entry_id,)).fetchone()
    if not entry_info:
        conn.close()
        flash('Beğenmek istediğiniz entry bulunamadı.', 'error')
        return redirect(request.referrer or url_for('index'))

    entry_owner_id = entry_info['yazar_id']
    entry_baslik_id = entry_info['baslik_id']

    # Kendi entry'ni beğenmeyi engelle
    if user_id == entry_owner_id:
        flash('Kendi entrynizi beğenemezsiniz!', 'error')
        conn.close()
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
    finally:
        conn.close()
    
    return redirect(request.referrer or url_for('index'))

@app.route('/entry_begenmekten_vazgec/<int:entry_id>')
def entry_begenmekten_vazgec(entry_id):
    if not is_logged_in():
        flash('Beğeniyi kaldırmak için giriş yapmalısınız.', 'warning')
        return redirect(url_for('login'))

    user_id = session['user_id']
    conn = get_db_connection()

    try:
        conn.execute('DELETE FROM likes WHERE user_id = ? AND entry_id = ?', (user_id, entry_id))
        conn.commit()
        flash('Beğeni kaldırıldı.', 'info')
    finally:
        conn.close()
    
    return redirect(request.referrer or url_for('index'))

@app.route('/begenilenler')
def begenilenler():
    if not is_logged_in():
        flash('Beğendiğiniz entryleri görmek için giriş yapmalısınız.', 'warning')
        return redirect(url_for('login'))

    user_id = session['user_id']
    conn = get_db_connection()

    begenilen_entryler = conn.execute('''
        SELECT e.entry_metni, e.tarih, b.baslik_adi, b.id as baslik_id, u.username, e.id as entry_id
        FROM likes l
        JOIN entryler e ON l.entry_id = e.id
        JOIN basliklar b ON e.baslik_id = b.id
        JOIN users u ON e.yazar_id = u.id
        WHERE l.user_id = ?
        ORDER BY e.tarih DESC
    ''', (user_id,)).fetchall()

    conn.close()
    return render_template('begenilenler.html', begenilen_entryler=begenilen_entryler, is_logged_in=is_logged_in())

# Ayarlar ve Şifre Değiştirme Rotası
@app.route('/ayarlar', methods=['GET', 'POST'])
def ayarlar():
    if not is_logged_in():
        flash('Ayarlarınızı düzenlemek için giriş yapmalısınız.', 'warning')
        return redirect(url_for('login'))

    conn = get_db_connection()
    user_id = session['user_id']
    current_user = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()

    if request.method == 'POST':
        current_password = request.form['current_password']
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']

        # Mevcut şifreyi doğrula
        if hash_password(current_password) != current_user['password_hash']:
            flash('Mevcut şifreniz yanlış.', 'error')
            conn.close()
            return render_template('ayarlar.html')

        # Yeni şifreler eşleşiyor mu kontrol et
        if new_password != confirm_password:
            flash('Yeni şifreler eşleşmiyor.', 'error')
            conn.close()
            return render_template('ayarlar.html')
        
        # Yeni şifrenin boş olup olmadığını kontrol et
        if not new_password:
            flash('Yeni şifre boş olamaz.', 'error')
            conn.close()
            return render_template('ayarlar.html')

        # Yeni şifreyi hashle ve güncelle
        hashed_new_password = hash_password(new_password)
        conn.execute('UPDATE users SET password_hash = ? WHERE id = ?', (hashed_new_password, user_id))
        conn.commit()
        conn.close()
        flash('Şifreniz başarıyla değiştirildi!', 'success')
        return redirect(url_for('profil', username=session['username']))

    conn.close()
    return render_template('ayarlar.html')

# Bildirimler Rotası
@app.route('/bildirimler')
def bildirimler():
    if not is_logged_in():
        flash('Bildirimleri görmek için giriş yapmalısınız.', 'warning')
        return redirect(url_for('login'))

    user_id = session['user_id']
    conn = get_db_connection()
    
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
    conn.close()

    return render_template('bildirimler.html', notifications=notifications, is_logged_in=is_logged_in())

# Mesajlaşma Rotaları (YENİ EKLENDİ)
@app.route('/mesajlar')
def mesajlar():
    if not is_logged_in():
        flash('Mesajları görmek için giriş yapmalısınız.', 'warning')
        return redirect(url_for('login'))

    user_id = session['user_id']
    conn = get_db_connection()

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

    conn.close()
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

    conn = get_db_connection()
    other_user = conn.execute('SELECT id, username FROM users WHERE id = ?', (other_user_id,)).fetchone()

    if not other_user:
        flash('Mesaj göndermek istediğiniz kullanıcı bulunamadı.', 'error')
        conn.close()
        return redirect(url_for('mesajlar'))

    if request.method == 'POST':
        message_text = request.form['message_text'].strip()
        if not message_text:
            flash('Mesaj boş olamaz!', 'error')
            conn.close()
            return redirect(url_for('sohbet', other_user_id=other_user_id))
        
        conn.execute('INSERT INTO messages (sender_id, receiver_id, message_text) VALUES (?, ?, ?)',
                     (user_id, other_user_id, message_text))
        conn.commit()

        # Mesaj bildirimi ekle
        add_notification(other_user_id, user_id, 'message', 
                         f"{session['username']} size bir mesaj gönderdi.", 
                         url_for('sohbet', other_user_id=user_id)) # Bildirime tıklayınca o sohbet sayfasına gider

        flash('Mesajınız gönderildi.', 'success')
        conn.close()
        return redirect(url_for('sohbet', other_user_id=other_user_id))

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
    conn.close()

    return render_template('sohbet.html', messages=messages, other_user=other_user, is_logged_in=is_logged_in())

if __name__ == '__main__':
    app.run(debug=True)
