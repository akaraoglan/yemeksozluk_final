#!/usr/bin/env python3
import sqlite3
import hashlib

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def create_admin():
    conn = sqlite3.connect('yemeksozluk.db')
    
    # Admin kullanıcısı oluştur
    admin_username = 'admin'
    admin_email = 'admin@yemeksozluk.com'
    admin_password = 'admin123'  # Güvenli bir şifre kullanın!
    
    try:
        conn.execute('''
            INSERT INTO users (username, email, password_hash, email_verified, is_admin, is_moderator)
            VALUES (?, ?, ?, 1, 1, 1)
        ''', (admin_username, admin_email, hash_password(admin_password)))
        conn.commit()
        print(f"Admin kullanıcısı oluşturuldu!")
        print(f"Kullanıcı adı: {admin_username}")
        print(f"E-posta: {admin_email}")
        print(f"Şifre: {admin_password}")
        print("Lütfen giriş yaptıktan sonra şifrenizi değiştirin!")
    except sqlite3.IntegrityError:
        print("Admin kullanıcısı zaten mevcut!")
    finally:
        conn.close()

if __name__ == '__main__':
    create_admin() 