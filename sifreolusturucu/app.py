import re
import random
import string
import pymysql
from flask import Flask, render_template, request, redirect, url_for, session
from werkzeug.security import generate_password_hash, check_password_hash


app = Flask(__name__)
app.secret_key = 'supersecretkey'  # Oturumlar için gizli anahtar

#  Veritabanı bağlantı fonksiyonu
def get_db_connection():
    connection = pymysql.connect(
        host='localhost',
        user='root',
        password='Ranbo143',  
        db='passwords_db',
        cursorclass=pymysql.cursors.DictCursor
    )
    return connection

#  Şifre güç seviyesi kontrol fonksiyonu
def check_password_strength(password):
    if len(password) < 6:
        return "Kolay"
    elif re.search(r'[A-Za-z]', password) and re.search(r'\d', password):
        if len(password) >= 8 and re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            return "Zor"
        return "Orta"
    return "Kolay"

#  Rastgele şifre oluşturma fonksiyonu
def generate_password(length=12, use_lowercase=True, use_uppercase=True, use_digits=True, use_symbols=True):
    characters = ''
    if use_lowercase:
        characters += string.ascii_lowercase
    if use_uppercase:
        characters += string.ascii_uppercase
    if use_digits:
        characters += string.digits
    if use_symbols:
        characters += string.punctuation

    if not characters:
        return '', 'Seçim yapılmadı'

    password = ''.join(random.choice(characters) for _ in range(length))
    return password, check_password_strength(password)


#  Kullanıcı kayıt işlemi
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = generate_password_hash(request.form['password']) 

        connection = get_db_connection()
        cursor = connection.cursor()

        try:
            cursor.execute(
                "INSERT INTO users (username, email, password) VALUES (%s, %s, %s)",
                (username, email, password)
            )
            connection.commit()
            return redirect(url_for('login'))
        except pymysql.MySQLError:
            return "Kayıt başarısız. E-posta veya kullanıcı adı zaten mevcut."
        finally:
            cursor.close()
            connection.close()

    return render_template('register.html')

#  Kullanıcı giriş işlemi
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        connection = get_db_connection()
        cursor = connection.cursor()
        cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
        user = cursor.fetchone()
        cursor.close()
        connection.close()

        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            return redirect(url_for('index'))
        else:
            return "Hatalı giriş bilgileri!"

    return render_template('login.html')

#  Kullanıcı profil bilgileri 
@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    connection = get_db_connection()
    cursor = connection.cursor()
    cursor.execute("SELECT * FROM users WHERE id = %s", (session['user_id'],))
    user = cursor.fetchone()

    if request.method == 'POST':
        new_username = request.form['username']
        new_email = request.form['email']
        new_password = request.form.get('new_password')

        if new_password:
            hashed_password = generate_password_hash(new_password)
            cursor.execute(
                "UPDATE users SET username = %s, email = %s, password = %s WHERE id = %s",
                (new_username, new_email, hashed_password, session['user_id'])
            )
        else:
            cursor.execute(
                "UPDATE users SET username = %s, email = %s WHERE id = %s",
                (new_username, new_email, session['user_id'])
            )

        connection.commit()
        cursor.close()
        connection.close()
        return redirect(url_for('profile'))

    cursor.close()
    connection.close()
    return render_template('profile.html', user=user)

#  Ana Sayfa (Şifre oluşturma)
@app.route('/', methods=['GET', 'POST'])
def root():
    return redirect(url_for('home'))

@app.route('/index', methods=['GET', 'POST'])
def index():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    password = ''
    strength = ''

    if request.method == 'POST':
        use_lowercase = 'lowercase' in request.form
        use_uppercase = 'uppercase' in request.form
        use_digits = 'digits' in request.form
        use_symbols = 'symbols' in request.form
        length = int(request.form.get('length', 12))

        password, strength = generate_password(length, use_lowercase, use_uppercase, use_digits, use_symbols)

        if password:
            connection = get_db_connection()
            cursor = connection.cursor()
            cursor.execute(
                "INSERT INTO passwords (password, strength, user_id) VALUES (%s, %s, %s)",
                (password, strength, session['user_id'])
            )
            connection.commit()
            cursor.close()
            connection.close()

    return render_template('index.html', password=password, strength=strength)



#  Kullanıcı çıkış işlemi
@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect(url_for('login'))

#  Kullanıcının kayıtlı şifreleri görüntüleme
@app.route('/view_passwords')
def view_passwords():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    connection = get_db_connection()
    cursor = connection.cursor()
    cursor.execute("SELECT * FROM passwords WHERE user_id = %s", (session['user_id'],))
    passwords = cursor.fetchall()
    cursor.close()
    connection.close()

    return render_template('view_passwords.html', passwords=passwords)

#  Kullanıcının manuel şifre eklemesi
@app.route('/add_password', methods=['POST'])
def add_password():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    new_password = request.form['new_password']
    strength = check_password_strength(new_password)

    connection = get_db_connection()
    cursor = connection.cursor()
    cursor.execute(
        "INSERT INTO passwords (password, strength, user_id) VALUES (%s, %s, %s)",
        (new_password, strength, session['user_id'])
    )
    connection.commit()
    cursor.close()
    connection.close()

    return redirect(url_for('view_passwords'))

#  Kullanıcının şifre silmesi
@app.route('/delete_password/<int:password_id>', methods=['POST'])
def delete_password(password_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    connection = get_db_connection()
    cursor = connection.cursor()
    cursor.execute(
        "DELETE FROM passwords WHERE id = %s AND user_id = %s",
        (password_id, session['user_id'])
    )
    connection.commit()
    cursor.close()
    connection.close()

    return redirect(url_for('view_passwords'))

# Ana bilgi sayfası (Home)
@app.route('/home')
def home():
    return render_template('home.html')

ADMIN_EMAIL = "admin@gmail.com"
ADMIN_PASSWORD = "admin123"  

@app.route('/admin_login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        if email == ADMIN_EMAIL and password == ADMIN_PASSWORD:
            session['admin'] = True
            return redirect(url_for('admin_dashboard'))
        else:
            return "Admin girişi başarısız."

    return render_template('admin_login.html')


@app.route('/admin_dashboard')
def admin_dashboard():
    if 'admin' not in session:
        return redirect(url_for('admin_login'))

    connection = get_db_connection()
    cursor = connection.cursor()

    
    cursor.execute("SELECT id, username, email FROM users")
    users = cursor.fetchall()

   
    cursor.execute("""
        SELECT passwords.id, passwords.password, passwords.strength, users.username 
        FROM passwords 
        JOIN users ON passwords.user_id = users.id
    """)
    passwords = cursor.fetchall()

    cursor.close()
    connection.close()

    return render_template('admin_dashboard.html', users=users, passwords=passwords)

@app.route('/admin_logout')
def logout_admin():
    session.pop('admin', None)
    return redirect(url_for('admin_login'))
  
#  Flask uygulamasını çalıştır
if __name__ == '__main__':
    app.run(debug=True)
