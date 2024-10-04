from flask import Flask, render_template, redirect, url_for, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt
from datetime import datetime
import spacy
import numpy as np
from models import db, User, Dream

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///dreamconnect.db'

db.init_app(app)

login_manager = LoginManager()
login_manager.init_app(app)
bcrypt = Bcrypt(app)

nlp = spacy.load('ru_core_news_md')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)

        return redirect(url_for('dashboard'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login_or_register():
    if request.method == 'POST':
        username = request.form.get('username')
        user = User.query.filter_by(username=username).first()

        # Проверка: существует ли аккаунт
        if 'password' not in request.form:
            if user:
                # Аккаунт существует, показываем поле для ввода пароля
                return render_template('login.html', show_password=True, username=username)
            else:
                # Аккаунт не существует, предлагаем создать аккаунт (появляется поле пароля)
                return render_template('login.html', show_password=True, username=username, error="Аккаунт не найден. Создайте пароль для регистрации.")

        # Проверка пароля, если пользователь уже существует
        else:
            password = request.form['password']
            if user:
                # Проверяем правильность пароля
                if bcrypt.check_password_hash(user.password, password):
                    login_user(user)
                    return redirect(url_for('dashboard'))
                else:
                    # Неверный пароль
                    return render_template('login.html', show_password=True, username=username, error="Неверный пароль.")
            else:
                # Регистрация нового пользователя
                hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
                new_user = User(username=username, password=hashed_password)
                db.session.add(new_user)
                db.session.commit()
                login_user(new_user)
                return redirect(url_for('dashboard'))

    return render_template('login.html')

@app.route('/dashboard')
@login_required
def dashboard():
    dreams = Dream.query.filter_by(user_id=current_user.id).all()
    return render_template('dashboard.html', dreams=dreams)

@app.route('/add_dream', methods=['GET', 'POST'])
@login_required
def add_dream():
    if request.method == 'POST':
        content = request.form['content']
        timestamp = datetime.now()
        
        # Генерация вектора с помощью spaCy
        doc = nlp(content)
        vector = doc.vector

        new_dream = Dream(content=content, timestamp=timestamp, user_id=current_user.id, vector=vector)
        db.session.add(new_dream)
        db.session.commit()

        return redirect(url_for('dashboard'))
    return render_template('add_dream.html')

@app.route('/dreams')
@login_required
def dreams():
    user_dreams = Dream.query.filter_by(user_id=current_user.id).all()
    other_dreams = Dream.query.filter(Dream.user_id != current_user.id).all()

    similar_dreams = []

    if user_dreams:
        last_dream_vector = user_dreams[-1].vector

        for dream in other_dreams:
            similarity = cosine_similarity(dream.vector, last_dream_vector)
            if similarity > 0.8:  # Порог схожести
                similar_dreams.append((dream, similarity))

        similar_dreams.sort(key=lambda x: x[1], reverse=True)

    return render_template('dreams.html', dreams=similar_dreams)

@app.route('/profiles')
def profiles():
    users = User.query.all()
    return render_template('profiles.html', users=users)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

def cosine_similarity(vec1, vec2):
    return np.dot(vec1, vec2) / (np.linalg.norm(vec1) * np.linalg.norm(vec2))

@app.route('/edit_dream/<int:dream_id>', methods=['GET', 'POST'])
@login_required
def edit_dream(dream_id):
    dream = Dream.query.get_or_404(dream_id)
    
    # Проверяем, что сон принадлежит либо текущему пользователю, либо текущий пользователь администратор
    if dream.user != current_user and not current_user.is_admin:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        dream.content = request.form['content']
        db.session.commit()
        return redirect(url_for('dashboard'))

    return render_template('edit_dream.html', dream=dream)

@app.route('/delete_dream/<int:dream_id>', methods=['POST'])
@login_required
def delete_dream(dream_id):
    dream = Dream.query.get_or_404(dream_id)
    
    # Проверяем, что сон принадлежит либо текущему пользователю, либо текущий пользователь администратор
    if dream.user != current_user and not current_user.is_admin:
        return redirect(url_for('dashboard'))

    db.session.delete(dream)
    db.session.commit()
    return redirect(url_for('dashboard'))


if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Пересоздаем таблицы с учетом новых полей
    app.run(debug=True)