from datetime import datetime  # Добавляем импорт

from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin

db = SQLAlchemy()

class Dream(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    
    # Поле для хранения вектора сна
    vector = db.Column(db.PickleType, nullable=True)  # Можно использовать PickleType для хранения сложных данных

    user = db.relationship('User', backref=db.backref('dreams', lazy=True))


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), nullable=False, unique=True)
    password = db.Column(db.String(150), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)

class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    dream_id = db.Column(db.Integer, db.ForeignKey('dream.id'), nullable=False)

    user = db.relationship('User', backref='comments')
    dream = db.relationship('Dream', backref='comments')
