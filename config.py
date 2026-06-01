import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', 'pci-compliance-secret-key-2024')
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL', "sqlite:///compliance.db")
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    FLASK_ENV = os.environ.get('FLASK_ENV', 'production')