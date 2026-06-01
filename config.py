import os

class Config:
    SECRET_KEY = 'pci-compliance-secret-key-2024'
    SQLALCHEMY_DATABASE_URI = "sqlite:///compliance.db"
    SQLALCHEMY_TRACK_MODIFICATIONS = False