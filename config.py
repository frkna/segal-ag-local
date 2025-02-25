import os

class Config:
    # Veritabanı yapılandırması
    SQLALCHEMY_DATABASE_URI = "postgresql://segal_ag_database_lyok_user:TW6ch37OLgioY7COblK8BdA80XrPGQ9f@dpg-cuk77mlumphs73bb5440-a.frankfurt-postgres.render.com/segal_ag_database_lyok"
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Flask-SocketIO yapılandırması
    SECRET_KEY = os.urandom(24)
    
    # Uygulama yapılandırması
    MAX_MESSAGE_LENGTH = 1000
    MAX_ROOM_NAME_LENGTH = 100
    MAX_ROOM_DESCRIPTION_LENGTH = 500
