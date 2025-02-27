import os

class Config:
    # Veritabanı yapılandırması
    SQLALCHEMY_DATABASE_URI = "postgresql://segaal_ag_database_user:wm4bQURekN6J8AZOSUCkrCneUrJKfHxD@dpg-cuvhooaj1k6c73ed00e0-a.frankfurt-postgres.render.com/segaal_ag_database"
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Flask-SocketIO yapılandırması
    SECRET_KEY = os.urandom(24)
    
    # Uygulama yapılandırması
    MAX_MESSAGE_LENGTH = 1000
    MAX_ROOM_NAME_LENGTH = 100
    MAX_ROOM_DESCRIPTION_LENGTH = 500
