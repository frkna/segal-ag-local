import os

class Config:
    # Veritabanı yapılandırması
    SQLALCHEMY_DATABASE_URI = "postgresql://postgres:d%&Ql_)SAvdSbNGd5qv9f5#9{@localhost/segal-ag-db"
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    HOST = "localhost"
    PORT = "5432"
    USER = "postgres"
    PASSWORD = "d%&Ql_)SAvdSbNGd5qv9f5#9{"
    DBNAME = "segal-ag-db"
    
    # Flask-SocketIO yapılandırması
    SECRET_KEY = os.urandom(24)
    
    # Uygulama yapılandırması
    MAX_MESSAGE_LENGTH = 1000
    MAX_ROOM_NAME_LENGTH = 100
    MAX_ROOM_DESCRIPTION_LENGTH = 500
