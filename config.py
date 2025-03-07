import os

class Config:
    # Veritabanı yapılandırması
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or "postgresql://segal_ag_database_xed7_user:NpGUwfDy84y0qPVZhRGDTXeM2qLmgPjY@dpg-cv4nts8gph6c739312vg-a.frankfurt-postgres.render.com/segal_ag_database_xed7"
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Flask-SocketIO yapılandırması
    SECRET_KEY = os.urandom(24)
    
    # Uygulama yapılandırması
    MAX_MESSAGE_LENGTH = 1000
    MAX_ROOM_NAME_LENGTH = 100
    MAX_ROOM_DESCRIPTION_LENGTH = 500
