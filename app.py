from flask import Flask, render_template, request, session, redirect, url_for, flash, jsonify, request
from flask_socketio import SocketIO, emit, join_room, leave_room
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from database import db, User, Room, Message, UserRole, ScheduleFile
from config import Config
import os
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash
from flask_wtf.csrf import generate_csrf
import pandas as pd
# Flask uygulamasını oluştur
app = Flask(__name__)
app.config.from_object(Config)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB limit

# Uploads klasörünü oluştur
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

app.config['SCHEDULES'] = os.path.join(app.root_path, 'ders programları')
os.makedirs(app.config['SCHEDULES'], exist_ok=True)

# Veritabanı ve SocketIO'yu başlat
db.init_app(app)
socketio = SocketIO(app)

# Login manager'ı yapılandır
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, user_id)

# Ana sayfa
@app.route('/')
@login_required
def index():
    rooms = db.session.query(Room).filter(
        Room.members.any(id=current_user.id)
    ).all()
    return render_template('index.html', rooms=rooms)

# Giriş sayfası
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password) and user.last_seen is not None or user and user.password_hash == password and user.last_seen is not None:
            if user.ip_address == request.remote_addr or user.username == "admin":
                user.update_last_seen()
                user.is_active = True
                db.session.commit()
                login_user(user)
                return redirect(url_for('index'))
            else:
                flash("Ip adresi uygun değil", "error")

        elif user and user.check_password(password) and user.last_seen is None:
            user.update_last_seen()
            user.is_active = True
            user.ip_address = request.remote_addr
            db.session.commit()
            login_user(user)
            return redirect(url_for('index'))
        else:
            flash('Geçersiz kullanıcı adı veya şifre', 'error')
    return render_template('login.html')

# Çıkış
@app.route('/logout/<int:user_id>')
@login_required
def logout(user_id):
    user = db.session.get(User, user_id)
    user.update_last_seen()
    user.is_active = False
    db.session.commit()
    logout_user()
    return redirect(url_for('login'))

# Oda yönetimi (sadece admin)
@app.route('/rooms', methods=['GET', 'POST'])
@login_required
def manage_rooms():
    if not current_user.can_manage_rooms():
        flash('Bu sayfaya erişim yetkiniz yok', 'error')
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        name = request.form.get('name')
        description = request.form.get('description')
        
        room = Room(
            name=name,
            description=description,
            creator_id=current_user.id
        )
        db.session.add(room)
        db.session.commit()
        
        flash('Oda başarıyla oluşturuldu', 'success')
        return redirect(url_for('manage_rooms'))
    
    rooms = Room.query.all()
    return render_template('manage_rooms.html', rooms=rooms, csrf_token=generate_csrf())

# Kullanıcı yönetimi (sadece admin)
@app.route('/users', methods=['GET', 'POST'])
@login_required
def manage_users():
    try:

        if not current_user.can_manage_users():
            flash('Bu sayfaya erişim yetkiniz yok', 'error')
            return redirect(url_for('index'))
        
        if request.method == 'POST':
            username = request.form.get('username')
            password = request.form.get('password')
            email = request.form.get('email')
            full_name = request.form.get('full_name')
            role = request.form.get('role')
            
            user = User(
                username=username,
                email=email,
                full_name=full_name,
                role=role
            )
            user.set_password(password)
            
            db.session.add(user)
            db.session.commit()
            
            flash('Kullanıcı başarıyla oluşturuldu', 'success')
            return redirect(url_for('manage_users'))
    except Exception as e:
        if str({e}) == "{IntegrityError('(sqlite3.IntegrityError) UNIQUE constraint failed: users.username')}":
            flash('Bu kullanıcı adı zaten kullanımda', 'error')
            return redirect(url_for('manage_users'))

        return jsonify({'error': str({e})}, 500)

    
    users = User.query.all()
    return render_template('manage_users.html', users=users, roles=[UserRole.ADMIN, UserRole.TEACHER, UserRole.STUDENT], user=current_user)

# Kullanıcı güncelleme
@app.route('/users/<int:user_id>/edit', methods=['POST'])
@login_required
def edit_user(user_id):
    if not current_user.can_manage_users():
        return jsonify({'error': 'Yetkiniz yok'}), 403
    
    user = User.query.get_or_404(user_id)
    data = request.json
    
    if 'username' in data:
        existing_user = User.query.filter_by(username=data['username']).first()
        if existing_user and existing_user.id != user_id:
            return jsonify({'error': 'Bu kullanıcı adı zaten kullanımda'}), 400
        user.username = data['username']
    
    if 'email' in data:
        existing_user = User.query.filter_by(email=data['email']).first()
        if existing_user and existing_user.id != user_id:
            return jsonify({'error': 'Bu e-posta adresi zaten kullanımda'}), 400
        user.email = data['email']
    
    if 'full_name' in data:
        user.full_name = data['full_name']
    
    if 'role' in data:
        user.role = data['role']
    
    if 'password' in data and data['password']:
        user.set_password(data['password'])
    
    if 'is_active' in data:
        user.is_active = data['is_active']
    
    try:
        db.session.commit()
        return jsonify({'message': 'Kullanıcı başarıyla güncellendi'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

# Oda güncelleme
@app.route('/rooms/<int:room_id>/edit', methods=['POST'])
@login_required
def edit_room(room_id):
    if not current_user.can_manage_rooms():
        return jsonify({'error': 'Yetkiniz yok'}), 403
    
    room = Room.query.get_or_404(room_id)
    data = request.json
    
    if 'name' in data:
        room.name = data['name']
    
    if 'description' in data:
        room.description = data['description']
    
    if 'is_active' in data:
        room.is_active = data['is_active']
    
    try:
        db.session.commit()
        return jsonify({'message': 'Oda başarıyla güncellendi'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

# Odaya kullanıcı ekleme/çıkarma
@app.route('/rooms/<int:room_id>/members', methods=['POST'])
@login_required
def manage_room_members(room_id):
    if not current_user.can_manage_rooms():
        return jsonify({'error': 'Yetkiniz yok'}), 403
    
    room = Room.query.get_or_404(room_id)
    data = request.json
    action = data.get('action')
    user_ids = data.get('user_ids', [])
    
    try:
        if action == 'add':
            users = User.query.filter(User.id.in_(user_ids)).all()
            for user in users:
                if user not in room.members:
                    room.members.append(user)
        elif action == 'remove':
            users = User.query.filter(User.id.in_(user_ids)).all()
            for user in users:
                if user in room.members:
                    room.members.remove(user)
        
        db.session.commit()
        return jsonify({'message': 'Oda üyeleri güncellendi'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

# Kullanıcıları listeleme (JSON)
@app.route('/api/users')
@login_required
def list_users():
    if not current_user.can_manage_users():
        return jsonify({'error': 'Yetkiniz yok'}), 403
    
    users = User.query.all()
    return jsonify([{
        'id': user.id,
        'username': user.username,
        'email': user.email,
        'full_name': user.full_name,
        'role': user.role,
        'is_active': user.is_active
    } for user in users])

# Oda üyelerini listeleme (JSON)
@app.route('/api/rooms/<int:room_id>/members')
@login_required
def list_room_members(room_id):
    if not current_user.can_manage_rooms():
        return jsonify({'error': 'Yetkiniz yok'}), 403
    
    room = Room.query.get_or_404(room_id)
    return jsonify([{
        'id': member.id,
        'username': member.username,
        'full_name': member.full_name,
        'role': member.role
    } for member in room.members])

# Oda mesajlarını getir
@app.route('/api/rooms/<int:room_id>/messages')
@login_required
def get_room_messages(room_id):
    room = Room.query.get_or_404(room_id)
    
    # Kullanıcının odaya erişim yetkisi var mı kontrol et
    if room not in current_user.rooms:
        return jsonify({'error': 'Bu odaya erişim yetkiniz yok'}), 403
    
    # Son 100 mesajı getir
    messages = Message.query.filter_by(room_id=room_id)\
        .order_by(Message.created_at.asc())\
        .all()
    
    return jsonify([{
        'user': msg.author.username,
        'content': msg.content,
        'timestamp': msg.created_at.strftime('%H:%M'),
        'file_path': msg.file_path,
        'is_file': bool(msg.file_path)
    } for msg in messages])

# Dosya yükleme
@app.route('/upload', methods=['POST'])
@login_required
def upload_file():
    try:
        if current_user.role not in ['öğretmen', 'idare']:
            return jsonify({'error': 'Yetkisiz işlem'}), 403
        
        if 'file' not in request.files:
            return jsonify({'error': 'Dosya seçilmedi'}), 400
        
        file = request.files['file']
        room_id = request.form.get('room_id')
        
        if not room_id:
            return jsonify({'error': 'Oda ID gerekli'}), 400
            
        room = db.session.get(Room, room_id)
        if not room:
            return jsonify({'error': 'Oda bulunamadı'}), 404
        
        if file.filename == '':
            return jsonify({'error': 'Dosya seçilmedi'}), 400
        
        if file:
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)
            
            # Dosya mesajını oluştur
            message = Message(
                content=f'[DOSYA] {filename}',
                file_path=filename,
                author=current_user,
                room_id=room_id,
            )
            db.session.add(message) 
            db.session.commit()
            
            # Socket.io ile mesajı gönder
            socketio.emit('message', {
                'room_id': room_id,
                'content': f"[DOSYA] {filename}",
                'user': current_user.username,
                'file_path': filename,
                'is_file': True,
                'timestamp': datetime.now().strftime('%H:%M')
            }, room=room_id)
            socketio.emit('play_sound', {'message': 'New message received!'}, room=room_id)
            
            return jsonify({
                'success': True,
                'filename': filename,
                'message': 'Dosya başarıyla yüklendi'
            })
    except Exception as e:
        db.session.rollback()
        print(f'Upload Error: {e}')
        return jsonify({'error': str(e)}), 500

# Dosya indirme
@app.route('/download/<filename>')
@login_required
def download_file(filename):
    try:
        return send_from_directory(
            app.config['UPLOAD_FOLDER'],
            filename,
            as_attachment=True,  # Dosyayı indirme olarak gönder
            download_name=filename  # Orijinal dosya adını koru
        )
    except Exception as e:
        return jsonify({'error': 'Dosya bulunamadı'}), 404

# Şifre sıfırlama
@app.route('/reset_password', methods=['POST'])
def reset_password():
    try:
        username = request.form.get('username2')
        new_password = request.form.get('new_password')

        if not username or not new_password:
            return jsonify({'error': 'Kullanıcı adı veya yeni şifre eksik!'}), 400

        user = User.query.filter_by(username=username).first()
        if user:
            user.password_hash = generate_password_hash(new_password)
            db.session.commit()
            return redirect(url_for('manage_users'))
        return jsonify({'error': 'Kullanıcı bulunamadı!'}), 404
    except Exception as e:
        print(f'Error: {e}')
        return jsonify({'error': 'Bir hata oluştu!'}), 500

# Oda silme
@app.route('/delete_room/<int:room_id>', methods=['DELETE'])
@login_required
def delete_room(room_id):
    if current_user.role != 'idare':
        return jsonify({'error': 'Yetkisiz işlem'}), 403

    room = db.session.get(Room, room_id)
    if room:
        # Delete all messages associated with the room
        Message.query.filter_by(room_id=room_id).delete()
        
        db.session.delete(room)
        db.session.commit()
        return jsonify({'success': True})
    else:
        return jsonify({'error': 'Oda bulunamadı'}), 404

# Kullanıcı silme
@app.route('/delete_user/<int:user_id>', methods=['DELETE'])
@login_required
def delete_user(user_id):
    if current_user.role != 'idare':
        return jsonify({'error': 'Yetkisiz işlem'}), 403

    user = User.query.get(user_id)
    if user:
        db.session.delete(user)
        db.session.commit()
        return jsonify({'success': True})
    else:
        return jsonify({'error': 'Kullanıcı bulunamadı'}), 404

                
# SocketIO event handlers
@socketio.on('join')
def on_join(data):
    room = data['room']
    join_room(room)
    
    # Kullanıcının odaya ilk kez katılıp katılmadığını kontrol et
    room_obj = db.session.get(Room, room)
    if room_obj and current_user not in room_obj.members:
        # Odaya ekle
        room_obj.members.append(current_user)
        db.session.commit()
        
        # Sistem mesajı gönder
        emit('message', {
            'user': 'Sistem',
            'content': f'{current_user.username} odaya katıldı',
            'timestamp': datetime.now().strftime('%H:%M')
        }, room=room)
        emit('play_sound', {'message': 'New message received!'}, broadcast=True)

@app.route('/rooms/<int:room_id>/upload', methods=['POST'])
def upload_schedule(room_id):
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400

    file = request.files['file']
    
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400

    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['SCHEDULES'], filename)

        # Check if a schedule file already exists for the room
        existing_file = ScheduleFile.query.filter_by(room_id=room_id).first()
        
        if existing_file:
            # If a file exists, delete it from the filesystem
            existing_file_path = os.path.join(app.config['SCHEDULES'], existing_file.filename)
            if os.path.exists(existing_file_path):
                os.remove(existing_file_path)  # Remove the old file

            # Update the existing entry in the database
            existing_file.filename = filename
        else:
            # If no file exists, create a new entry
            existing_file = ScheduleFile(room_id=room_id, filename=filename)
            db.session.add(existing_file)

        # Save the new file
        file.save(file_path)

        # Commit the changes to the database
        db.session.commit()

        return jsonify({'success': True}), 200
    else:
        return jsonify({'error': 'File type not allowed'}), 400

def allowed_file(filename):
    allowed_extensions = {'xls', 'xlsx'}
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in allowed_extensions

@app.route('/rooms/<int:room_id>/files', methods=['GET'])
def get_uploaded_schedules(room_id):
    files = ScheduleFile.query.filter_by(room_id=room_id).all()
    return jsonify([{'id': file.id, 'filename': file.filename} for file in files]), 200


@socketio.on('connect')
def on_connect():
    if current_user.is_authenticated:
        current_user.update_last_seen()
        emit('message', {
            'user': 'Sistem',
            'content': f'{current_user.username} bağlandı',
            'timestamp': datetime.now().strftime('%H:%M')
        })
    return jsonify({'success': True})

@socketio.on('disconnect')
def on_disconnect():
    current_user.update_last_seen()
    emit('message', {
        'user': 'Sistem',
        'content': f'{current_user.username} çıkış yaptı',
        'timestamp': datetime.now().strftime('%H:%M')
    })

@socketio.on('message')
def on_message(data):
    room_id = data['room']
    message_content = data['message']
    room = db.session.get(Room, room_id)
    
    if not room:
        emit('error', {'message': 'Oda bulunamadı'})
        return
    
    if not current_user.can_send_message(room):
        emit('error', {'message': 'Bu odaya mesaj gönderme yetkiniz yok'})
        return
    
    message = Message(content=message_content, author=current_user, room=room)
    db.session.add(message)
    db.session.commit()
    
    emit('message', {
        'user': current_user.username,
        'content': message_content,
        'timestamp': message.created_at.strftime('%H:%M')
    }, room=room_id)
    emit('play_sound', {'message': 'Yeni mesaj alındı!'}, broadcast=True)

def init_db():
    with app.app_context():
        db.create_all()  # Create all tables

        # List of admin users to create
        admin_users = [
            {
                'username': 'metinsözer',
                'email': 'admin1@okul.com',
                'full_name': 'Metin Sözer',
                'password': '123'
            },
            {
                'username': 'özenözcan',
                'email': 'admin2@okul.com',
                'full_name': 'Özen Özcan',
                'password': '123'
            },
            {
                'username': 'zekeriyakıldırıcı',
                'email': 'admin3@okul.com',
                'full_name': 'Zekeriya Kıldırıcı',
                'password': '123'
            }
        ]

        for user_data in admin_users:
            # Check if the user already exists
            existing_user = User.query.filter_by(username=user_data['username']).first()
            if not existing_user:
                # Create a new admin user
                admin_user = User(
                    username=user_data['username'],
                    email=user_data['email'],
                    full_name=user_data['full_name'],
                    role=UserRole.ADMIN
                )
                admin_user.set_password(user_data['password'])  # Assuming you have a method to set the password
                db.session.add(admin_user)

        db.session.commit()  # Commit the changes to the database

@app.route('/rooms/<int:room_id>/current_class')
@login_required
def current_class(room_id):
    room = db.session.get(Room, room_id)
    if not room:
        return jsonify({'error': 'Room not found'}), 404

    # Get the current class name and teacher's name based on the schedule file
    current_class_name, current_teacher = get_current_class_info(room)
    return jsonify({'name': current_class_name, 'teacher': current_teacher})

def get_current_class_info(room):
    # Get the current time
    current_time = datetime.now().time()

    # Define the lunch break time range
    lunch_start = datetime.strptime("13:00:00", "%H:%M:%S").time()
    lunch_end = datetime.strptime("13:45:00", "%H:%M:%S").time()

    # Check if the current time is within the lunch break
    if lunch_start <= current_time <= lunch_end:
        return "ÖĞLE ARASI", ""  # Return "ÖĞLE ARASI" and empty teacher name
    # Load the schedule file for the room
    schedule_file = ScheduleFile.query.filter_by(room_id=room.id).first()
    if not schedule_file:
        return "Ders yok", ""  # No schedule file found

    # Define the path to the schedule file
    file_path = os.path.join(app.config['SCHEDULES'], schedule_file.filename)

    # Read the Excel file
    try:
        df = pd.read_excel(file_path, engine='openpyxl')  # Use openpyxl to read .xlsx files
    except Exception as e:
        print(f"Error reading the Excel file: {e}")
        return "Ders yok", ""  # Return "Ders yok" and empty teacher name

    # Convert 'Başlangıç' and 'Bitiş' columns to datetime.time
    df['Başlangıç'] = pd.to_datetime(df['Başlangıç'], format='%H:%M:%S', errors='coerce').dt.time
    df['Bitiş'] = pd.to_datetime(df['Bitiş'], format='%H:%M:%S', errors='coerce').dt.time

    # Iterate through the rows to find the current class
    for index, row in df.iterrows():
        start_time = row['Başlangıç']  # This should now be a datetime.time object
        end_time = row['Bitiş']  # This should also be a datetime.time object
        class_name = row['Ders']  # Assuming 'Ders' is the class name column
        teacher_name = row['Öğretmen']  # Get the teacher's name

        # Combine the current date with the start and end times
        start_datetime = datetime.combine(datetime.now().date(), start_time)
        end_datetime = datetime.combine(datetime.now().date(), end_time)

        # If the end time is less than the start time, it means it goes past midnight
        if end_time < start_time:
            end_datetime += timedelta(days=1)  # Move the end time to the next day

        # Check if the current time is within the start and end time
        if start_datetime <= datetime.now() <= end_datetime:
            return class_name, teacher_name  # Return the current class name and teacher's name

    return "Ders yok", ""  # No class currently, return "Ders yok" and empty teacher name

if __name__ == '__main__':
    init_db()
    socketio.run(app, debug=True, host='0.0.0.0', port=5000)