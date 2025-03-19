from flask import Flask, render_template, request, session, redirect, url_for, flash, jsonify, request, send_from_directory
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
from schedule_convert import parse_schedule
import re
from plyer import notification
from sqlalchemy import text  # Import the text function

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

# Dictionary to track user statuses
user_status = {}

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, user_id)

@app.before_request
def before_first_request():
    try:
        db.session.execute(text('SELECT 1'))
    except Exception as e:
        pass

# Ana sayfa
@app.route('/')
@login_required
def index():
    rooms = db.session.query(Room).filter(
        Room.members.any(id=current_user.id)
    ).all()
    if rooms:
        current_room = rooms[0]
        return render_template('index.html', rooms=rooms, current_user=current_user, current_room=current_room)
    else:
        first_room = Room(name="first room", description="first room", creator=current_user)
        db.session.add(first_room)
        db.session.commit()
        return render_template('index.html', rooms=rooms, current_user=current_user, current_room=first_room)

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
@app.route('/manage_rooms', methods=['GET'])
@login_required
def manage_rooms():
    if not current_user.can_manage_rooms():
        flash('Bu sayfaya erişim yetkiniz yok', 'error')
        return redirect(url_for('index'))
    
    rooms = db.session.query(Room).all()
    for room in rooms:
        room.created_at_adjusted = room.created_at + timedelta(hours=3)  # Adjust created at time
        room.current_class_name, room.current_teacher = get_current_class_info(room)
    
    # Generate CSRF token
    csrf_token = generate_csrf()
    
    return render_template('manage_rooms.html', rooms=rooms, csrf_token=csrf_token, extract_class_from_room_name=extract_class_from_room_name)

# Kullanıcı yönetimi (sadece admin)
@app.route('/users', methods=['GET', 'POST'])
@login_required
def manage_users():
    if not current_user.role == UserRole.ADMIN:
        flash('Bu sayfaya erişim yetkiniz yok', 'error')
        return redirect(url_for('index'))
    
    users = db.session.query(User).all()
    for user in users:
        if user.last_seen:
            user.last_seen_adjusted = user.last_seen + timedelta(hours=3)  # Adjust last seen time

    return render_template('manage_users.html', users=users, csrf_token=generate_csrf())

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

# Oda yönetimi (sadece admin)
@app.route('/rooms', methods=['POST'])
@login_required
def create_room():
    if not current_user.can_manage_rooms():
        return jsonify({'error': 'Bu işlem için yetkiniz yok'}), 403
    
    name = request.form.get('name')
    description = request.form.get('description')

    if not name or not description:
        return jsonify({'error': 'Oda adı ve açıklama gereklidir.'}), 400

    new_room = Room(name=name, description=description, creator=current_user)
    db.session.add(new_room)
    
    try:
        db.session.commit()  # Commit to get the new room ID
        
        # Find the latest schedule file
        latest_schedule = ScheduleFile.query.order_by(ScheduleFile.id.desc()).first()
        
        # If a schedule file exists, assign it to the new room
        if latest_schedule:
            new_schedule = ScheduleFile(room_id=new_room.id, filename=latest_schedule.filename)
            db.session.add(new_schedule)
            db.session.commit()
        
        # Check if the request expects JSON
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({'success': True, 'room_id': new_room.id}), 201
        else:
            flash('Oda başarıyla oluşturuldu!', 'success')
            return redirect(url_for('manage_rooms'))
    except Exception as e:
        db.session.rollback()
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({'error': f'Oda oluşturulurken bir hata oluştu: {str(e)}'}), 500
        else:
            flash(f'Oda oluşturulurken bir hata oluştu: {str(e)}', 'error')
            return redirect(url_for('manage_rooms'))

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
    room = db.session.get(Room, room_id)
    
    if not room:
        return jsonify({'error': 'Room not found'}), 404
    
    # Retrieve the last 100 messages for the room
    messages = db.session.query(Message).filter_by(room_id=room_id)\
        .order_by(Message.created_at.asc())\
        .all()
    
    # Prepare the messages with adjusted timestamps
    adjusted_messages = [{
        'user': msg.author.username,
        'content': msg.content,
        'timestamp': (msg.created_at + timedelta(hours=3)).isoformat(),  # Adjust timestamp here
        'file_path': msg.file_path,
        'is_file': bool(msg.file_path)
    } for msg in messages]

    return jsonify(adjusted_messages)

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
                'timestamp': (message.created_at + timedelta(hours=3)).isoformat()
            }, room=room_id)
            notification.notify(title=current_user.username, message=filename, timeout=5, app_name="ŞEGAL AĞ",app_icon="logo.ico")
            socketio.emit('play_sound', {'message': 'Yeni dosya alındı!'}, room=room_id)
            
            return jsonify({
                'success': True,
                'filename': filename,
                'message': 'Dosya başarıyla yüklendi'
            })
    except Exception as e:
        db.session.rollback()
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
        print(e)
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
        return jsonify({'error': 'Bir hata oluştu!'}), 500

# Oda silme
@app.route('/delete_room/<int:room_id>', methods=['DELETE'])
@login_required
def delete_room(room_id):
    if current_user.role != 'idare':
        return jsonify({'error': 'Yetkisiz işlem'}), 403

    try:
        room = db.session.get(Room, room_id)
        if room:
            # Delete all schedules associated with the room
            ScheduleFile.query.filter_by(room_id=room_id).delete()  # Assuming ScheduleFile is the model for schedules
            
            # Delete all messages associated with the room
            Message.query.filter_by(room_id=room_id).delete()
            
            db.session.delete(room)
            db.session.commit()
            return jsonify({'success': True})
        else:
            return jsonify({'error': 'Oda bulunamadı'}), 404
    except Exception as e:
        db.session.rollback()

        return jsonify({'error': f'Oda silinirken bir hata oluştu: {str(e)}'}), 500

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
    
    room_obj = db.session.get(Room, room)
    if room_obj:
        
        if current_user not in room_obj.members:
            room_obj.members.append(current_user)
            db.session.commit()
            
            # Emit a message to the room
            emit('message', {
                'user': 'Sistem',
                'content': f'{current_user.username} odaya katıldı',
                'timestamp': datetime.now().strftime('%H:%M')
            }, room=room)
            emit('play_sound', {'message': 'Kullanıcı katıldı!'}, broadcast=True)

            # Emit the updated list of users in the room
            users_in_room = [{'id': user.id, 'username': user.username} for user in room_obj.members]
            emit('users', {'users': users_in_room}, room=room)  # Emit the users to the room
        else:
           pass
    else:
        pass

@app.route('/upload_schedule', methods=['POST'])
@login_required
def upload_schedule():
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400

    file = request.files['file']
    
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400

    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['SCHEDULES'], filename)

        # Save the uploaded file
        file.save(file_path)

        # Update each room with the new schedule
        for room in Room.query.all():
            existing_file = ScheduleFile.query.filter_by(room_id=room.id).first()
            if existing_file:
                    # Update the existing entry in the database
                existing_file.filename = filename
            else:
                    # If no file exists, create a new entry
                existing_file = ScheduleFile(room_id=room.id, filename=filename)
                db.session.add(existing_file)

        # Commit the changes to the database
        db.session.commit()

        return jsonify({'success': True, 'message': 'Ders programı başarıyla yüklendi'}), 200
    else:
        return jsonify({'error': 'File type not allowed'}), 400

def allowed_file(filename):
    allowed_extensions = {'xls', 'xlsx'}
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in allowed_extensions

@socketio.on('connect')
def on_connect():
    if current_user.is_authenticated:
        user_status[current_user.id] = True  # Mark user as online
    emit('user_status_change', {
        'user_id': current_user.id,
            'is_active': True
        }, broadcast=True)  # Notify all clients

@socketio.on('disconnect')
def on_disconnect():
    if current_user.is_authenticated:
        user_status[current_user.id] = False  # Mark user as offline
        emit('user_status_change', {
            'user_id': current_user.id,
            'is_active': False
        }, broadcast=True)  # Notify all clients

@socketio.on('message')
def on_message(data):
    if not current_user.is_authenticated:
        emit('error', {'message': 'You must be logged in to send messages.'})
        return

    room_id = data['room']
    message_content = data['message']
    room = db.session.get(Room, room_id)
    
    if not room:
        emit('error', {'message': 'Room not found'})
        return
    
    if not current_user.can_send_message(room):
        emit('error', {'message': 'You do not have permission to send messages in this room.'})
        return
    
    message = Message(content=message_content, author=current_user, room=room)
    db.session.add(message)
    db.session.commit()
    
    # Emit the message with the original timestamp
    emit('message', {
        'user': current_user.username,
        'content': message_content,
        'timestamp': (message.created_at + timedelta(hours=3)).isoformat(),  # Adjust timestamp here
        'is_file': False  # or True if it's a file
    }, room=room_id)
    notification.notify(title=current_user.username, message=message_content, timeout=5, app_name="ŞEGAL AĞ",app_icon="logo.ico")
    # Send notification only to other users in the room
    if current_user.is_authenticated:
        emit('play_sound', {'message': 'Yeni mesaj alındı!'}, room=room_id, skip_sid=request.sid)  # Skip the sender

@socketio.on('user_online')
def handle_user_online():
    if current_user.is_authenticated:
        user_status[current_user.id] = True  # Mark user as online
        emit('user_status_change', {
            'user_id': current_user.id,
            'is_active': True
        }, broadcast=True)  # Notify all clients

@socketio.on('user_offline')
def handle_user_offline():
    if current_user.is_authenticated:
        user_status[current_user.id] = False  # Mark user as offline
        emit('user_status_change', {
            'user_id': current_user.id,
            'is_active': False
        }, broadcast=True)  # Notify all clients

# Veritabanını oluştur
def init_db():
    with app.app_context():
        db.create_all()  # Create all tables


        # List of admin users to create
        admin_users = [
            {
                'username': 'metinsözer',
                'full_name': 'Metin Sözer',
                'password': '123'
            },
            {
                'username': 'özenözcan',
                'full_name': 'Özen Özcan',
                'password': '123'
            },
            {
                'username': 'zekeriyakıldırıcı',
                'full_name': 'Zekeriya Kıldırıcı',
                'password': '123'
            },
            {
                'username': 'server',
                'full_name': 'Ana Bilgisayar',
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
    # Get the current time and day
    now = datetime.now()
    current_time = now.time()
    current_day = now.strftime('%A')  # Get the current day name in English
    
    # Map English day names to Turkish
    day_map = {
        'Monday': 'Pazartesi',
        'Tuesday': 'Salı',
        'Wednesday': 'Çarşamba',
        'Thursday': 'Perşembe',
        'Friday': 'Cuma',
        'Saturday': 'Cumartesi',
        'Sunday': 'Pazar'
    }
    
    current_day_turkish = day_map.get(current_day, '')
    
    # If it's Sunday, return "Ders yok"
    if current_day_turkish == 'Pazar':
        return "Ders yok0", ""
    
    # Define the lunch break time range
    lunch_start = datetime.strptime("12:00:00", "%H:%M:%S").time()
    lunch_end = datetime.strptime("12:45:00", "%H:%M:%S").time()

    # Check if the current time is within the lunch break
    if lunch_start <= current_time <= lunch_end:
        return "ÖĞLE ARASI", ""  # Return "ÖĞLE ARASI" and empty teacher name

    # Get the schedule file
    schedule_file = ScheduleFile.query.filter_by(room_id=room.id).first()
    if not schedule_file:
        return "Ders programı yüklenmemiş", ""  # No schedule file found

    # Parse the schedule data
    try:
        file_path = os.path.join(app.config['SCHEDULES'], schedule_file.filename)
        schedule_data = parse_schedule(file_path)
    except Exception as e:
        return "Ders programı doğru yüklenmemiş", ""  # Error parsing schedule

    # Extract the class name from the room name
    room_class = extract_class_from_room_name(room.name)
    
    # If no class name could be extracted (e.g., "demo"), return "Ders yok"
    if not room_class:
        return "Ders programında geçerli bir sınıf değil", ""
    
    # Try different formats of the class name for matching
    possible_class_formats = []
    if room_class:
        # Original format
        possible_class_formats.append(room_class)
        
        # Without separator
        possible_class_formats.append(room_class.replace('/', ''))
        
        # With different separators
        possible_class_formats.append(room_class.replace('/', '-'))
        possible_class_formats.append(room_class.replace('/', ' '))
        
        # Different case
        possible_class_formats.append(room_class.upper())
        possible_class_formats.append(room_class.lower())
    
    # Filter schedule data for the current day and matching class
    current_schedule = []
    for entry in schedule_data:
        if entry['day'] == current_day_turkish:
            # Only add entries that match the class name
            if room_class:
                # Check if the entry's class matches any of the possible formats
                entry_class = entry['class'].strip()
                match_found = False
                
                # Direct match
                if entry_class == room_class:
                    match_found = True
                
                # Check if entry_class contains room_class or vice versa
                for format in possible_class_formats:
                    if format in entry_class or entry_class in format:
                        match_found = True
                        break
                
                # Check if the numeric part and letter part match
                entry_number_match = re.search(r'(\d+)', entry_class)
                entry_letter_match = re.search(r'([A-Za-z])', entry_class)
                room_number_match = re.search(r'(\d+)', room_class)
                room_letter_match = re.search(r'([A-Za-z])', room_class)
                
                if (entry_number_match and entry_letter_match and room_number_match and room_letter_match and
                    entry_number_match.group(1) == room_number_match.group(1) and
                    entry_letter_match.group(1).upper() == room_letter_match.group(1).upper()):
                    match_found = True
                
                if match_found:
                    current_schedule.append(entry)
    
    # If no matching schedule found, return "Ders yok"
    if not current_schedule:
        return "Ders programı yüklenmemiş", ""

    # Iterate through the schedule data to find the current class
    for entry in current_schedule:
        time_range = entry['time_range']
        
        # Handle newline-separated time range
        if '\n' in time_range:
            try:
                lines = time_range.split('\n')
                start_time = lines[0].strip()
                end_time = lines[1].strip()
                
                # Convert to datetime.time objects
                start_datetime = datetime.strptime(start_time, '%H:%M').time()
                end_datetime = datetime.strptime(end_time, '%H:%M').time()
                
                # If the end time is less than the start time, it means it goes past midnight
                if end_datetime < start_datetime:
                    end_datetime = (datetime.combine(datetime.today(), end_datetime) + timedelta(days=1)).time()
                
                # Check if the current time is within the start and end time
                if start_datetime <= current_time <= end_datetime:
                    return entry['subject'], entry['teacher']
            except Exception:
                continue
        else:
            # Try different separators for time range
            separators = ['-', '\n', ' - ', ' to ', ':', 'to']
            for separator in separators:
                if separator in time_range:
                    try:
                        parts = time_range.split(separator, 1)
                        start_time = parts[0].strip()
                        end_time = parts[1].strip()
                        
                        # Try to parse the times
                        try:
                            # Try different time formats
                            formats = ['%H:%M', '%H:%M:%S', '%I:%M %p', '%I:%M:%S %p']
                            start_datetime = None
                            end_datetime = None
                            
                            for fmt in formats:
                                try:
                                    start_datetime = datetime.strptime(start_time, fmt).time()
                                    break
                                except ValueError:
                                    continue
                            
                            for fmt in formats:
                                try:
                                    end_datetime = datetime.strptime(end_time, fmt).time()
                                    break
                                except ValueError:
                                    continue
                            
                            if start_datetime and end_datetime:
                                # If the end time is less than the start time, it means it goes past midnight
                                if end_datetime < start_datetime:
                                    end_datetime = (datetime.combine(datetime.today(), end_datetime) + timedelta(days=1)).time()
                                
                                # Check if the current time is within the start and end time
                                if start_datetime <= current_time <= end_datetime:
                                    return entry['subject'], entry['teacher']  # Return the current class name and teacher's name
                        except ValueError:
                            continue
                    except Exception:
                        continue
                    
                    break

    # If we're here, it means no class is currently in session
    # Let's find the next class for today
    next_class = None
    next_start_time = None
    
    for entry in current_schedule:
        time_range = entry['time_range']
        
        # Handle newline-separated time range for next class
        if '\n' in time_range:
            try:
                start_time = time_range.split('\n')[0].strip()
                start_datetime = datetime.strptime(start_time, '%H:%M').time()
                
                # If this class starts after the current time and is earlier than any previously found next class
                if start_datetime > current_time and (next_start_time is None or start_datetime < next_start_time):
                    next_class = entry
                    next_start_time = start_datetime
            except Exception:
                continue
        else:
            # Try different separators for time range
            for separator in ['-', ' - ', ' to ', ':', 'to']:
                if separator in time_range:
                    try:
                        start_time = time_range.split(separator, 1)[0].strip()
                        
                        # Try different time formats
                        for fmt in ['%H:%M', '%H:%M:%S', '%I:%M %p', '%I:%M:%S %p']:
                            try:
                                start_datetime = datetime.strptime(start_time, fmt).time()
                                
                                # If this class starts after the current time and is earlier than any previously found next class
                                if start_datetime > current_time and (next_start_time is None or start_datetime < next_start_time):
                                    next_class = entry
                                    next_start_time = start_datetime
                                
                                break
                            except ValueError:
                                continue
                    except Exception:
                        continue
                    
                    break
    
    if next_class:
        # If there's a next class today, show it with a "Sonraki Ders" prefix
        return f"Sonraki Ders: {next_class['subject']}", next_class['teacher']
    
    return "Dersler bitti", ""  # No class currently or next, return "Ders yok" and empty teacher name

def extract_class_from_room_name(room_name):
    """
    Extract class name from room name.
    Examples:
    - "9/A Sınıfı" -> "9/A"
    - "10-B Odası" -> "10/B"
    - "9a Sınıfı" -> "9/A"
    - "9A" -> "9/A"
    - "9-a" -> "9/A"
    - "Fizik Laboratuvarı" -> None (no class match)
    """
    import re
    
    # Try to match patterns like "9/A", "10-B", "11 C", "9a", "9A", "9-a", etc.
    patterns = [
        r'(\d+[\s/\-\.]*[A-Za-z])',  # Match patterns like "9/A", "10-B", "11.C", "12 D", "9a", "9A"
        r'([A-Za-z][\s/\-\.]*\d+)',  # Match patterns like "A/9", "B-10"
    ]
    
    for pattern in patterns:
        match = re.search(pattern, room_name)
        if match:
            # Clean up the matched class name
            class_name = match.group(1)
            
            # Extract the number and letter parts
            number_match = re.search(r'(\d+)', class_name)
            letter_match = re.search(r'([A-Za-z])', class_name)
            
            if number_match and letter_match:
                number = number_match.group(1)
                letter = letter_match.group(1).upper()  # Convert letter to uppercase
                
                # Standardize the format to "number/letter"
                return f"{number}/{letter}"
    
    # If no class pattern is found, return None
    return None

@app.route('/rooms/<int:room_id>/users', methods=['GET'])
@login_required
def room_users(room_id):
    room = db.session.get(Room, room_id)
    if not room:
        return jsonify({'error': 'Room not found'}), 404

    # Filter out non-admin users
    non_admin_users = [user for user in room.members if user.role != UserRole.ADMIN]

    # Prepare the user status data
    user_statuses = []
    for user in non_admin_users:
        user_statuses.append({
                'id': user.id,
                'username': user.username,
            'full_name': user.full_name,
            'is_online': user_status.get(user.id, False)  # Check online status
        })

    return render_template('room_users.html', users=user_statuses, room=room)  # Pass only non-admin users

@app.route('/add_user', methods=['POST'])
def add_user():
    username = request.form.get('username')
    password = request.form.get('password')
    full_name = request.form.get('full_name')
    role = request.form.get('role')

    # Validate input
    if not username or not password or not full_name or not role:
        return jsonify({'error': 'Tüm alanlar gereklidir.'}), 400

    # Check if the username already exists
    existing_user = User.query.filter_by(username=username).first()
    if existing_user:
        return jsonify({'error': 'Bu kullanıcı adı zaten mevcut.'}), 400

    # Create a new user
    new_user = User(username=username, password_hash=password, full_name=full_name, role=role)
    
    try:
        db.session.add(new_user)
        db.session.commit()
        flash('Kullanıcı başarıyla eklendi.', 'success')
        return jsonify({'success': True}), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': 'Kullanıcı eklenirken bir hata oluştu: ' + str(e)}), 500

if __name__ == '__main__':
    init_db()
    socketio.run(app, debug=True, host='0.0.0.0', port=5000)
