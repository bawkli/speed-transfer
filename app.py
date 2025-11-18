from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from flask_socketio import SocketIO, emit
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import os
from datetime import datetime, timedelta
import secrets
import uuid
import logging
import random
import string
import re

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Reduce werkzeug logging
log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)

# Reduce engineio/socketio logging
engineio_logger = logging.getLogger('engineio.server')
engineio_logger.setLevel(logging.CRITICAL)

socketio_logger = logging.getLogger('socketio')
socketio_logger.setLevel(logging.WARNING)

app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(16)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///speedtransfer.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024

db = SQLAlchemy(app)
socketio = SocketIO(app, cors_allowed_origins="*", max_size=52428800, logger=False, engineio_logger=False)

# Create upload folders
for folder in ['images', 'videos', 'files', 'profiles']:
    os.makedirs(os.path.join(app.config['UPLOAD_FOLDER'], folder), exist_ok=True)

# ========== Database Models ==========
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String(50), unique=True, nullable=False)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), default='user')
    profile_pic = db.Column(db.String(200), default='')
    bio = db.Column(db.Text, default='')
    status = db.Column(db.String(20), default='active')
    ban_until = db.Column(db.DateTime, nullable=True)
    ban_type = db.Column(db.String(20), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.now)
    last_seen = db.Column(db.DateTime, nullable=True)
    
    messages_sent = db.relationship('Message', foreign_keys='Message.sender_id', backref='sender', lazy=True)
    messages_received = db.relationship('Message', foreign_keys='Message.recipient_id', backref='recipient', lazy=True)
    activity_logs = db.relationship('ActivityLog', backref='user', lazy=True, cascade='all, delete-orphan')

class ActivityLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'), nullable=False)
    activity_type = db.Column(db.String(50), nullable=False)
    details = db.Column(db.Text, default='')
    device_info = db.Column(db.String(200), default='')
    ip_address = db.Column(db.String(50), default='')
    timestamp = db.Column(db.DateTime, default=datetime.now)

class Group(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    group_id = db.Column(db.String(20), unique=True, nullable=False)
    name = db.Column(db.String(100), nullable=False)
    creator = db.Column(db.String(80), nullable=False)
    avatar = db.Column(db.String(200), default='')
    created_at = db.Column(db.DateTime, default=datetime.now)
    
    members = db.relationship('GroupMember', backref='group', lazy=True, cascade='all, delete-orphan')
    messages = db.relationship('Message', backref='group', lazy=True, cascade='all, delete-orphan')

class GroupMember(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    group_id = db.Column(db.Integer, db.ForeignKey('group.id', ondelete='CASCADE'), nullable=False)
    username = db.Column(db.String(80), nullable=False)
    joined_at = db.Column(db.DateTime, default=datetime.now)

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    message_id = db.Column(db.String(50), unique=True, nullable=False)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    recipient_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    group_id = db.Column(db.Integer, db.ForeignKey('group.id', ondelete='CASCADE'), nullable=True)
    message = db.Column(db.Text, default='')
    msg_type = db.Column(db.String(20), default='text')
    file_url = db.Column(db.String(300), default='')
    is_group = db.Column(db.Boolean, default=False)
    is_read = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.now)

# Initialize database
with app.app_context():
    try:
        db.create_all()
        
        # Create admin user if not exists
        admin = User.query.filter_by(username='admin').first()
        if not admin:
            admin = User(
                user_id='ADMIN-SYS-ROOT',
                username='admin',
                email='admin@speedtransfer.com',
                password=generate_password_hash('admin123'),
                role='admin',
                bio='System Administrator',
                status='active'
            )
            db.session.add(admin)
            db.session.commit()
            print("✅ Admin user created successfully!")
        else:
            print("✅ Admin user already exists!")
    except Exception as e:
        print(f"⚠️ Database initialization error: {e}")
        db.session.rollback()

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'mp4', 'avi', 'mov', 'pdf', 'doc', 'docx', 'txt', 'zip'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def generate_user_id():
    """Generate unique complex user ID: USR-YYYYMMDD-XXXXXXXX"""
    date_part = datetime.now().strftime('%Y%m%d')
    random_part = ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))
    
    user_id = f"USR-{date_part}-{random_part}"
    
    # Check if already exists (very unlikely but just in case)
    retry_count = 0
    while User.query.filter_by(user_id=user_id).first() and retry_count < 10:
        random_part = ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))
        user_id = f"USR-{date_part}-{random_part}"
        retry_count += 1
    
    return user_id

def log_activity(user_id, activity_type, details=''):
    """Log user activity"""
    try:
        device_info = request.headers.get('User-Agent', 'Unknown')
        ip_address = request.remote_addr or 'Unknown'
        
        activity = ActivityLog(
            user_id=user_id,
            activity_type=activity_type,
            details=details,
            device_info=device_info,
            ip_address=ip_address
        )
        db.session.add(activity)
        db.session.commit()
    except Exception as e:
        logger.error(f"Activity log error: {e}")
        db.session.rollback()

def get_device_type(user_agent):
    """Detect device type from user agent"""
    ua = user_agent.lower()
    if 'mobile' in ua or 'android' in ua or 'iphone' in ua:
        if 'iphone' in ua:
            return '📱 iPhone'
        elif 'android' in ua:
            return '📱 Android'
        else:
            return '📱 Mobile'
    elif 'tablet' in ua or 'ipad' in ua:
        return '📱 Tablet'
    elif 'windows' in ua:
        return '💻 Windows'
    elif 'mac' in ua:
        return '💻 Mac'
    elif 'linux' in ua:
        return '💻 Linux'
    else:
        return '💻 Desktop'

# Online users tracking
online_users = {}  # {socket_id: username}
user_sockets = {}  # {username: socket_id}

# ========== Routes ==========

@app.route('/')
def index():
    if 'username' in session:
        user = User.query.filter_by(username=session['username']).first()
        if user and user.role == 'admin':
            return redirect(url_for('admin_dashboard'))
        return redirect(url_for('chat'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        data = request.get_json()
        identifier = data.get('username')
        password = data.get('password')
        
        user = User.query.filter(
            (User.username == identifier) | (User.user_id == identifier)
        ).first()
        
        if user and check_password_hash(user.password, password):
            # Check if blocked
            if user.status == 'blocked':
                if user.ban_type == 'temporary' and user.ban_until:
                    if datetime.now() > user.ban_until:
                        user.status = 'active'
                        user.ban_until = None
                        user.ban_type = None
                        db.session.commit()
                    else:
                        ban_time = user.ban_until.strftime('%Y-%m-%d %H:%M')
                        return jsonify({'success': False, 'message': f'Account is temporarily banned until {ban_time}'})
                else:
                    return jsonify({'success': False, 'message': 'Account is permanently blocked'})
            
            session['username'] = user.username
            session['user_id'] = user.user_id
            session['role'] = user.role
            
            # Log login activity
            log_activity(user.id, 'login', f'Logged in successfully')
            
            if user.role == 'admin':
                return jsonify({'success': True, 'redirect': '/admin'})
            return jsonify({'success': True, 'redirect': '/chat'})
        
        return jsonify({'success': False, 'message': 'Invalid credentials'})
    
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        try:
            username = request.form.get('username')
            email = request.form.get('email')
            password = request.form.get('password')
            bio = request.form.get('bio', '')
            
            # Check if username already exists
            if User.query.filter_by(username=username).first():
                return jsonify({'success': False, 'message': 'Username already exists'})
            
            # Check if email already exists
            if User.query.filter_by(email=email).first():
                return jsonify({'success': False, 'message': 'Email already exists'})
            
            profile_pic = ''
            if 'profile_pic' in request.files:
                file = request.files['profile_pic']
                if file and file.filename and allowed_file(file.filename):
                    filename = secure_filename(file.filename)
                    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                    filename = f"{timestamp}_{username}_{filename}"
                    filepath = os.path.join(app.config['UPLOAD_FOLDER'], 'profiles', filename)
                    file.save(filepath)
                    profile_pic = f"/static/uploads/profiles/{filename}"
            
            user_id = generate_user_id()
            
            new_user = User(
                user_id=user_id,
                username=username,
                email=email,
                password=generate_password_hash(password),
                profile_pic=profile_pic,
                bio=bio
            )
            
            db.session.add(new_user)
            db.session.commit()
            
            session['username'] = username
            session['user_id'] = user_id
            session['role'] = 'user'
            
            return jsonify({'success': True})
            
        except Exception as e:
            db.session.rollback()
            logger.error(f"Signup error: {e}")
            return jsonify({'success': False, 'message': 'An error occurred during signup. Please try again.'})
    
    return render_template('signup.html')

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        data = request.get_json()
        user_id = data.get('user_id')
        new_password = data.get('new_password')
        
        user = User.query.filter_by(user_id=user_id).first()
        if user:
            user.password = generate_password_hash(new_password)
            db.session.commit()
            return jsonify({'success': True, 'username': user.username})
        
        return jsonify({'success': False, 'message': 'User ID not found'})
    
    return render_template('forgot_password.html')

@app.route('/chat')
def chat():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    current_user = User.query.filter_by(username=session['username']).first()
    if current_user.role == 'admin':
        return redirect(url_for('admin_dashboard'))
    
    # Include admin in chat list for regular users
    users = User.query.filter(
        User.username != session['username']
    ).all()
    
    groups = Group.query.join(GroupMember).filter(
        GroupMember.username == session['username']
    ).all()
    
    # Calculate unread message counts
    user_list = []
    for u in users:
        unread_count = Message.query.filter(
            Message.sender_id == u.id,
            Message.recipient_id == current_user.id,
            Message.is_read == False
        ).count()
        
        user_list.append({
            'username': u.username, 
            'data': {
                'user_id': u.user_id,
                'email': u.email,
                'profile_pic': u.profile_pic,
                'bio': u.bio,
                'status': u.status,
                'role': u.role,
                'unread_count': unread_count
            }
        })
    
    group_list = [{'id': g.group_id, 'data': {
        'name': g.name,
        'creator': g.creator,
        'members': [m.username for m in g.members],
        'created_at': g.created_at.isoformat()
    }} for g in groups]
    
    return render_template('chat.html',
                         username=current_user.username,
                         user_data={
                             'user_id': current_user.user_id,
                             'email': current_user.email,
                             'profile_pic': current_user.profile_pic,
                             'bio': current_user.bio
                         },
                         users=user_list,
                         groups=group_list)

@app.route('/settings')
def settings():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    user = User.query.filter_by(username=session['username']).first()
    user_data = {
        'user_id': user.user_id,
        'email': user.email,
        'profile_pic': user.profile_pic,
        'bio': user.bio,
        'created_at': user.created_at.isoformat()
    }
    
    return render_template('settings.html', user_data=user_data)

@app.route('/admin')
def admin_dashboard():
    if 'username' not in session or session.get('role') != 'admin':
        return redirect(url_for('login'))
    
    users = User.query.filter(User.role != 'admin').all()
    groups = Group.query.all()
    
    user_list = []
    for u in users:
        # Get message statistics
        messages_sent_count = Message.query.filter_by(sender_id=u.id).count()
        messages_received_count = Message.query.filter_by(recipient_id=u.id).count()
        
        # Get last activity
        last_activity = ActivityLog.query.filter_by(user_id=u.id).order_by(ActivityLog.timestamp.desc()).first()
        
        # Get device info
        device_info = 'Unknown'
        if last_activity and last_activity.device_info:
            device_info = get_device_type(last_activity.device_info)
        
        user_list.append({
            'username': u.username, 
            'data': {
                'user_id': u.user_id,
                'email': u.email,
                'profile_pic': u.profile_pic,
                'bio': u.bio,
                'status': u.status,
                'ban_until': u.ban_until.isoformat() if u.ban_until else None,
                'ban_type': u.ban_type,
                'created_at': u.created_at.isoformat(),
                'last_seen': u.last_seen.isoformat() if u.last_seen else None,
                'messages_sent': messages_sent_count,
                'messages_received': messages_received_count,
                'device_info': device_info
            }
        })
    
    # Get all users including admin for messaging
    all_users_for_messaging = User.query.all()
    messaging_users = [{'username': u.username, 'data': {
        'user_id': u.user_id,
        'email': u.email,
        'profile_pic': u.profile_pic,
        'bio': u.bio,
        'role': u.role
    }} for u in all_users_for_messaging if u.username != session['username']]
    
    stats = {
        'total_users': len(users),
        'active_users': len([u for u in users if u.status == 'active']),
        'blocked_users': len([u for u in users if u.status == 'blocked']),
        'total_groups': len(groups),
        'total_messages': Message.query.count()
    }
    
    group_dict = {g.group_id: {
        'name': g.name,
        'creator': g.creator,
        'members': [m.username for m in g.members],
        'created_at': g.created_at.isoformat()
    } for g in groups}
    
    return render_template('admin.html', users=user_list, groups=group_dict, stats=stats, messaging_users=messaging_users)

@app.route('/update_profile', methods=['POST'])
def update_profile():
    if 'username' not in session:
        return jsonify({'success': False})
    
    try:
        user = User.query.filter_by(username=session['username']).first()
        if not user:
            return jsonify({'success': False, 'message': 'User not found'})
        
        user.email = request.form.get('email')
        user.bio = request.form.get('bio', '')
        
        if 'profile_pic' in request.files:
            file = request.files['profile_pic']
            if file and file.filename and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                filename = f"{timestamp}_{user.username}_{filename}"
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], 'profiles', filename)
                file.save(filepath)
                user.profile_pic = f"/static/uploads/profiles/{filename}"
        
        db.session.commit()
        
        socketio.emit('profile_updated', {
            'username': user.username,
            'data': {
                'profile_pic': user.profile_pic,
                'email': user.email,
                'bio': user.bio
            }
        })
        
        return jsonify({'success': True, 'data': {
            'profile_pic': user.profile_pic,
            'email': user.email,
            'bio': user.bio
        }})
    except Exception as e:
        db.session.rollback()
        logger.error(f"Update profile error: {e}")
        return jsonify({'success': False, 'message': 'Failed to update profile'})

@app.route('/change_user_id', methods=['POST'])
def change_user_id():
    """Allow user to change their own user ID"""
    if 'username' not in session:
        return jsonify({'success': False, 'message': 'Unauthorized'})
    
    try:
        data = request.get_json()
        new_user_id = data.get('new_user_id', '').strip()
        
        if not new_user_id:
            return jsonify({'success': False, 'message': 'User ID cannot be empty'})
        
        # Validation: User ID format
        if len(new_user_id) < 8 or len(new_user_id) > 30:
            return jsonify({'success': False, 'message': 'User ID must be between 8-30 characters'})
        
        # Check if contains only allowed characters (letters, numbers, dash, underscore)
        if not re.match(r'^[A-Za-z0-9_-]+$', new_user_id):
            return jsonify({'success': False, 'message': 'User ID can only contain letters, numbers, dash and underscore'})
        
        # Check if already taken
        existing_user = User.query.filter_by(user_id=new_user_id).first()
        if existing_user:
            return jsonify({'success': False, 'message': 'This User ID is already taken'})
        
        # Update user ID
        user = User.query.filter_by(username=session['username']).first()
        if not user:
            return jsonify({'success': False, 'message': 'User not found'})
        
        old_user_id = user.user_id
        user.user_id = new_user_id
        db.session.commit()
        
        # Update session
        session['user_id'] = new_user_id
        
        # Log activity
        log_activity(user.id, 'user_id_changed', f'Changed User ID from {old_user_id} to {new_user_id}')
        
        return jsonify({'success': True, 'new_user_id': new_user_id})
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Change user ID error: {e}")
        return jsonify({'success': False, 'message': 'Failed to change User ID'})

@app.route('/change_password', methods=['POST'])
def change_password():
    if 'username' not in session:
        return jsonify({'success': False})
    
    data = request.get_json()
    old_password = data.get('old_password')
    new_password = data.get('new_password')
    
    user = User.query.filter_by(username=session['username']).first()
    if check_password_hash(user.password, old_password):
        user.password = generate_password_hash(new_password)
        db.session.commit()
        return jsonify({'success': True})
    
    return jsonify({'success': False, 'message': 'Incorrect password'})

@app.route('/delete_account', methods=['POST'])
def delete_account():
    if 'username' not in session:
        return jsonify({'success': False})
    
    user = User.query.filter_by(username=session['username']).first()
    db.session.delete(user)
    db.session.commit()
    session.clear()
    
    return jsonify({'success': True})

@app.route('/create_group', methods=['POST'])
def create_group():
    if 'username' not in session:
        return jsonify({'success': False})
    
    try:
        data = request.get_json()
        group_name = data.get('name')
        members = data.get('members', [])
        
        if not group_name:
            return jsonify({'success': False, 'message': 'Group name is required'})
        
        group_id = str(uuid.uuid4())[:8]
        new_group = Group(
            group_id=group_id,
            name=group_name,
            creator=session['username']
        )
        
        db.session.add(new_group)
        db.session.flush()
        
        # Add creator
        creator_member = GroupMember(group_id=new_group.id, username=session['username'])
        db.session.add(creator_member)
        
        # Add other members
        for member in members:
            group_member = GroupMember(group_id=new_group.id, username=member)
            db.session.add(group_member)
        
        db.session.commit()
        
        socketio.emit('group_created', {
            'group_id': group_id,
            'data': {
                'name': group_name,
                'creator': session['username'],
                'members': [session['username']] + members
            }
        })
        
        return jsonify({'success': True, 'group_id': group_id})
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Create group error: {e}")
        return jsonify({'success': False, 'message': 'Failed to create group'})

# ========== Admin Routes ==========

@app.route('/admin/block_user', methods=['POST'])
def admin_block_user():
    if 'username' not in session or session.get('role') != 'admin':
        return jsonify({'success': False})
    
    data = request.get_json()
    username = data.get('username')
    
    user = User.query.filter_by(username=username).first()
    if user and user.username != 'admin':
        user.status = 'blocked'
        user.ban_type = 'permanent'
        db.session.commit()
        # Force logout blocked user immediately
        socketio.emit('force_logout', {'username': username, 'reason': 'Account has been permanently blocked'})
        return jsonify({'success': True})
    
    return jsonify({'success': False})

@app.route('/admin/unblock_user', methods=['POST'])
def admin_unblock_user():
    if 'username' not in session or session.get('role') != 'admin':
        return jsonify({'success': False})
    
    data = request.get_json()
    username = data.get('username')
    
    user = User.query.filter_by(username=username).first()
    if user:
        user.status = 'active'
        user.ban_until = None
        user.ban_type = None
        db.session.commit()
        socketio.emit('user_unblocked', {'username': username})
        return jsonify({'success': True})
    
    return jsonify({'success': False})

@app.route('/admin/delete_user', methods=['POST'])
def admin_delete_user():
    if 'username' not in session or session.get('role') != 'admin':
        return jsonify({'success': False})
    
    data = request.get_json()
    username = data.get('username')
    
    user = User.query.filter_by(username=username).first()
    if user and user.username != 'admin':
        # Force logout before deleting
        socketio.emit('force_logout', {'username': username, 'reason': 'Your account has been deleted by administrator'})
        db.session.delete(user)
        db.session.commit()
        return jsonify({'success': True})
    
    return jsonify({'success': False})

@app.route('/admin/time_ban_user', methods=['POST'])
def admin_time_ban_user():
    if 'username' not in session or session.get('role') != 'admin':
        return jsonify({'success': False})
    
    data = request.get_json()
    username = data.get('username')
    hours = data.get('hours', 24)
    
    user = User.query.filter_by(username=username).first()
    if user and user.username != 'admin':
        ban_until = datetime.now() + timedelta(hours=hours)
        user.status = 'blocked'
        user.ban_until = ban_until
        user.ban_type = 'temporary'
        db.session.commit()
        
        # Force logout banned user immediately
        socketio.emit('force_logout', {
            'username': username,
            'reason': f'Account has been temporarily banned until {ban_until.strftime("%Y-%m-%d %H:%M")}'
        })
        
        return jsonify({'success': True})
    
    return jsonify({'success': False})

@app.route('/admin/change_user_password', methods=['POST'])
def admin_change_user_password():
    if 'username' not in session or session.get('role') != 'admin':
        return jsonify({'success': False})
    
    data = request.get_json()
    username = data.get('username')
    new_password = data.get('new_password')
    
    user = User.query.filter_by(username=username).first()
    if user and user.username != 'admin':
        user.password = generate_password_hash(new_password)
        db.session.commit()
        return jsonify({'success': True})
    
    return jsonify({'success': False})

@app.route('/admin/user_activity/<username>')
def admin_user_activity(username):
    """Get detailed user activity logs"""
    if 'username' not in session or session.get('role') != 'admin':
        return jsonify({'success': False, 'message': 'Unauthorized'})
    
    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({'success': False, 'message': 'User not found'})
    
    # Get activity logs
    activities = ActivityLog.query.filter_by(user_id=user.id).order_by(ActivityLog.timestamp.desc()).limit(100).all()
    
    activity_list = []
    for activity in activities:
        activity_list.append({
            'type': activity.activity_type,
            'details': activity.details,
            'device': get_device_type(activity.device_info),
            'ip': activity.ip_address,
            'timestamp': activity.timestamp.strftime('%Y-%m-%d %I:%M %p')
        })
    
    # Get chat statistics
    chat_partners = db.session.query(
        User.username,
        db.func.count(Message.id).label('message_count')
    ).join(
        Message,
        db.or_(
            (Message.sender_id == user.id) & (Message.recipient_id == User.id),
            (Message.recipient_id == user.id) & (Message.sender_id == User.id)
        )
    ).filter(
        User.id != user.id,
        Message.is_group == False
    ).group_by(User.username).order_by(db.desc('message_count')).limit(10).all()
    
    chat_stats = [{'partner': partner, 'count': count} for partner, count in chat_partners]
    
    return jsonify({
        'success': True,
        'user': {
            'username': user.username,
            'user_id': user.user_id,
            'email': user.email,
            'created_at': user.created_at.strftime('%Y-%m-%d %I:%M %p'),
            'last_seen': user.last_seen.strftime('%Y-%m-%d %I:%M %p') if user.last_seen else 'Never',
            'messages_sent': Message.query.filter_by(sender_id=user.id).count(),
            'messages_received': Message.query.filter_by(recipient_id=user.id).count()
        },
        'activities': activity_list,
        'chat_stats': chat_stats
    })

@app.route('/admin/send_message', methods=['POST'])
def admin_send_message():
    """Admin sends message to specific user or broadcast to all users"""
    if 'username' not in session or session.get('role') != 'admin':
        return jsonify({'success': False, 'message': 'Unauthorized'})
    
    try:
        data = request.get_json()
        message_text = data.get('message')
        recipient = data.get('recipient')  # 'all' or specific username
        
        if not message_text:
            return jsonify({'success': False, 'message': 'Message is required'})
        
        admin_user = User.query.filter_by(username=session['username']).first()
        
        if recipient == 'all':
            # Broadcast to all users
            users = User.query.filter(User.role != 'admin').all()
            
            for user in users:
                msg_id = str(uuid.uuid4())
                new_message = Message(
                    message_id=msg_id,
                    sender_id=admin_user.id,
                    recipient_id=user.id,
                    message=f"📢 Admin Broadcast: {message_text}",
                    msg_type='text',
                    is_group=False
                )
                db.session.add(new_message)
            
            db.session.commit()
            
            # Send real-time notification to all online users
            socketio.emit('admin_broadcast', {
                'message': message_text,
                'sender': 'admin',
                'timestamp': datetime.now().strftime('%I:%M %p')
            })
            
            return jsonify({'success': True, 'message': f'Message sent to {len(users)} users'})
        else:
            # Send to specific user
            recipient_user = User.query.filter_by(username=recipient).first()
            
            if not recipient_user:
                return jsonify({'success': False, 'message': 'User not found'})
            
            msg_id = str(uuid.uuid4())
            new_message = Message(
                message_id=msg_id,
                sender_id=admin_user.id,
                recipient_id=recipient_user.id,
                message=f"👑 Admin: {message_text}",
                msg_type='text',
                is_group=False
            )
            
            db.session.add(new_message)
            db.session.commit()
            
            # Send real-time message
            msg_data = {
                'id': msg_id,
                'sender': 'admin',
                'sender_data': {
                    'profile_pic': admin_user.profile_pic,
                    'email': admin_user.email
                },
                'recipient': recipient,
                'message': f"👑 Admin: {message_text}",
                'type': 'text',
                'file_url': '',
                'is_group': False,
                'timestamp': datetime.now().strftime('%I:%M %p'),
                'date': datetime.now().strftime('%Y-%m-%d'),
                'chat_id': f"admin_{recipient}"
            }
            
            if recipient in user_sockets:
                socketio.emit('receive_message', msg_data, room=user_sockets[recipient])
            
            # Also send to admin's own socket
            if session['username'] in user_sockets:
                socketio.emit('receive_message', msg_data, room=user_sockets[session['username']])
            
            return jsonify({'success': True, 'message': f'Message sent to {recipient}'})
            
    except Exception as e:
        db.session.rollback()
        logger.error(f"Admin send message error: {e}")
        return jsonify({'success': False, 'message': 'Failed to send message'})

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'username' not in session:
        return jsonify({'success': False})
    
    if 'file' not in request.files:
        return jsonify({'success': False})
    
    file = request.files['file']
    if file and file.filename and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"{timestamp}_{filename}"
        
        ext = filename.rsplit('.', 1)[1].lower()
        subfolder = 'images' if ext in {'png','jpg','jpeg','gif'} else 'videos' if ext in {'mp4','avi','mov'} else 'files'
        
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], subfolder, filename)
        file.save(filepath)
        
        return jsonify({'success': True, 'file_url': f"/static/uploads/{subfolder}/{filename}", 'file_type': subfolder})
    
    return jsonify({'success': False})

@app.route('/logout')
def logout():
    if 'username' in session:
        user = User.query.filter_by(username=session['username']).first()
        if user:
            # Update last seen
            user.last_seen = datetime.now()
            db.session.commit()
            # Log logout activity
            log_activity(user.id, 'logout', f'Logged out')
    
    session.clear()
    return redirect(url_for('login'))

# ========== WebSocket Events ==========

@socketio.on('connect')
def handle_connect():
    if 'username' in session:
        username = session['username']
        online_users[request.sid] = username
        user_sockets[username] = request.sid
        
        user = User.query.filter_by(username=username).first()
        
        # Log online activity
        if user:
            log_activity(user.id, 'online', 'User came online')
        
        emit('user_connected', {
            'username': username,
            'online_users': list(set(online_users.values())),
            'user_data': {
                'profile_pic': user.profile_pic,
                'email': user.email
            }
        }, broadcast=True)

@socketio.on('disconnect')
def handle_disconnect():
    if request.sid in online_users:
        username = online_users[request.sid]
        
        user = User.query.filter_by(username=username).first()
        if user:
            # Update last seen
            user.last_seen = datetime.now()
            db.session.commit()
            # Log offline activity
            log_activity(user.id, 'offline', 'User went offline')
        
        del online_users[request.sid]
        if username in user_sockets:
            del user_sockets[username]
        
        emit('user_disconnected', {
            'username': username,
            'online_users': list(set(online_users.values()))
        }, broadcast=True)

@socketio.on('send_message')
def handle_message(data):
    if 'username' not in session:
        return
    
    try:
        sender = session['username']
        sender_user = User.query.filter_by(username=sender).first()
        
        if not sender_user:
            return
        
        recipient = data.get('recipient')
        message = data.get('message')
        msg_type = data.get('type', 'text')
        file_url = data.get('file_url', '')
        is_group = data.get('is_group', False)
        
        msg_id = str(uuid.uuid4())
        
        # Save to database
        if is_group:
            group = Group.query.filter_by(group_id=recipient).first()
            new_message = Message(
                message_id=msg_id,
                sender_id=sender_user.id,
                group_id=group.id if group else None,
                message=message,
                msg_type=msg_type,
                file_url=file_url,
                is_group=True
            )
        else:
            recipient_user = User.query.filter_by(username=recipient).first()
            new_message = Message(
                message_id=msg_id,
                sender_id=sender_user.id,
                recipient_id=recipient_user.id if recipient_user else None,
                message=message,
                msg_type=msg_type,
                file_url=file_url,
                is_group=False
            )
        
        db.session.add(new_message)
        db.session.commit()
        
        # Log message sent activity
        log_activity(sender_user.id, 'message_sent', f'Sent message to {recipient}')
        
        msg_data = {
            'id': msg_id,
            'sender': sender,
            'sender_data': {
                'profile_pic': sender_user.profile_pic,
                'email': sender_user.email
            },
            'recipient': recipient,
            'message': message,
            'type': msg_type,
            'file_url': file_url,
            'is_group': is_group,
            'timestamp': datetime.now().strftime('%I:%M %p'),
            'date': datetime.now().strftime('%Y-%m-%d'),
            'chat_id': f"{sender}_{recipient}" if not is_group else f"group_{recipient}"
        }
        
        if is_group:
            # Group message - send to all group members
            group = Group.query.filter_by(group_id=recipient).first()
            if group:
                for member in group.members:
                    if member.username in user_sockets:
                        emit('receive_message', msg_data, room=user_sockets[member.username])
        else:
            # 1-on-1 message
            if sender in user_sockets:
                emit('receive_message', msg_data, room=user_sockets[sender])
            
            if recipient in user_sockets:
                emit('receive_message', msg_data, room=user_sockets[recipient])
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Send message error: {e}")

@socketio.on('get_messages')
def handle_get_messages(data):
    if 'username' not in session:
        return
    
    user1 = session['username']
    user2 = data.get('recipient')
    is_group = data.get('is_group', False)
    
    current_user = User.query.filter_by(username=user1).first()
    
    if is_group:
        group = Group.query.filter_by(group_id=user2).first()
        if group:
            messages = Message.query.filter_by(group_id=group.id, is_group=True).order_by(Message.created_at).all()
        else:
            messages = []
    else:
        other_user = User.query.filter_by(username=user2).first()
        if other_user:
            messages = Message.query.filter(
                ((Message.sender_id == current_user.id) & (Message.recipient_id == other_user.id)) |
                ((Message.sender_id == other_user.id) & (Message.recipient_id == current_user.id))
            ).order_by(Message.created_at).all()
            
            # Mark messages as read when opening chat
            unread_messages = Message.query.filter(
                Message.sender_id == other_user.id,
                Message.recipient_id == current_user.id,
                Message.is_read == False
            ).all()
            
            for msg in unread_messages:
                msg.is_read = True
            
            if unread_messages:
                db.session.commit()
                # Notify sender that messages were read
                socketio.emit('messages_read', {
                    'reader': user1,
                    'sender': user2
                })
        else:
            messages = []
    
    chat_messages = []
    for msg in messages:
        sender_user = db.session.get(User, msg.sender_id)
        chat_messages.append({
            'id': msg.message_id,
            'sender': sender_user.username,
            'sender_data': {
                'profile_pic': sender_user.profile_pic,
                'email': sender_user.email
            },
            'recipient': user2,
            'message': msg.message,
            'type': msg.msg_type,
            'file_url': msg.file_url,
            'is_group': msg.is_group,
            'timestamp': msg.created_at.strftime('%I:%M %p'),
            'date': msg.created_at.strftime('%Y-%m-%d')
        })
    
    emit('load_messages', {'messages': chat_messages})

@socketio.on('typing')
def handle_typing(data):
    recipient = data.get('recipient')
    is_group = data.get('is_group', False)
    
    typing_data = {
        'username': session['username'],
        'recipient': recipient,
        'is_group': is_group
    }
    
    if is_group:
        group = Group.query.filter_by(group_id=recipient).first()
        if group:
            for member in group.members:
                if member.username != session['username'] and member.username in user_sockets:
                    emit('user_typing', typing_data, room=user_sockets[member.username])
    else:
        if recipient in user_sockets:
            emit('user_typing', typing_data, room=user_sockets[recipient])

@socketio.on('delete_message')
def handle_delete_message(data):
    msg_id = data.get('message_id')
    message = Message.query.filter_by(message_id=msg_id).first()
    
    if message:
        if message.is_group:
            group = db.session.get(Group, message.group_id)
            if group:
                for member in group.members:
                    if member.username in user_sockets:
                        emit('message_deleted', {'message_id': msg_id}, room=user_sockets[member.username])
        else:
            sender = db.session.get(User, message.sender_id)
            recipient = db.session.get(User, message.recipient_id)
            
            if sender and sender.username in user_sockets:
                emit('message_deleted', {'message_id': msg_id}, room=user_sockets[sender.username])
            if recipient and recipient.username in user_sockets:
                emit('message_deleted', {'message_id': msg_id}, room=user_sockets[recipient.username])
        
        db.session.delete(message)
        db.session.commit()

# ========== Main ==========

if __name__ == '__main__':
    print("=" * 60)
    print("🚀 Speed Transfer Chat Application Starting...")
    print("=" * 60)
    print(f"📍 Server: http://localhost:5000")
    print(f"💾 Database: SQLite (speedtransfer.db)")
    print(f"👤 Admin Login: admin / admin123")
    print(f"🔑 Admin User ID: ADMIN-SYS-ROOT")
    print(f"📝 User ID Format: USR-YYYYMMDD-XXXXXXXX")
    print("=" * 60)
    print("\n✨ Features:")
    print("  • Real-time messaging with WebSocket")
    print("  • User & Group chat support")
    print("  • File uploads (images, videos, documents)")
    print("  • Admin dashboard with user management")
    print("  • Admin broadcast messaging")
    print("  • Force logout for banned users")
    print("  • Online status tracking")
    print("  • Profile customization")
    print("  • Activity logging & tracking")
    print("  • Custom User ID (changeable)")
    print("  • Device detection (iPhone, Android, Windows, Mac, Linux)")
    print("=" * 60)
    
    try:
        socketio.run(app, debug=False, host='0.0.0.0', port=5000, log_output=False)
    except KeyboardInterrupt:
        print("\n👋 Server stopped by user")
    except Exception as e:
        print(f"❌ Server error: {e}")
