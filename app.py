from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
import os
import base64
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import json
from datetime import datetime
from functools import wraps

app = Flask(__name__)
app.secret_key = 'your-secret-key-here-change-in-production'
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Tạo thư mục uploads nếu chưa có
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Database giả lập
USERS_FILE = 'users.json'

# Tạo admin mặc định
def init_admin():
    users = load_users()
    if 'admin' not in users:
        users['admin'] = {
            'email': 'admin@matias.com',
            'password': generate_password_hash('admin123'),
            'role': 'admin',
            'created_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }
        save_users(users)
        print("✅ Tài khoản admin đã được tạo!")
        print("Username: admin")
        print("Password: admin123")

def load_users():
    if os.path.exists(USERS_FILE):
        with open(USERS_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    return {}

def save_users(users):
    with open(USERS_FILE, 'w', encoding='utf-8') as f:
        json.dump(users, f, ensure_ascii=False, indent=2)

# Decorator để bảo vệ route
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            flash('Vui lòng đăng nhập để tiếp tục', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            flash('Vui lòng đăng nhập để tiếp tục', 'warning')
            return redirect(url_for('login'))
        
        users = load_users()
        if users.get(session['user'], {}).get('role') != 'admin':
            flash('Bạn không có quyền truy cập trang này', 'error')
            return redirect(url_for('home'))
        return f(*args, **kwargs)
    return decorated_function

@app.route("/")
def home():
    is_logged_in = 'user' in session
    username = session.get('user', None)
    return render_template("index.html", is_logged_in=is_logged_in, username=username)

@app.route("/settings")
def settings():
    is_logged_in = 'user' in session
    username = session.get('user', None)
    users = load_users()
    user_data = users.get(username, {}) if username else {}
    return render_template("settings.html", 
                         is_logged_in=is_logged_in, 
                         username=username,
                         user_data=user_data)

@app.route("/tienich")
@login_required
def tienich():
    users = load_users()
    user_data = users.get(session['user'], {})
    return render_template("tienich.html", 
                         username=session.get('user'),
                         role=user_data.get('role', 'user'))

@app.route("/blog")
def blog():
    is_logged_in = 'user' in session
    username = session.get('user', None)
    return render_template("blog.html", is_logged_in=is_logged_in, username=username)

@app.route("/contact")
def contact():
    is_logged_in = 'user' in session
    username = session.get('user', None)
    return render_template("contact.html", is_logged_in=is_logged_in, username=username)

# Admin Dashboard
@app.route("/admin")
@admin_required
def admin_dashboard():
    users = load_users()
    user_list = []
    
    for username, data in users.items():
        user_list.append({
            'username': username,
            'email': data.get('email'),
            'role': data.get('role', 'user'),
            'created_at': data.get('created_at')
        })
    
    return render_template("admin.html", 
                         users=user_list,
                         admin_name=session.get('user'))

@app.route("/admin/delete_user/<username>", methods=['POST'])
@admin_required
def delete_user(username):
    if username == 'admin':
        flash('Không thể xóa tài khoản admin', 'error')
        return redirect(url_for('admin_dashboard'))
    
    users = load_users()
    if username in users:
        del users[username]
        save_users(users)
        flash(f'Đã xóa tài khoản {username}', 'success')
    else:
        flash('Người dùng không tồn tại', 'error')
    
    return redirect(url_for('admin_dashboard'))

@app.route("/admin/change_role/<username>", methods=['POST'])
@admin_required
def change_role(username):
    if username == 'admin':
        flash('Không thể thay đổi quyền của admin', 'error')
        return redirect(url_for('admin_dashboard'))
    
    users = load_users()
    if username in users:
        current_role = users[username].get('role', 'user')
        new_role = 'admin' if current_role == 'user' else 'user'
        users[username]['role'] = new_role
        save_users(users)
        flash(f'Đã thay đổi quyền của {username} thành {new_role}', 'success')
    else:
        flash('Người dùng không tồn tại', 'error')
    
    return redirect(url_for('admin_dashboard'))

# Authentication Routes
@app.route("/login", methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        users = load_users()
        
        if username in users and check_password_hash(users[username]['password'], password):
            session['user'] = username
            session['role'] = users[username].get('role', 'user')
            
            # Redirect admin to admin dashboard
            if users[username].get('role') == 'admin':
                flash('Chào mừng Admin!', 'success')
                return redirect(url_for('admin_dashboard'))
            else:
                flash('Đăng nhập thành công!', 'success')
                return redirect(url_for('tienich'))
        else:
            flash('Tên đăng nhập hoặc mật khẩu không đúng', 'error')
    
    return render_template("login.html")

@app.route("/register", methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        users = load_users()
        
        if username in users:
            flash('Tên đăng nhập đã tồn tại', 'error')
        elif password != confirm_password:
            flash('Mật khẩu xác nhận không khớp', 'error')
        elif len(password) < 6:
            flash('Mật khẩu phải có ít nhất 6 ký tự', 'error')
        else:
            users[username] = {
                'email': email,
                'password': generate_password_hash(password),
                'role': 'user',  # Mặc định là user
                'created_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }
            save_users(users)
            flash('Đăng ký thành công! Vui lòng đăng nhập', 'success')
            return redirect(url_for('login'))
    
    return render_template("register.html")

@app.route("/logout")
def logout():
    session.pop('user', None)
    session.pop('role', None)
    flash('Đã đăng xuất', 'info')
    return redirect(url_for('home'))

# Utility Routes
@app.route("/encode_image", methods=['POST'])
@login_required
def encode_image():
    if 'image' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400
    
    file = request.files['image']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
    # Đọc file và encode base64
    image_data = file.read()
    encoded = base64.b64encode(image_data).decode('utf-8')
    
    return jsonify({
        'success': True,
        'encoded': encoded,
        'filename': file.filename,
        'size': len(image_data)
    })

@app.route("/decode_image", methods=['POST'])
@login_required
def decode_image():
    data = request.get_json()
    encoded_string = data.get('encoded')
    
    if not encoded_string:
        return jsonify({'error': 'No encoded string provided'}), 400
    
    try:
        # Decode base64
        decoded = base64.b64decode(encoded_string)
        
        # Lưu file tạm
        filename = f"decoded_{datetime.now().strftime('%Y%m%d%H%M%S')}.png"
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        
        with open(filepath, 'wb') as f:
            f.write(decoded)
        
        return jsonify({
            'success': True,
            'url': url_for('static', filename=f'uploads/{filename}'),
            'size': len(decoded)
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 400

if __name__ == "__main__":
    init_admin()  # Tạo admin khi khởi động
    app.run(debug=True)