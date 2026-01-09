import datetime
import time
import random
import uuid
import os
import re
import requests
import traceback
import secrets
from functools import wraps
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, Response
from flask_mail import Mail, Message
from PIL import Image, ImageDraw, ImageFont
from sqlalchemy import or_, and_, desc

# --- NEW DB IMPORTS ---
from database import db  # Import the db object from our new file
import models            # Import our new models

# -------------------------------------
# 1. FLASK APP INITIALIZATION & CONFIGURATION
# -------------------------------------
app = Flask(__name__)
app.secret_key = 'a-very-complex-and-unpredictable-secret-key-for-dev'

# --- DATABASE CONFIGURATION ---
# Best Practice: Use Environment Variable, fallback to your string if not found
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv(
    'DATABASE_URL', 
    'postgresql://postgres:9342621245@localhost:5001/securebank'
)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# --- Flask-Mail Configuration ---
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'rohansarkar6361@gmail.com'
app.config['MAIL_PASSWORD'] = '' # Your Google App Password
app.config['MAIL_DEFAULT_SENDER'] = ('SecureBank', 'rohansarkar6361@gmail.com')

mail = Mail(app)

# --- File Upload Configuration ---
UPLOAD_FOLDER = 'static/images/avatars'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

# --- MASTER ADMIN EMAIL ---
MASTER_ADMIN_EMAIL = 'rohansarkar6361@gmail.com' 

# --- INITIALIZE DATABASE ---
db.init_app(app)

# --- CREATE TABLES ---
with app.app_context():
    db.create_all() 
    
    # --- Seed default admin user (only if it doesn't exist) ---
    if not models.User.query.filter_by(role='admin').first():
        print("Creating default admin user...")
        admin_email = 'rohansarkar6361@gmail.com'
        admin_pass = '9342621245'
        
        admin_user = models.User(
            email=admin_email,
            password_hash=generate_password_hash(admin_pass),
            role='admin',
            full_name='Administrator'
        )
        db.session.add(admin_user)
        db.session.commit()
        print(f"Default admin user created. Email: {admin_email}")

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# -------------------------------------
# 2. GLOBAL ERROR HANDLER
# -------------------------------------
@app.errorhandler(Exception)
def handle_global_exception(e):
    try:
        db.session.rollback()
    except Exception as rb_e:
        print(f"--- ERROR during rollback: {rb_e} ---")
        
    traceback.print_exc()
    return render_template('error.html', error=str(e)), 500

# -------------------------------------
# 3. CONTEXT PROCESSOR (Updated for Dashboard Link)
# -------------------------------------
@app.context_processor
def inject_user_data():
    """
    Injects current_user and the correct dashboard_url 
    into ALL templates automatically.
    """
    context = {
        'current_user': None,
        'dashboard_url': url_for('login')
    }

    if 'user_id' in session:
        user = db.session.get(models.User, session['user_id'])
        if user:
            context['current_user'] = user
            # CHANGE: Dynamically set where the "Back to Dashboard" button goes
            if user.role == 'admin':
                context['dashboard_url'] = url_for('admin_dashboard')
            else:
                context['dashboard_url'] = url_for('dashboard')
                
    return context

@app.template_filter('strftime')
def _jinja2_filter_datetime(ts, fmt='%Y-%m-%d %H:%M'):
    if not isinstance(ts, (int, float)): return ts
    return datetime.datetime.fromtimestamp(ts).strftime(fmt)

# -------------------------------------
# 4. HELPER FUNCTIONS & DECORATORS
# -------------------------------------
def send_email_alert(to_email, subject, body_html):
    try:
        msg = Message(subject, recipients=[to_email])
        msg.html = body_html
        mail.send(msg)
    except Exception as e:
        print(f"--- FAILED TO SEND EMAIL to {to_email}: {e} ---")

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def get_location_from_ip(ip_address):
    if ip_address == '127.0.0.1':
        return "Local Host (IP)"
    try:
        response = requests.get(f"http://ip-api.com/json/{ip_address}", timeout=5)
        data = response.json()
        if data['status'] == 'success':
            return f"{data.get('city', 'N/A')}, {data.get('regionName', 'N/A')}, {data.get('country', 'N/A')} (IP)"
    except Exception:
        return "Location (IP) not found"
    return "Location (IP) not found"

def get_location_from_coords(lat, lon):
    if not lat or not lon:
        return "High-Precision Location Not Provided"
    try:
        url = f"https://nominatim.openstreetmap.org/reverse?format=json&lat={lat}&lon={lon}"
        headers = {'User-Agent': 'SecureBankApp/1.0'}
        response = requests.get(url, headers=headers, timeout=5)
        data = response.json()
        address = data.get('address', {})
        display_name = data.get('display_name', 'Unknown Location')
        city = address.get('city', address.get('town', ''))
        state = address.get('state', '')
        country = address.get('country', '')
        if city and state and country:
            return f"{city}, {state}, {country} (GPS)"
        else:
            return f"{display_name.split(',')[0]}, {country} (GPS)"
    except Exception as e:
        print(f"Reverse geocoding failed: {e}")
        return "Location (GPS) Lookup Failed"

def is_password_strong(password):
    if len(password) < 8: return False, "Password must be at least 8 characters long."
    if not re.search(r"[A-Z]", password): return False, "Password must contain an uppercase letter."
    if not re.search(r"[a-z]", password): return False, "Password must contain a lowercase letter."
    if not re.search(r"\d", password): return False, "Password must contain a digit."
    if not re.search(r"[!@#$%^&*(),.?:{}|<>]", password): return False, "Password must contain a special symbol."
    return True, ""

def login_required(role="any"):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user_id' not in session or not session.get('2fa_passed'):
                flash("You must be logged in to view this page.", "danger")
                return redirect(url_for('login'))
            
            user = db.session.get(models.User, session['user_id'])
            
            if not user or (role != "any" and user.role != role):
                flash("Permission denied.", "danger")
                # Redirect intelligently based on actual role
                if user and user.role == 'admin':
                    return redirect(url_for('admin_dashboard'))
                return redirect(url_for('dashboard'))
                
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def get_user_and_account(user_id):
    user = db.session.get(models.User, user_id)
    if not user: 
        return None, None, None
    # user.account is available from the relationship
    return user, user.account, (user.account.account_number if user.account else None)

# -------------------------------------
# 5. AUTHENTICATION & CORE ROUTES
# -------------------------------------
@app.route('/')
def index():
    if 'user_id' in session:
        user = db.session.get(models.User, session['user_id'])
        if user:
            if user.role == 'admin':
                return redirect(url_for('admin_dashboard'))
            return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    role = request.args.get('role', 'user')

    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        if password != request.form['confirm_password']:
            flash("Passwords do not match.", "danger")
            return redirect(url_for('signup', role=role))
        
        is_strong, message = is_password_strong(password)
        if not is_strong:
            flash(message, "danger")
            return redirect(url_for('signup', role=role))
            
        if models.User.query.filter_by(email=email).first() or \
           models.PendingAdmin.query.filter_by(email=email).first():
            flash("An account with this email already exists or is pending approval.", "danger")
            return redirect(url_for('signup', role=role))
        
        if role == 'admin':
            pending_admin = models.PendingAdmin(
                email=email,
                password_hash=generate_password_hash(password),
                timestamp=time.time()
            )
            db.session.add(pending_admin)
            db.session.commit()
            
            approve_url = url_for('approve_admin', token=pending_admin.token, _external=True)
            disapprove_url = url_for('disapprove_admin', token=pending_admin.token, _external=True)
            
            email_body = f"""<h3>New Administrator Request</h3><p><b>Email:</b> {email}</p>
                             <a href="{approve_url}">Approve</a> | <a href="{disapprove_url}">Disapprove</a>"""
            send_email_alert(MASTER_ADMIN_EMAIL, "New Admin Request for SecureBank", email_body)
            
            flash("Your administrator request has been submitted. It is pending approval.", "info")
            return redirect(url_for('login', role='admin'))

        else:
            otp = str(random.randint(100000, 999999))
            session['pending_user'] = {
                'email': email,
                'password_hash': generate_password_hash(password),
                'otp': otp,
                'timestamp': time.time()
            }
            
            email_body = f"<h3>Welcome to SecureBank!</h3><p>Your account verification OTP is: <b>{otp}</b></p>"
            send_email_alert(email, "Verify Your SecureBank Account", email_body)
            
            flash("A verification code has been sent to your email.", "info")
            return redirect(url_for('verify_signup'))
        
    return render_template('signup.html', title="Sign Up", role=role)

@app.route('/verify-signup', methods=['GET', 'POST'])
def verify_signup():
    if 'pending_user' not in session:
        flash("No pending registration found. Please sign up again.", "warning")
        return redirect(url_for('signup'))
    
    pending_user = session['pending_user']
    
    if time.time() - pending_user.get('timestamp', 0) > 300: # 5 min expiry
        session.pop('pending_user', None)
        flash("Your OTP has expired. Please sign up again.", "danger")
        return redirect(url_for('signup'))

    if request.method == 'POST':
        if request.form['otp'] == pending_user['otp']:
            try:
                new_user = models.User(
                    email=pending_user['email'],
                    password_hash=pending_user['password_hash']
                )
                
                new_account = models.Account(
                    account_number='SB' + ''.join(random.choices('0123456789', k=10)),
                    balance=1000.0,
                    user=new_user
                )
                
                db.session.add(new_user)
                db.session.add(new_account)
                db.session.commit()
                
                session.pop('pending_user', None)
                flash("Account created successfully! You can now log in.", "success")
                return redirect(url_for('login'))
            except Exception as e:
                db.session.rollback()
                print(f"Error in verify_signup: {e}")
                flash("This email or account number might already be taken.", "danger")
                return redirect(url_for('signup'))
        else:
            flash("Invalid OTP. Please try again.", "danger")
            
    return render_template('verify_signup_otp.html', title="Verify Account")

@app.route('/login', methods=['GET', 'POST'])
def login():
    role = request.args.get('role', 'user')

    if request.method == 'POST':
        captcha_input = request.form.get('captcha', '').lower()
        if captcha_input != session.get('captcha_text', '').lower():
            flash("Invalid captcha.", "danger")
            return redirect(url_for('login', role=role))
        
        email = request.form['email']
        password = request.form['password']
        
        user = models.User.query.filter_by(email=email).first()
        
        if not user:
            flash("Invalid credentials.", "danger")
            return redirect(url_for('login', role=role))
            
        if user.locked:
            flash("Your account is locked. Please contact an administrator.", "danger")
            return redirect(url_for('login', role=role))

        if check_password_hash(user.password_hash, password):
            user.login_attempts = 0
            otp = str(random.randint(100000, 999999))
            user.otps = {otp: time.time()}
            
            db.session.commit()
            
            session['login_user_id'] = user.id
            
            email_body = f"<h3>Your SecureBank Login OTP is: {otp}</h3><p>It is valid for 5 minutes.</p>"
            send_email_alert(user.email, "Your SecureBank Login OTP", email_body)
            
            return redirect(url_for('verify_otp'))
        else:
            user.login_attempts = user.login_attempts + 1
            if user.login_attempts >= 3:
                user.locked = True
            db.session.commit()
            
            flash("Invalid credentials.", "danger")
            return redirect(url_for('login', role=role))

    return render_template('login.html', title="Login", role=role)

@app.route('/captcha.png')
def captcha():
    text = ''.join(random.choices('ABCDEFGHJKLMNPQRSTUVWXYZ23456789', k=5))
    session['captcha_text'] = text
    img = Image.new('RGB', (150, 50), color=(25, 35, 50))
    d = ImageDraw.Draw(img)
    try:
        font_path = "arial.ttf" if os.name == 'nt' else "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"
        if not os.path.exists(font_path): font_path = "arial.ttf"
        font = ImageFont.truetype(font_path, 30)
    except IOError:
        font = ImageFont.load_default()
    d.text((10, 10), text, fill=(200, 210, 220), font=font)
    for _ in range(70):
        d.point((random.randint(0, 150), random.randint(0, 50)), fill=(random.randint(50, 150),)*3)
    import io
    buf = io.BytesIO()
    img.save(buf, 'PNG')
    buf.seek(0)
    return Response(buf, mimetype='image/png')


@app.route('/verify_otp', methods=['GET', 'POST'])
def verify_otp():
    if 'login_user_id' not in session: return redirect(url_for('login'))
    
    user = db.session.get(models.User, session['login_user_id'])
    if not user: return redirect(url_for('login'))
    
    if request.method == 'POST':
        submitted_otp = request.form['otp']
        user_otps = user.otps or {}
        
        if submitted_otp in user_otps and (time.time() - user_otps[submitted_otp] < 300):
            session['user_id'] = user.id
            session['2fa_passed'] = True
            session['profile_pic_version'] = str(time.time())
            session.pop('login_user_id', None)
            user.otps = {} 
            
            latitude = request.form.get('latitude')
            longitude = request.form.get('longitude')
            location = get_location_from_coords(latitude, longitude) if (latitude and longitude) else get_location_from_ip(request.remote_addr)

            login_record = models.LoginHistory(
                ip_address=request.remote_addr,
                device_info=request.user_agent.string,
                location=location,
                latitude=latitude,
                longitude=longitude,
                user_id=user.id
            )
            db.session.add(login_record)
            db.session.commit()
            
            return redirect(url_for('index'))
        else:
            flash("Invalid or expired OTP.", "danger")
            
    return render_template('verify_otp.html', title="Verify OTP")

@app.route('/logout')
def logout():
    session.clear()
    flash("You have been successfully logged out.", "success")
    return redirect(url_for('login'))

# -------------------------------------
# 6. PASSWORD RESET ROUTES
# -------------------------------------
@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        user = models.User.query.filter_by(email=email).first()
        
        if user:
            token = secrets.token_urlsafe(32)
            user.reset_token = token
            user.reset_token_expiry = time.time() + 3600
            db.session.commit()
            
            reset_url = url_for('reset_password', token=token, _external=True)
            email_body = f"""
                <h3>Password Reset Request</h3>
                <p>Click below to reset your password (valid for 1 hour):</p>
                <a href="{reset_url}">{reset_url}</a>
            """
            send_email_alert(user.email, "Reset Your SecureBank Password", email_body)
            
        flash("If an account with that email exists, a password reset link has been sent.", "info")
        return redirect(url_for('login'))
        
    return render_template('forgot_password.html', title="Forgot Password")

@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    user = models.User.query.filter_by(reset_token=token).first()
    
    if not user or user.reset_token_expiry < time.time():
        flash("The password reset link is invalid or has expired.", "danger")
        return redirect(url_for('forgot_password'))
        
    if request.method == 'POST':
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']
        
        if new_password != confirm_password:
            flash("Passwords do not match.", "danger")
            return redirect(url_for('reset_password', token=token))
            
        is_strong, message = is_password_strong(new_password)
        if not is_strong:
            flash(message, "danger")
            return redirect(url_for('reset_password', token=token))
        
        user.password_hash = generate_password_hash(new_password)
        user.reset_token = None
        user.reset_token_expiry = None
        db.session.commit()
        
        flash("Your password has been reset successfully! You can now log in.", "success")
        return redirect(url_for('login'))
    
    return render_template('reset_password.html', title="Reset Your Password", token=token)

@app.route('/approve-admin/<token>')
def approve_admin(token):
    pending_admin = db.session.get(models.PendingAdmin, token)
    
    if not pending_admin:
        flash("Invalid or expired approval token.", "danger")
        return redirect(url_for('login', role='admin'))
        
    email = pending_admin.email
    
    if models.User.query.filter_by(email=email).first():
        flash(f"An account for {email} already exists. Cannot approve.", "danger")
        db.session.delete(pending_admin)
        db.session.commit()
        return redirect(url_for('login', role='admin'))
        
    new_admin = models.User(
        email=email,
        password_hash=pending_admin.password_hash,
        role='admin',
        full_name='New Administrator'
    )
    db.session.add(new_admin)
    db.session.delete(pending_admin)
    db.session.commit()
    
    send_email_alert(email, "Your SecureBank Account is Approved",
                     "<h3>Your administrator account for SecureBank has been approved.</h3><p>You can now log in.</p>")
    
    flash(f"Administrator {email} has been approved and created.", "success")
    return redirect(url_for('login', role='admin'))

@app.route('/disapprove-admin/<token>')
def disapprove_admin(token):
    pending_admin = db.session.get(models.PendingAdmin, token)
    
    if pending_admin:
        email = pending_admin.email
        db.session.delete(pending_admin)
        db.session.commit()
        
        send_email_alert(email, "Your SecureBank Account Request",
                         "<h3>Your administrator account request for SecureBank has been reviewed.</h3><p>We regret to inform you that your request was not approved.</p>")
        flash(f"Administrator request for {email} has been disapproved.", "info")
    else:
        flash("Invalid or expired approval token.", "danger")
        
    return redirect(url_for('login', role='admin'))

# -------------------------------------
# 7. PROFILE & DASHBOARD
# -------------------------------------
@app.route('/dashboard')
@login_required()
def dashboard():
    user, account, account_number = get_user_and_account(session['user_id'])
    
    # CHANGE: Prevent admins from accessing user dashboard
    if user.role == 'admin':
        return redirect(url_for('admin_dashboard'))
    
    user_transactions = models.Transaction.query.filter(
        or_(
            models.Transaction.sender_account == account_number,
            models.Transaction.recipient_account == account_number
        )
    ).order_by(desc(models.Transaction.timestamp)).all()
    
    return render_template('dashboard.html', title="Dashboard", user=user, account=account, account_number=account_number, transactions=user_transactions)

@app.route('/profile')
@login_required()
def profile():
    user, _, _ = get_user_and_account(session['user_id'])
    return render_template('profile.html', title="My Profile", user=user)

@app.route('/profile/update', methods=['POST'])
@login_required()
def update_profile():
    user, _, _ = get_user_and_account(session['user_id'])
    
    user.full_name = request.form.get('full_name')
    user.dob = request.form.get('dob')
    user.phone_number = request.form.get('phone_number')
    user.address = request.form.get('address')
    
    db.session.commit()
    flash("Profile details updated successfully!", "success")
    return redirect(url_for('profile'))

@app.route('/profile/update_picture', methods=['POST'])
@login_required()
def update_profile_picture():
    user, _, _ = get_user_and_account(session['user_id'])
    file = request.files.get('croppedImage')
    
    if not file or not allowed_file(file.filename):
        flash('Invalid image file received.', 'danger')
        return redirect(url_for('profile'))
        
    filename = secure_filename(file.filename)
    unique_filename = f"{uuid.uuid4()}_{filename}"
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
    
    try:
        file.save(filepath)
        user.profile_picture_url = f'/static/images/avatars/{unique_filename}'
        db.session.commit()
        session['profile_pic_version'] = str(time.time())
        flash('Profile picture updated!', 'success')
    except Exception as e:
        flash(f'Error saving file: {e}', 'danger')
        
    return redirect(url_for('profile'))

@app.route('/profile/change_password', methods=['POST'])
@login_required()
def change_password():
    user, _, _ = get_user_and_account(session['user_id'])
    
    if not check_password_hash(user.password_hash, request.form['current_password']):
        flash("Current password incorrect.", "danger")
        return redirect(url_for('profile'))
    
    new_password = request.form['new_password']
    if new_password != request.form['confirm_password']:
        flash("New passwords do not match.", "danger")
        return redirect(url_for('profile'))
        
    is_strong, message = is_password_strong(new_password)
    if not is_strong:
        flash(message, "danger")
        return redirect(url_for('profile'))
        
    user.password_hash = generate_password_hash(new_password)
    db.session.commit()
    
    flash("Password changed successfully!", "success")
    return redirect(url_for('profile'))

@app.route('/profile/set_mpin', methods=['POST'])
@login_required()
def set_mpin():
    user, _, _ = get_user_and_account(session['user_id'])
    mpin = request.form.get('mpin')

    if not mpin or not mpin.isdigit() or len(mpin) != 4:
        flash("MPIN must be 4 digits.", "danger")
        return redirect(url_for('profile'))
    if mpin != request.form.get('confirm_mpin'):
        flash("MPINs do not match.", "danger")
        return redirect(url_for('profile'))

    user.mpin_hash = generate_password_hash(mpin)
    db.session.commit()
    
    flash("MPIN has been set successfully!", "success")
    return redirect(url_for('profile'))

# -------------------------------------
# 8. MONEY TRANSFER & HISTORY
# -------------------------------------
@app.route('/history')
@login_required()
def history():
    user, account, account_number = get_user_and_account(session['user_id'])
    
    user_transactions = models.Transaction.query.filter(
        or_(
            models.Transaction.sender_account == account_number,
            models.Transaction.recipient_account == account_number
        )
    ).order_by(desc(models.Transaction.timestamp)).all()
    
    user_logins = models.LoginHistory.query.filter_by(
        user_id=user.id
    ).order_by(desc(models.LoginHistory.timestamp)).all()
    
    return render_template('history.html', title="History", transactions=user_transactions, logins=user_logins, account_number=account_number)

@app.route('/location-map')
@login_required()
def location_map():
    target_user_id = request.args.get('user_id')
    current_user = db.session.get(models.User, session['user_id'])
    
    user_to_view = None
    
    if target_user_id and current_user.role == 'admin':
        user_to_view = db.session.get(models.User, target_user_id)
        if not user_to_view:
            flash("User not found.", "danger")
            return redirect(url_for('admin_dashboard'))
    else:
        user_to_view = current_user

    user_logins = models.LoginHistory.query.filter_by(
        user_id=user_to_view.id
    ).order_by(desc(models.LoginHistory.timestamp)).all()
    
    login_locations = [
        {
            "lat": login.latitude, 
            "lon": login.longitude, 
            "location": login.location,
            "ip": login.ip_address,
            "time": login.timestamp
        } 
        for login in user_logins if login.latitude and login.longitude
    ]
    
    return render_template('location_map.html', 
                           title=f"Login Map for {user_to_view.email}", 
                           login_locations=login_locations)

@app.route('/api/verify-recipient', methods=['POST'])
@login_required()
def verify_recipient():
    recipient_account_num = request.json.get('account_number')
    account = db.session.get(models.Account, recipient_account_num)
    
    if account and account.user:
        return jsonify({'status': 'success', 'recipient_name': account.user.full_name or 'Name not set'})
    
    return jsonify({'status': 'error', 'message': 'Account not found'}), 404

@app.route('/transfer', methods=['POST'])
@login_required()
def transfer():
    user, sender_account, _ = get_user_and_account(session['user_id'])
    
    if not user.mpin_hash:
        flash("You must set an MPIN in your profile before making transfers.", "danger")
        return redirect(url_for('dashboard'))

    amount = float(request.form['amount'])
    if sender_account.balance < amount:
        flash("Insufficient funds.", "danger")
        return redirect(url_for('dashboard'))
        
    otp = str(random.randint(100000, 999999))
    user.transfer_otp = {
        'otp': otp, 
        'timestamp': time.time(), 
        'details': { 
            'recipient_account': request.form['recipient_account'], 
            'recipient_name': request.form['recipient_name'], 
            'amount': amount 
        }
    }
    db.session.commit()
    
    email_body = f"<h3>Confirm Your Transfer</h3><p>Use OTP {otp} to confirm your transfer.</p>"
    send_email_alert(user.email, "Confirm Your SecureBank Transfer", email_body)
    
    flash("An OTP has been sent to your email.", "info")
    return redirect(url_for('transfer_otp'))

@app.route('/transfer/otp', methods=['GET', 'POST'])
@login_required()
def transfer_otp():
    user, sender_account, sender_account_num = get_user_and_account(session['user_id'])
    transfer_data = user.transfer_otp or {}
    details = transfer_data.get('details')
    
    if not details:
        flash("No pending transfer found.", "warning")
        return redirect(url_for('dashboard'))
        
    if request.method == 'POST':
        if not check_password_hash(user.mpin_hash, request.form.get('mpin')):
            flash("Incorrect MPIN.", "danger")
            return render_template('transfer_otp.html', title="Confirm Transfer", details=details)

        user_otp = transfer_data.get('otp')
        otp_time = transfer_data.get('timestamp', 0)
        
        if request.form['otp'] == user_otp and (time.time() - otp_time < 300):
            amount = float(details['amount'])
            recipient_account_num = details['recipient_account']
            
            sender_account = db.session.get(models.Account, sender_account_num)
            recipient_account = db.session.get(models.Account, recipient_account_num)

            if not recipient_account:
                flash("Recipient account no longer exists.", "danger")
                return redirect(url_for('dashboard'))

            if sender_account.balance < amount:
                flash("Transaction failed. Your balance is now too low.", "danger")
                return redirect(url_for('dashboard'))

            sender_account.balance -= amount
            recipient_account.balance += amount
            
            tx = models.Transaction(
                sender_account=sender_account_num,
                recipient_account=recipient_account_num,
                recipient_name=details['recipient_name'],
                amount=amount,
                status='Completed'
            )
            db.session.add(tx)
            user.transfer_otp = {}
            db.session.commit()
            
            flash("Transfer completed!", "success")
            return redirect(url_for('dashboard'))
        else:
            flash("Invalid or expired OTP.", "danger")
            
    return render_template('transfer_otp.html', title="Confirm Transfer", details=details)

@app.route('/emergency', methods=['POST'])
@login_required()
def emergency():
    _, account, _ = get_user_and_account(session['user_id'])
    
    account.emergency_mode = not account.emergency_mode
    db.session.commit()
    
    status = "activated" if account.emergency_mode else "deactivated"
    flash(f"Emergency mode has been {status}.", "warning")
    return redirect(url_for('dashboard'))

# -------------------------------------
# 9. ADMIN PANEL
# -------------------------------------
@app.route('/admin')
@login_required(role='admin')
def admin_dashboard():
    failed_transactions = models.Transaction.query.filter_by(status='Failed').all()
    all_users = models.User.query.filter_by(role='user').all()
    
    admin_logins = db.session.query(models.LoginHistory).join(models.User).filter(models.User.role == 'admin').order_by(desc(models.LoginHistory.timestamp)).all()

    return render_template('admin_dashboard.html', title="Admin Panel", 
                           users=all_users, 
                           transactions=failed_transactions,
                           admin_logins=admin_logins)

@app.route('/admin/view_profile/<user_id>')
@login_required(role='admin')
def admin_view_profile(user_id):
    user, account, _ = get_user_and_account(user_id)
    if not user:
        flash("User not found.", "danger")
        return redirect(url_for('admin_dashboard'))
    return render_template('admin_view_profile.html', title="View Profile", user=user, account=account)

@app.route('/admin/toggle_lock/<user_id>', methods=['POST'])
@login_required(role='admin')
def admin_toggle_lock(user_id):
    user = db.session.get(models.User, user_id)
    if user:
        user.locked = not user.locked
        if not user.locked: 
            user.login_attempts = 0
        db.session.commit()
        status = "locked" if user.locked else "unlocked"
        flash(f"User {user.email} has been {status}.", "success")
    else:
        flash("User not found.", "danger")
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/search', methods=['POST'])
@login_required(role='admin')
def admin_search():
    account_number = request.form.get('account_number')
    account = db.session.get(models.Account, account_number)
    
    if not account:
        flash(f"No account found: {account_number}.", "danger")
        return redirect(url_for('admin_dashboard'))
        
    user = account.user
    
    user_transactions = models.Transaction.query.filter(
        or_(
            models.Transaction.sender_account == account_number,
            models.Transaction.recipient_account == account_number
        )
    ).order_by(desc(models.Transaction.timestamp)).all()
    
    user_logins = models.LoginHistory.query.filter_by(
        user_id=user.id
    ).order_by(desc(models.LoginHistory.timestamp)).all()
    
    return render_template('admin_search_results.html', title=f"History for {account_number}", 
                           user=user, account=account, account_number=account_number, 
                           transactions=user_transactions, logins=user_logins)

@app.route('/admin/credit', methods=['POST'])
@login_required(role="admin")
def admin_credit():
    account_number = request.form['account_number']
    amount = float(request.form['amount'])
    
    account = db.session.get(models.Account, account_number)
    
    if account:
        account.balance += amount
        tx = models.Transaction(
            sender_account=None,
            recipient_account=account_number,
            amount=amount,
            status='Completed',
            type=request.form.get('reason', 'Admin Credit')
        )
        db.session.add(tx)
        db.session.commit()
        flash(f"Credited ₹{amount:.2f} to {account_number}.", "success")
    else:
        flash("Account not found.", "danger")
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/update_balance', methods=['POST'])
@login_required(role="admin")
def admin_update_balance():
    account_number = request.form['account_number']
    new_balance = float(request.form['new_balance'])
    
    account = db.session.get(models.Account, account_number)
    
    if account:
        account.balance = new_balance
        tx = models.Transaction(
            sender_account=None,
            recipient_account=account_number,
            amount=new_balance,
            status='Completed',
            type="Balance Correction"
        )
        db.session.add(tx)
        db.session.commit()
        flash(f"Balance for {account_number} updated to ₹{new_balance:.2f}.", "success")
    else:
        flash("Account not found.", "danger")
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/refund', methods=['POST'])
@login_required(role="admin")
def admin_refund():
    tx_id = request.form['transaction_id']
    transaction = db.session.get(models.Transaction, tx_id)

    if not transaction:
        flash("Transaction not found.", "danger")
        return redirect(url_for('admin_dashboard'))

    if transaction.status != 'Failed':
        flash("Transaction is not eligible for refund (must be 'Failed').", "danger")
        return redirect(url_for('admin_dashboard'))

    if not transaction.sender_account or transaction.sender_account == 'ADMIN':
         flash(f"Cannot refund transaction {tx_id}: No valid sender account.", "danger")
         return redirect(url_for('admin_dashboard'))

    sender_account_obj = transaction.sender

    if sender_account_obj:
        try:
            sender_account_obj.balance += transaction.amount
            transaction.status = 'Refunded'
            db.session.commit()
            flash(f"Transaction {tx_id} (Amount: ₹{transaction.amount:.2f}) refunded to account {sender_account_obj.account_number}.", "success")
        except Exception as e:
            db.session.rollback()
            flash(f"Error refunding transaction {tx_id}: {e}", "danger")
            print(f"--- ERROR IN ADMIN REFUND ---")
            traceback.print_exc()
    else:
        flash(f"Sender account ({transaction.sender_account}) linked to transaction {tx_id} not found in database.", "danger")

    return redirect(url_for('admin_dashboard'))

# -------------------------------------
# 10. CHATBOT API
# -------------------------------------
@app.route('/api/chatbot', methods=['POST'])
@login_required()
def chatbot():
    user, account, account_number = get_user_and_account(session['user_id'])
    query = request.json.get('query', '').lower()
    response = "Sorry, I can't help with that. Try asking about 'balance', 'history', or 'account number'."
    
    if 'balance' in query:
        response = f"Your current balance is ₹{account.balance:.2f}."
    elif 'account number' in query:
        response = f"Your account number is: {account_number}."
    elif 'history' in query or 'last transaction' in query:
        last_tx = models.Transaction.query.filter(
            or_(
                models.Transaction.sender_account == account_number,
                models.Transaction.recipient_account == account_number
            )
        ).order_by(desc(models.Transaction.timestamp)).first()
        
        if last_tx:
            desc = f"to {last_tx.recipient_account}" if last_tx.sender_account == account_number else f"from {last_tx.sender_account}"
            response = f"Your last transaction was for ₹{last_tx.amount:.2f} {desc}."
        else: 
            response = "You have no transaction history."
            
    return jsonify({'response': response})

if __name__ == '__main__':
    port = 5005
    print("========================================================")
    print(f" * SecureBank is running on http://127.0.0.1:{port}")
    print("========================================================")
    app.run(debug=True, port=port)