from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, send_file
from flask_mysqldb import MySQL
from werkzeug.security import generate_password_hash, check_password_hash
from threading import Thread
from functools import wraps
import pandas as pd
import os
from datetime import datetime, timedelta
import re
import logging
import MySQLdb
# Import predictors and preprocessors
from predictorr import load_models_and_scalers, make_predictions
from data_preprocessor import preprocess_network_data, validate_data
from predictor import FlowPredictor

app = Flask(__name__, template_folder='templates', static_folder='static', static_url_path='/')
app.secret_key = 'your_secret_key'  # Set this to a secure key

# MySQL Configuration (XAMPP)
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = ''  # Default password for XAMPP
app.config['MYSQL_DB'] = 'arun'
app.config['MYSQL_PORT'] = 3306  # Default MySQL port for XAMPP
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)

mysql = MySQL(app)
app.logger.setLevel(logging.INFO)

# Store blocked IP with timestamp
BLOCKED_IPS = {}
CSV_FOLDER = 'captured_traffic'
os.makedirs(CSV_FOLDER, exist_ok=True)
os.makedirs('static', exist_ok=True)

# Initialize predictors and models
capture_thread = None
predictor = None
models = None
scalers = None
required_features = None
capture_module = None


def get_capture_module():
    global capture_module
    if capture_module is None:
        import capture as _capture_module
        capture_module = _capture_module
    return capture_module


def ensure_models_loaded():
    global predictor, models, scalers, required_features
    if predictor is None:
        predictor = FlowPredictor()
    if models is None or scalers is None or required_features is None:
        models, scalers, required_features = load_models_and_scalers()


def login_required(view_func):
    @wraps(view_func)
    def wrapper(*args, **kwargs):
        if 'user_id' not in session:
            flash('You need to log in to view this!!', 'danger')
            return redirect(url_for('login'))
        return view_func(*args, **kwargs)
    return wrapper

# Authentication Routes
def validate_password(password):
    """
    Validate password complexity:
    - At least 8 characters
    - Contains at least one uppercase letter
    - Contains at least one lowercase letter
    - Contains at least one number
    - Contains at least one special character
    """
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter"
    
    if not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter"
    
    if not re.search(r'\d', password):
        return False, "Password must contain at least one number"
    
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return False, "Password must contain at least one special character"
    
    return True, "Valid password"


def get_db_cursor():
    """Return a MySQL cursor or None if the database is unavailable."""
    try:
        return mysql.connection.cursor()
    except MySQLdb.OperationalError:
        flash(
            "Database is unavailable. Start MySQL in XAMPP (port 3306) and try again.",
            "danger",
        )
        return None
    except Exception:
        flash("Unable to connect to the database. Please try again.", "danger")
        return None


def ensure_users_table():
    """Create users table if it does not exist."""
    cur = get_db_cursor()
    if cur is None:
        return False

    try:
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                username VARCHAR(100) NOT NULL,
                email VARCHAR(255) NOT NULL UNIQUE,
                password VARCHAR(255) NOT NULL
            )
            """
        )
        mysql.connection.commit()
        return True
    except MySQLdb.Error:
        app.logger.exception("Failed to create or validate users table.")
        flash("Database schema error. Please check MySQL setup.", "danger")
        return False
    finally:
        cur.close()

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        if not ensure_users_table():
            return redirect(url_for('register'))

        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        # Password matching check
        if password != confirm_password:
            flash('Passwords do not match!!', 'danger')
            return redirect(url_for('register'))

        # Password complexity validation
        is_valid, validation_message = validate_password(password)
        if not is_valid:
            flash(validation_message, 'danger')
            return redirect(url_for('register'))

        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')

        cur = get_db_cursor()
        if cur is None:
            return redirect(url_for('register'))

        try:
            cur.execute("SELECT * FROM users WHERE email = %s", [email])
            existing_user = cur.fetchone()

            if existing_user:
                flash('Email already registered!!', 'danger')
                return redirect(url_for('register'))

            cur.execute("INSERT INTO users (username, email, password) VALUES (%s, %s, %s)",
                        (username, email, hashed_password))
            mysql.connection.commit()
        except MySQLdb.Error:
            app.logger.exception("Registration query failed.")
            flash("Registration failed due to a database error.", "danger")
            return redirect(url_for('register'))
        finally:
            cur.close()

        flash('Registration successful!!', 'success')
        return redirect(url_for('login'))

    return render_template('auth.html', action='Register')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        if not ensure_users_table():
            return redirect(url_for('login'))

        email = request.form['email']
        password = request.form['password']

        cur = get_db_cursor()
        if cur is None:
            return redirect(url_for('login'))

        try:
            cur.execute("SELECT * FROM users WHERE email = %s", [email])
            user = cur.fetchone()
        except MySQLdb.Error:
            app.logger.exception("Login query failed.")
            flash("Login failed due to a database error.", "danger")
            return redirect(url_for('login'))
        finally:
            cur.close()

        if user and check_password_hash(user[3], password):
            session['user_id'] = user[0]
            session['username'] = user[1]
            # Keep session beyond browser close only when "Remember me" is checked.
            session.permanent = request.form.get('remember') == 'on'
            flash('Login successful!', 'success')
            return redirect(url_for('online_mode'))
        else:
            flash('Invalid credentials!!', 'danger')
            return redirect(url_for('login'))

    return render_template('auth.html', action='Login')

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('home'))

# Main Home Routes
@app.route('/')
def home():
    return render_template('home.html')

@app.route('/online-mode')
@login_required
def online_mode():
    return render_template('online_index.html', username=session.get('username'))

# Online Mode Capture Routes
@app.route('/start_capture')
@login_required
def start_capture():
    global capture_thread
    ensure_models_loaded()
    capture = get_capture_module()
    if capture_thread is None or not capture_thread.is_alive():
        capture_thread = Thread(
            target=capture.capture_packets,
            args=("Intel(R) Wi-Fi 6 AX201 160MHz", predictor.predict)
        )
        capture_thread.start()
        return jsonify({"status": "success", "message": "Capturing packets..."})
    return jsonify({"status": "warning", "message": "Capture already in progress."})

@app.route('/stop_capture')
@login_required
def stop_capture_route():
    global capture_thread
    capture = get_capture_module()
    if capture_thread and capture_thread.is_alive():
        capture.stop_capture()
        capture_thread.join()
        capture_thread = None
        capture.save_to_csv()
        return jsonify({"status": "success", "message": "Stopped capturing packets."})
    return jsonify({"status": "warning", "message": "No capture in progress."})
# Route to get flows data
@app.route('/flows')
@login_required
def get_flows():
    capture = get_capture_module()
    return jsonify({'flows': capture.flow_data, 'blocked_ips': list(BLOCKED_IPS)})

# Route to get detected attacks and blocked IPs
@app.route('/detected_attacks')
@login_required
def get_detected_attacks():
    capture = get_capture_module()
    attacks = [flow for flow in capture.flow_data if flow['Prediction'] == 'Attack']
    blocked_ips_list = [
        {'ip': ip, 'blocked_at': str(block_time)}
        for ip, block_time in BLOCKED_IPS.items()
    ]
    return jsonify({'attacks': attacks, 'blocked_ips': blocked_ips_list})

# Route to clear detected attacks
@app.route('/clear_attacks', methods=['POST'])
@login_required
def clear_attacks():
    capture = get_capture_module()
    capture.flow_data = [flow for flow in capture.flow_data if flow['Prediction'] != 'Attack']
    return jsonify({"status": "success", "message": "Attacks cleared"})

# Route to block an IP
@app.route('/block_ip', methods=['POST'])
@login_required
def block_ip():
    ip = request.json.get('ip')
    if ip:
        BLOCKED_IPS[ip] = datetime.now()
        return jsonify({"status": "success", "message": f"Blocked IP: {ip}"})
    return jsonify({"status": "error", "message": "No IP provided"})

# Route to unblock an IP
@app.route('/unblock_ip', methods=['POST'])
@login_required
def unblock_ip():
    ip = request.json.get('ip')
    if ip in BLOCKED_IPS:
        del BLOCKED_IPS[ip]
        return jsonify({"status": "success", "message": f"Unblocked IP: {ip}"})
    return jsonify({"status": "error", "message": "IP not found in blocked list"})

# Route to download captured traffic as CSV
@app.route('/download_csv')
@login_required
def download_csv():
    capture = get_capture_module()
    if not capture.flow_data:
        return jsonify({"status": "error", "message": "No data to download"})

    filename = f"traffic_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    filepath = os.path.join(CSV_FOLDER, filename)
    pd.DataFrame(capture.flow_data).to_csv(filepath, index=False)
    return send_file(filepath, as_attachment=True)

# Route to get network statistics
@app.route('/network_statistics')
@login_required
def get_network_statistics():
    capture = get_capture_module()
    attacker_counts = {}
    for flow in capture.flow_data:
        if flow['Prediction'] == 'Attack':
            src_ip = flow['Src IP']
            attacker_counts[src_ip] = attacker_counts.get(src_ip, 0) + 1
    
    top_attacker_ips = sorted(
        [{'ip': ip, 'attack_count': count} for ip, count in attacker_counts.items()],
        key=lambda x: x['attack_count'],
        reverse=True
    )[:5]

    victim_counts = {}
    for flow in capture.flow_data:
        if flow['Prediction'] == 'Attack':
            dst_ip = flow['Dst IP']
            victim_counts[dst_ip] = victim_counts.get(dst_ip, 0) + 1
    
    top_victim_ips = sorted(
        [{'ip': ip, 'attack_count': count} for ip, count in victim_counts.items()],
        key=lambda x: x['attack_count'],
        reverse=True
    )[:5]

    total_packets = sum(flow['Tot Fwd Pkts'] + flow['Tot Bwd Pkts'] for flow in capture.flow_data)
    unique_ips = len(set(flow['Src IP'] for flow in capture.flow_data) | set(flow['Dst IP'] for flow in capture.flow_data))
    avg_packet_size = total_packets / len(capture.flow_data) if capture.flow_data else 0

    total_attacks = len([flow for flow in capture.flow_data if flow['Prediction'] == 'Attack'])
    attack_rate = (total_attacks / len(capture.flow_data) * 100) if capture.flow_data else 0

    attack_types = {}
    for flow in capture.flow_data:
        if flow['Prediction'] == 'Attack':
            attack_types[flow['Prediction']] = attack_types.get(flow['Prediction'], 0) + 1
    common_attack_type = max(attack_types, key=attack_types.get) if attack_types else 'N/A'

    blocked_ip_count = len(BLOCKED_IPS)
    
    if BLOCKED_IPS:
        current_time = datetime.now()
        quarantine_durations = [(current_time - block_time).total_seconds() / 3600 for block_time in BLOCKED_IPS.values()]
        avg_quarantine_duration = sum(quarantine_durations) / len(quarantine_durations)
    else:
        avg_quarantine_duration = 0

    unblocked_ip_count = 0  # Placeholder

    return jsonify({
        'top_attacker_ips': top_attacker_ips,
        'top_victim_ips': top_victim_ips,
        'total_packets': total_packets,
        'unique_ips': unique_ips,
        'avg_packet_size': round(avg_packet_size, 2),
        'total_attacks': total_attacks,
        'attack_rate': attack_rate,
        'common_attack_type': common_attack_type,
        'blocked_ip_count': blocked_ip_count,
        'avg_quarantine_duration': avg_quarantine_duration,
        'unblocked_ip_count': unblocked_ip_count
    })

# Offline Mode Routes
@app.route('/offline-mode')
@login_required
def offline_mode():
    return render_template('offline_index.html')

@app.route('/predict', methods=['POST'])
@login_required
def predict():
    try:
        ensure_models_loaded()
        # Check for file in request
        if 'file' not in request.files or request.files['file'].filename == '':
            flash('No file uploaded or no file selected.')
            return redirect(url_for('offline_index'))
        
        file = request.files['file']
        
        # Read the CSV
        original_data = pd.read_csv(file)
        
        # Preprocess the data
        processed_data = preprocess_network_data(original_data)
        
        # Validate processed data
        if not validate_data(processed_data):
            flash('Invalid data format. Please check your CSV file.')
            return redirect(url_for('offline_index'))
        
        # Make predictions
        predictions = make_predictions(processed_data, models, scalers)
        
        # Add predictions to original data
        original_data['Prediction'] = predictions
        
        # Save results
        output_file = 'static/output_with_predictions.csv'
        original_data.to_csv(output_file, index=False)
        
        flash('Predictions completed successfully!')
        return render_template('offline_index.html', output_file=output_file)
    
    except Exception as e:
        flash(f"An error occurred: {str(e)}")
        return redirect(url_for('offline_index'))

@app.route('/download/<filename>')
@login_required
def download(filename):
    return send_file(os.path.join('static', filename), as_attachment=True)

if __name__ == '__main__':
    # Ensure static directory exists
    os.makedirs('static', exist_ok=True)
    app.run(debug=True)
