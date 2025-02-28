from flask import Blueprint, request, jsonify, session
from extensions import db
from models.user import User
from models.file import File
import os
import mimetypes
import uuid
import logging
import time
import datetime
from werkzeug.utils import secure_filename

# Configure logging
logging.basicConfig(
    filename="file_uploads.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)

# Allowed extensions and MIME types
ALLOWED_EXTENSIONS = {'pdf', 'png', 'jpg', 'jpeg', 'gif'}
ALLOWED_MIME_TYPES = {'application/pdf', 'image/png', 'image/jpeg', 'image/gif'}
UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Monitoring Metrics
upload_metrics = {
    "total_uploads": 0,
    "failed_uploads": 0,
    "successful_uploads": 0,
    "unauthorized_uploads": 0  # New metric for unauthorized file attempts
}

files_bp = Blueprint('files', __name__, url_prefix='/apps/files')

def allowed_file(filename):
    """Check if the file has an allowed extension"""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def generate_safe_filename(filename):
    """Generate a unique filename with timestamp to prevent overwriting"""
    ext = filename.rsplit('.', 1)[1].lower()
    timestamp = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
    return f"{uuid.uuid4().hex}_{timestamp}.{ext}"

@files_bp.route('/upload', methods=['POST'])
def upload_file():
    """Handle secure file upload with logging and unauthorized upload notices"""
    start_time = time.time()
    upload_metrics["total_uploads"] += 1
    user_ip = request.remote_addr  # Get user IP

    if 'user' not in session:
        logging.warning(f"Unauthorized upload attempt from {user_ip}")
        upload_metrics["failed_uploads"] += 1
        return jsonify({'success': False, 'error': 'Not logged in'}), 401

    current_user = User.query.filter_by(username=session['user']).first()
    if not current_user:
        logging.warning(f"Upload attempt by non-existent user: {session['user']} from {user_ip}")
        upload_metrics["failed_uploads"] += 1
        return jsonify({'success': False, 'error': 'User not found'}), 404

    file = request.files.get('file')
    if not file:
        logging.warning(f"User {current_user.username} from {user_ip} attempted to upload without a file")
        upload_metrics["failed_uploads"] += 1
        return jsonify({'success': False, 'error': 'No file provided'}), 400

    filename = secure_filename(file.filename)
    if not allowed_file(filename):
        logging.warning(f"⚠️ Unauthorized File Attempt! User: {current_user.username}, IP: {user_ip}, File: {filename}")
        upload_metrics["unauthorized_uploads"] += 1  # Track unauthorized uploads
        return jsonify({'success': False, 'error': 'File type not allowed. This attempt has been logged.'}), 400

    # MIME type validation (Stronger security)
    if file.mimetype not in ALLOWED_MIME_TYPES:
        logging.warning(f"⚠️ Unauthorized MIME Type! User: {current_user.username}, IP: {user_ip}, MIME: {file.mimetype}")
        upload_metrics["unauthorized_uploads"] += 1
        return jsonify({'success': False, 'error': 'Invalid file type detected. This attempt has been logged.'}), 400

    # Generate a unique filename and save the file
    safe_filename = generate_safe_filename(filename)
    file_path = os.path.join(UPLOAD_FOLDER, safe_filename)

    try:
        file.save(file_path)
        upload_time = round(time.time() - start_time, 2)
        logging.info(f"✅ File uploaded: {safe_filename} by User {current_user.username} from {user_ip} (Time: {upload_time}s)")
        
        new_file = File(filename=safe_filename, file_path=file_path, user_id=current_user.id)
        db.session.add(new_file)
        db.session.commit()

        upload_metrics["successful_uploads"] += 1
        return jsonify({'success': True, 'message': 'File uploaded successfully!', 'file': new_file.to_dict()})
    except Exception as e:
        logging.error(f"❌ Upload failed for User {current_user.username} from {user_ip}: {str(e)}")
        upload_metrics["failed_uploads"] += 1
        return jsonify({'success': False, 'error': str(e)}), 500

@files_bp.route('/metrics', methods=['GET'])
def get_metrics():
    """Retrieve upload monitoring metrics"""
    return jsonify(upload_metrics)
