from flask import Flask, render_template, session, redirect, request, url_for, flash, send_file, jsonify
from functools import wraps
from pymongo import MongoClient
from passlib.hash import pbkdf2_sha256
import uuid
import os
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta
from flask.json.provider import DefaultJSONProvider
from bson import ObjectId
from io import BytesIO
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
from dotenv import load_dotenv
import json
import google.generativeai as genai
from datetime import datetime

# Load environment variables
load_dotenv()

# Initialize Flask app
app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', b'\xcc^\x91\xea\x17-\xd0W\x03\xa7\xf8J0\xac8\xc5')

class MongoJSONProvider(DefaultJSONProvider):
    def default(self, o):
        if isinstance(o, ObjectId):
            return str(o)
        if isinstance(o, datetime):
            return o.isoformat()
        return super().default(o)

app.json = MongoJSONProvider(app)

# Configure file uploads
UPLOAD_FOLDER = 'static/uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'pdf'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Database setup
client = MongoClient(
    os.getenv("MONGO_URI"),
    tlsAllowInvalidCertificates=True  # This bypasses SSL verification
)
db = client.kobatela

# Collections
users = db.users
col_medical_history = db.medical_history
col_medications = db.medications
col_vaccines = db.vaccines
col_lab_reports = db.lab_reports
col_emergency_notes = db.emergency_notes
col_family_members = db.family_members
col_reminders = db.reminders

# Helper functions
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def login_required(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'logged_in' in session:
            return f(*args, **kwargs)
        flash("Please log in to access this page", "error")
        return redirect(url_for('login'))
    return wrap

# Service Classes
class UserService:
    @staticmethod
    def get_by_id(user_id):
        return users.find_one({"_id": ObjectId(user_id)})
    
    @staticmethod
    def get_by_email(email):
        return users.find_one({"email": email})
    
    @staticmethod
    def create(user_data):
        user_data['_id'] = ObjectId()
        user_data['password'] = pbkdf2_sha256.hash(user_data['password'])
        user_data['created_at'] = datetime.utcnow()
        return users.insert_one(user_data)
    
    @staticmethod
    def update(user_id, updates):
        return users.update_one(
            {"_id": ObjectId(user_id)},
            {"$set": updates}
        )


class MedicalHistoryService:
    @staticmethod
    def get_all(user_id):
        return list(col_medical_history.find({"user_id": ObjectId(user_id)}).sort("date", -1))
    
    @staticmethod
    def get_by_id(entry_id, user_id):
        return col_medical_history.find_one({
            "_id": ObjectId(entry_id),
            "user_id": ObjectId(user_id)
        })
    
    @staticmethod
    def create(user_id, data, filename=None):
        entry = {
            "user_id": ObjectId(user_id),
            "type": data.get('type'),
            "details": data.get('details'),
            "date": datetime.strptime(data.get('date'), '%Y-%m-%d') if data.get('date') else None,
            "notes": data.get('notes'),
            "filename": filename,
            "created_at": datetime.utcnow()
        }
        return col_medical_history.insert_one(entry)
    
    @staticmethod
    def update(entry_id, user_id, data):
        updates = {
            "type": data.get('type'),
            "details": data.get('details'),
            "date": datetime.strptime(data.get('date'), '%Y-%m-%d') if data.get('date') else None,
            "notes": data.get('notes'),
            "updated_at": datetime.utcnow()
        }
        return col_medical_history.update_one(
            {"_id": ObjectId(entry_id),
            "user_id": ObjectId(user_id)},
            {"$set": updates}
        )
    
    @staticmethod
    def delete(entry_id, user_id):
        # First get the entry to check for filename
        entry = col_medical_history.find_one({
            "_id": ObjectId(entry_id),
            "user_id": ObjectId(user_id)
        })
    
        # Delete the associated file if it exists
        if entry and entry.get('filename'):
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], 'medical_history', entry['filename'])
            if os.path.exists(filepath):
                os.remove(filepath)
    
        # Delete the database entry
        return col_medical_history.delete_one({
            "_id": ObjectId(entry_id),
            "user_id": ObjectId(user_id)
        })

class MedicationService:
    @staticmethod
    def get_all(user_id):
        return list(col_medications.find({"user_id": ObjectId(user_id)}).sort("created_at", -1))
    
    @staticmethod
    def get_by_id(med_id, user_id):
        return col_medications.find_one({
            "_id": ObjectId(med_id),
            "user_id": ObjectId(user_id)
        })
    
    @staticmethod
    def create(user_id, data, filename=None):
        medication = {
            "user_id": ObjectId(user_id),
            "name": data.get('name'),
            "dosage": data.get('dosage'),
            "frequency": data.get('frequency'),
            "times": data.getlist('times'),
            "notes": data.get('notes'),
            "attachment": filename,
            "created_at": datetime.utcnow()
        }
        return col_medications.insert_one(medication)
    
    @staticmethod
    def update(med_id, user_id, data, filename=None):
        updates = {
            "name": data.get('name'),
            "dosage": data.get('dosage'),
            "frequency": data.get('frequency'),
            "times": data.getlist('times'),
            "notes": data.get('notes'),
            "updated_at": datetime.utcnow()
        }
        if filename is not None:
            updates['attachment'] = filename
        
        return col_medications.update_one(
            {"_id": ObjectId(med_id),
            "user_id": ObjectId(user_id)},
            {"$set": updates}
        )
    
    @staticmethod
    def delete(med_id, user_id):
        # First get the medication to check for filename
        medication = col_medications.find_one({
            "_id": ObjectId(med_id),
            "user_id": ObjectId(user_id)
        })
        
        # Delete the associated file if it exists
        if medication and medication.get('attachment'):
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], 'medications', medication['attachment'])
            if os.path.exists(filepath):
                os.remove(filepath)
        
        # Delete the database entry
        return col_medications.delete_one({
            "_id": ObjectId(med_id),
            "user_id": ObjectId(user_id)
        })

# User class for authentication
class User:
    def start_session(self, user):
        user['_id'] = str(user['_id'])
        del user['password']
        session['logged_in'] = True
        session['user'] = user
        return redirect(url_for('dashboard'))

    def signup(self):
        user_data = {
            "name": request.form.get('name', ""),
            "email": request.form.get('email'),
            "password": request.form.get('password'),
            "age": int(request.form.get('age', 0)) if request.form.get('age') else None,
            "gender": request.form.get('gender'),
            "weight": float(request.form.get('weight')) if request.form.get('weight') else None,
            "avatar_url": "",
            "role": "user"
        }

        if UserService.get_by_email(user_data['email']):
            flash("Email already exists", "error")
            return redirect(url_for('signup'))

        if UserService.create(user_data):
            return self.start_session(user_data)
        
        flash("Signup failed", "error")
        return redirect(url_for('signup'))

    def login(self):
        email = request.form.get('email').strip()
        password = request.form.get('password').strip()
        user = UserService.get_by_email(email)
        
        if user and pbkdf2_sha256.verify(password, user['password']):
            UserService.update(user['_id'], {"last_login": datetime.utcnow()})
            return self.start_session(user)
        
        flash("Invalid credentials", "error")
        return redirect(url_for('login'))

    def signout(self):
        session.clear()
        flash("You have been logged out", "info")
        return redirect(url_for('login'))

user_manager = User()

# Template filters and context processors
@app.context_processor
def inject_datetime():
    return {'datetime': datetime}

@app.template_filter('datetimeformat')
def datetimeformat(value, format='%Y-%m-%d %H:%M'):
    if value is None:
        return ""
    if isinstance(value, str):
        try:
            value = datetime.strptime(value, '%Y-%m-%d')
        except ValueError:
            return value
    return value.strftime(format)

# Routes
@app.route('/')
def home():
    if 'logged_in' in session:
        return redirect(url_for('dashboard'))
    return render_template('login.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'logged_in' in session:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        return user_manager.login()
    
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if 'logged_in' in session:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        return user_manager.signup()
    
    return render_template('signup.html')

@app.route('/logout')
@login_required
def logout():
    return user_manager.signout()

# Dashboard
@app.route('/dashboard')
@login_required
def dashboard():
    user_id = session['user']['_id']
    med_count = col_medications.count_documents({"user_id": ObjectId(user_id)})
    upcoming_reminders = list(col_reminders.find({
        "user_id": ObjectId(user_id),
        "due_date": {"$gte": datetime.utcnow()}
    }).sort("due_date", 1).limit(3))
    
    next_vaccine = col_vaccines.find_one({
        "user_id": ObjectId(user_id),
        "$or": [
            {"booster_due": {"$gte": datetime.utcnow().strftime('%Y-%m-%d')}},
            {"booster_due": {"$exists": False}}
        ]
    }, sort=[("booster_due", 1)])
    
    recent_lab = col_lab_reports.find_one(
        {"user_id": ObjectId(user_id)},
        sort=[("date", -1)]
    )
    
    return render_template('dashboard.html',
        med_count=med_count,
        reminders=upcoming_reminders,
        next_vaccine=next_vaccine,
        recent_lab=recent_lab,
        current_date=datetime.now().strftime('%B %d, %Y')
    )

# Profile Routes
@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    user_id = session['user']['_id']
    user = UserService.get_by_id(user_id)
    
    if request.method == 'POST':
        updates = {
            "name": request.form.get('name'),
            "email": request.form.get('email'),
            "age": int(request.form.get('age')) if request.form.get('age') else None,
            "weight": float(request.form.get('weight')) if request.form.get('weight') else None,
            "gender": request.form.get('gender'),
            "updated_at": datetime.utcnow()
        }
        
        if 'avatar' in request.files:
            file = request.files['avatar']
            if file and allowed_file(file.filename):
                filename = secure_filename(f"{user_id}_{file.filename}")
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], 'avatars', filename)
                os.makedirs(os.path.dirname(filepath), exist_ok=True)
                file.save(filepath)
                updates['avatar_url'] = f"/static/uploads/avatars/{filename}"
        
        if request.form.get('current_password') and request.form.get('new_password'):
            if pbkdf2_sha256.verify(request.form.get('current_password'), user['password']):
                updates['password'] = pbkdf2_sha256.hash(request.form.get('new_password'))
            else:
                flash("Current password is incorrect", "error")
                return redirect(url_for('profile'))
        
        UserService.update(user_id, updates)
        session['user'] = UserService.get_by_id(user_id)
        flash("Profile updated successfully", "success")
        return redirect(url_for('profile'))
    
    return render_template('profile.html', user=user)

# Medical History Routes
@app.route('/medical-history')
@login_required
def medical_history_list():
    user_id = session['user']['_id']
    history = MedicalHistoryService.get_all(user_id)
    return render_template('medical_history/list.html', history=history)

@app.route('/medical-history/create', methods=['GET', 'POST'])
@login_required
def medical_history_create():
    if request.method == 'POST':
        user_id = session['user']['_id']
        file = request.files.get('attachment')
        filename = None
        
        if file and allowed_file(file.filename):
            filename = secure_filename(f"{user_id}_{datetime.now().timestamp()}.{file.filename.rsplit('.', 1)[1].lower()}")
            # Create medical_history subfolder if it doesn't exist
            os.makedirs(os.path.join(app.config['UPLOAD_FOLDER'], 'medical_history'), exist_ok=True)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], 'medical_history', filename))
        
        try:
            MedicalHistoryService.create(user_id, request.form, filename)
            flash('Entry created successfully', 'success')
            return redirect(url_for('medical_history_list'))
        except Exception as e:
            flash(f'Error creating entry: {str(e)}', 'error')
    
    return render_template('medical_history/create.html')

@app.route('/medical-history/<entry_id>/edit', methods=['GET', 'POST'])
@login_required
def medical_history_edit(entry_id):
    user_id = session['user']['_id']
    entry = MedicalHistoryService.get_by_id(entry_id, user_id)
    
    if not entry:
        flash('Entry not found', 'error')
        return redirect(url_for('medical_history_list'))
    
    if request.method == 'POST':
        file = request.files.get('attachment')
        filename = entry.get('filename')
        
        if file and allowed_file(file.filename):
            # Delete old file if it exists
            if filename:
                old_filepath = os.path.join(app.config['UPLOAD_FOLDER'], 'medical_history', filename)
                if os.path.exists(old_filepath):
                    os.remove(old_filepath)
            
            # Save new file
            filename = secure_filename(f"{user_id}_{datetime.now().timestamp()}.{file.filename.rsplit('.', 1)[1].lower()}")
            os.makedirs(os.path.join(app.config['UPLOAD_FOLDER'], 'medical_history'), exist_ok=True)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], 'medical_history', filename))
        
        try:
            MedicalHistoryService.update(entry_id, user_id, request.form)
            
            # Update filename in database if new file was uploaded
            if file and allowed_file(file.filename):
                col_medical_history.update_one(
                    {"_id": ObjectId(entry_id)},
                    {"$set": {"filename": filename}}
                )
            
            flash('Entry updated successfully', 'success')
            return redirect(url_for('medical_history_list'))
        except Exception as e:
            flash(f'Error updating entry: {str(e)}', 'error')
    
    return render_template('medical_history/edit.html', entry=entry)

@app.route('/medical-history/<entry_id>/delete', methods=['POST'])
@login_required
def medical_history_delete(entry_id):
    user_id = session['user']['_id']
    result = MedicalHistoryService.delete(entry_id, user_id)
    
    if result.deleted_count > 0:
        flash('Entry deleted successfully', 'success')
    else:
        flash('Entry not found or could not be deleted', 'error')
    
    return redirect(url_for('medical_history_list'))

# Medication Routes
@app.route('/medications')
@login_required
def medications_list():
    user_id = session['user']['_id']
    meds = MedicationService.get_all(user_id)
    return render_template('medications/list.html', medications=meds)

@app.route('/medications/create', methods=['GET', 'POST'])
@login_required
def medications_create():
    if request.method == 'POST':
        user_id = session['user']['_id']
        file = request.files.get('attachment')
        filename = None
        
        if file and allowed_file(file.filename):
            filename = secure_filename(f"{user_id}_{datetime.now().timestamp()}.{file.filename.rsplit('.', 1)[1].lower()}")
            # Create medications subfolder if it doesn't exist
            os.makedirs(os.path.join(app.config['UPLOAD_FOLDER'], 'medications'), exist_ok=True)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], 'medications', filename))
        
        try:
            MedicationService.create(user_id, request.form, filename)
            flash('Medication added successfully', 'success')
            return redirect(url_for('medications_list'))
        except Exception as e:
            flash(f'Error adding medication: {str(e)}', 'error')
    
    return render_template('medications/create.html')

@app.route('/medications/<med_id>/edit', methods=['GET', 'POST'])
@login_required
def medications_edit(med_id):
    user_id = session['user']['_id']
    medication = MedicationService.get_by_id(med_id, user_id)
    
    if not medication:
        flash('Medication not found', 'error')
        return redirect(url_for('medications_list'))
    
    if request.method == 'POST':
        file = request.files.get('attachment')
        filename = medication.get('attachment')
        
        if file and allowed_file(file.filename):
            # Delete old file if it exists
            if filename:
                old_filepath = os.path.join(app.config['UPLOAD_FOLDER'], 'medications', filename)
                if os.path.exists(old_filepath):
                    os.remove(old_filepath)
            
            # Save new file
            filename = secure_filename(f"{user_id}_{datetime.now().timestamp()}.{file.filename.rsplit('.', 1)[1].lower()}")
            os.makedirs(os.path.join(app.config['UPLOAD_FOLDER'], 'medications'), exist_ok=True)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], 'medications', filename))
        
        try:
            MedicationService.update(med_id, user_id, request.form, filename)
            flash('Medication updated successfully', 'success')
            return redirect(url_for('medications_list'))
        except Exception as e:
            flash(f'Error updating medication: {str(e)}', 'error')
    
    return render_template('medications/edit.html', medication=medication)

@app.route('/medications/<med_id>/delete', methods=['POST'])
@login_required
def medications_delete(med_id):
    user_id = session['user']['_id']
    result = MedicationService.delete(med_id, user_id)
    
    if result.deleted_count > 0:
        flash('Medication deleted successfully', 'success')
    else:
        flash('Medication not found or could not be deleted', 'error')
    
    return redirect(url_for('medications_list'))

# API Endpoints
@app.route('/api/medical-history', methods=['GET'])
@login_required
def api_medical_history():
    user_id = session['user']['_id']
    history = MedicalHistoryService.get_all(user_id)
    
    # Convert for JSON response
    for entry in history:
        entry['_id'] = str(entry['_id'])
        if 'date' in entry and entry['date']:
            entry['date'] = entry['date'].isoformat()
    
    return jsonify({'success': True, 'data': history})

@app.route('/api/medical-history', methods=['POST'])
@login_required
def api_medical_history_create():
    user_id = session['user']['_id']
    data = request.get_json()
    
    try:
        result = MedicalHistoryService.create(user_id, data)
        return jsonify({
            'success': True,
            'message': 'Entry created',
            'id': str(result.inserted_id)
        }), 201
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 400

@app.route('/view/medical-history/<entry_id>')
@login_required
def view_medical_history_attachment(entry_id):
    user_id = session['user']['_id']
    entry = MedicalHistoryService.get_by_id(entry_id, user_id)
    
    if not entry or not entry.get('filename'):
        flash('File not found', 'error')
        return redirect(url_for('medical_history_list'))
    
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], 'medical_history', entry['filename'])
    
    if not os.path.exists(filepath):
        flash('File no longer available', 'error')
        return redirect(url_for('medical_history_list'))
    
    # For images and PDFs, we can display them in the browser
    file_ext = entry['filename'].split('.')[-1].lower()
    
    if file_ext in ['png', 'jpg', 'jpeg', 'pdf']:
        return send_file(filepath)
    else:
        # For other file types, force download
        return send_file(
            filepath,
            as_attachment=True,
            download_name=os.path.basename(entry['filename'])
        )

# Similar API endpoints would be created for other resources

# ... (previous imports and setup remain the same)

# Service Classes for all resources
class VaccineService:
    @staticmethod
    def get_all(user_id):
        return list(col_vaccines.find({"user_id": ObjectId(user_id)}).sort("date", -1))
    
    @staticmethod
    def get_by_id(vaccine_id, user_id):
        return col_vaccines.find_one({
            "_id": ObjectId(vaccine_id),
            "user_id": ObjectId(user_id)
        })
    
    @staticmethod
    def create(user_id, data, filename=None):
        vaccine = {
            "user_id": ObjectId(user_id),
            "name": data.get('name'),
            "date": datetime.strptime(data.get('date'), '%Y-%m-%d') if data.get('date') else None,
            "booster_due": datetime.strptime(data.get('booster_due'), '%Y-%m-%d') if data.get('booster_due') else None,
            "attachment": filename,
            "created_at": datetime.utcnow()
        }
        return col_vaccines.insert_one(vaccine)
    
    @staticmethod
    def update(vaccine_id, user_id, data):
        updates = {
            "name": data.get('name'),
            "date": datetime.strptime(data.get('date'), '%Y-%m-%d') if data.get('date') else None,
            "booster_due": datetime.strptime(data.get('booster_due'), '%Y-%m-%d') if data.get('booster_due') else None,
            "updated_at": datetime.utcnow()
        }
        return col_vaccines.update_one(
            {"_id": ObjectId(vaccine_id),
            "user_id": ObjectId(user_id)},
            {"$set": updates}
        )
    
    @staticmethod
    def delete(vaccine_id, user_id):
        return col_vaccines.delete_one({
            "_id": ObjectId(vaccine_id),
            "user_id": ObjectId(user_id)
        })

class LabReportService:
    @staticmethod
    def get_all(user_id):
        return list(col_lab_reports.find({"user_id": ObjectId(user_id)}).sort("date", -1))
    
    @staticmethod
    def get_by_id(report_id, user_id):
        return col_lab_reports.find_one({
            "_id": ObjectId(report_id),
            "user_id": ObjectId(user_id)
        })
    
    @staticmethod
    def create(user_id, data, filename=None):
        report = {
            "user_id": ObjectId(user_id),
            "name": data.get('name'),
            "test_type": data.get('test_type'),
            "date": datetime.strptime(data.get('date'), '%Y-%m-%d') if data.get('date') else None,
            "notes": data.get('notes'),
            "filename": filename,
            "created_at": datetime.utcnow()
        }
        return col_lab_reports.insert_one(report)
    
    @staticmethod
    def update(report_id, user_id, data):
        updates = {
            "name": data.get('name'),
            "test_type": data.get('test_type'),
            "date": datetime.strptime(data.get('date'), '%Y-%m-%d') if data.get('date') else None,
            "notes": data.get('notes'),
            "updated_at": datetime.utcnow()
        }
        return col_lab_reports.update_one(
            {"_id": ObjectId(report_id),
            "user_id": ObjectId(user_id)},
            {"$set": updates}
        )
    
    @staticmethod
    def delete(report_id, user_id):
        return col_lab_reports.delete_one({
            "_id": ObjectId(report_id),
            "user_id": ObjectId(user_id)
        })

class EmergencyNotesService:
    @staticmethod
    def get(user_id):
        return col_emergency_notes.find_one({"user_id": ObjectId(user_id)})
    
    @staticmethod
    def create_or_update(user_id, data, files=None):
        emergency_data = {
            "user_id": ObjectId(user_id),
            "blood_type": data.get('blood_type'),
            "allergies": data.get('allergies'),
            "medical_conditions": data.get('medical_conditions'),
            "emergency_contacts": data.get('emergency_contacts'),
            "files": files or [],
            "updated_at": datetime.utcnow()
        }
        
        existing = EmergencyNotesService.get(user_id)
        if existing:
            return col_emergency_notes.update_one(
                {"_id": existing['_id']},
                {"$set": emergency_data}
            )
        else:
            emergency_data['created_at'] = datetime.utcnow()
            return col_emergency_notes.insert_one(emergency_data)

class FamilyMemberService:
    @staticmethod
    def get_all(user_id):
        return list(col_family_members.find({"user_id": ObjectId(user_id)}))
    
    @staticmethod
    def get_by_id(member_id, user_id):
        return col_family_members.find_one({
            "_id": ObjectId(member_id),
            "user_id": ObjectId(user_id)
        })
    
    @staticmethod
    def create(user_id, data):
        family_user = UserService.get_by_email(data.get('email'))
        if not family_user:
            return None
        
        member = {
            "user_id": ObjectId(user_id),
            "family_user_id": family_user['_id'],
            "name": family_user.get('name'),
            "email": family_user.get('email'),
            "relation": data.get('relation'),
            "access_level": data.get('access_level', 'view_emergency'),
            "created_at": datetime.utcnow()
        }
        return col_family_members.insert_one(member)
    
    @staticmethod
    def delete(member_id, user_id):
        return col_family_members.delete_one({
            "_id": ObjectId(member_id),
            "user_id": ObjectId(user_id)
        })

class ReminderService:
    @staticmethod
    def get_all(user_id):
        return list(col_reminders.find({"user_id": ObjectId(user_id)}).sort("due_date", 1))
    
    @staticmethod
    def get_upcoming(user_id, limit=3):
        return list(col_reminders.find({
            "user_id": ObjectId(user_id),
            "due_date": {"$gte": datetime.utcnow()}
        }).sort("due_date", 1).limit(limit))
    
    @staticmethod
    def get_by_id(reminder_id, user_id):
        return col_reminders.find_one({
            "_id": ObjectId(reminder_id),
            "user_id": ObjectId(user_id)
        })
    
    @staticmethod
    def create(user_id, data):
        reminder = {
            "user_id": ObjectId(user_id),
            "type": data.get('type'),
            "item_id": ObjectId(data.get('item_id')) if data.get('item_id') else None,
            "title": data.get('title'),
            "due_date": datetime.strptime(data.get('due_date'), '%Y-%m-%d') if data.get('due_date') else None,
            "notes": data.get('notes'),
            "created_at": datetime.utcnow()
        }
        return col_reminders.insert_one(reminder)
    
    @staticmethod
    def update(reminder_id, user_id, data):
        updates = {
            "title": data.get('title'),
            "due_date": datetime.strptime(data.get('due_date'), '%Y-%m-%d') if data.get('due_date') else None,
            "notes": data.get('notes'),
            "updated_at": datetime.utcnow()
        }
        return col_reminders.update_one(
            {"_id": ObjectId(reminder_id),
            "user_id": ObjectId(user_id)},
            {"$set": updates}
        )
    
    @staticmethod
    def delete(reminder_id, user_id):
        return col_reminders.delete_one({
            "_id": ObjectId(reminder_id),
            "user_id": ObjectId(user_id)
        })

# Vaccine Routes
@app.route('/vaccines')
@login_required
def vaccines_list():
    user_id = session['user']['_id']
    vaccines = VaccineService.get_all(user_id)
    return render_template('vaccines/list.html', vaccines=vaccines)

@app.route('/vaccines/create', methods=['GET', 'POST'])
@login_required
def vaccines_create():
    if request.method == 'POST':
        user_id = session['user']['_id']
        file = request.files.get('attachment')
        filename = None
        
        if file and allowed_file(file.filename):
            filename = secure_filename(f"{user_id}_{datetime.now().timestamp()}.{file.filename.rsplit('.', 1)[1].lower()}")
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], 'vaccines', filename))
        
        try:
            VaccineService.create(user_id, request.form, filename)
            flash('Vaccine record added successfully', 'success')
            return redirect(url_for('vaccines_list'))
        except Exception as e:
            flash(f'Error adding vaccine: {str(e)}', 'error')
    
    return render_template('vaccines/create.html')

@app.route('/vaccines/<vaccine_id>/edit', methods=['GET', 'POST'])
@login_required
def vaccines_edit(vaccine_id):
    user_id = session['user']['_id']
    vaccine = VaccineService.get_by_id(vaccine_id, user_id)
    
    if not vaccine:
        flash('Vaccine record not found', 'error')
        return redirect(url_for('vaccines_list'))
    
    if request.method == 'POST':
        try:
            VaccineService.update(vaccine_id, user_id, request.form)
            flash('Vaccine record updated successfully', 'success')
            return redirect(url_for('vaccines_list'))
        except Exception as e:
            flash(f'Error updating vaccine: {str(e)}', 'error')
    
    return render_template('vaccines/edit.html', vaccine=vaccine)

@app.route('/vaccines/<vaccine_id>/delete', methods=['POST'])
@login_required
def vaccines_delete(vaccine_id):
    user_id = session['user']['_id']
    result = VaccineService.delete(vaccine_id, user_id)
    
    if result.deleted_count > 0:
        flash('Vaccine record deleted successfully', 'success')
    else:
        flash('Vaccine record not found or could not be deleted', 'error')
    
    return redirect(url_for('vaccines_list'))

# Lab Report Routes
@app.route('/lab-reports')
@login_required
def lab_reports_list():
    user_id = session['user']['_id']
    reports = LabReportService.get_all(user_id)
    
    # Get AI suggestions
    user = UserService.get_by_id(user_id)
    suggestions = []
    
    if user.get('age') and user.get('gender'):
        try:
            model = genai.GenerativeModel('gemini-pro')
            prompt = f"Suggest health tests for {user['age']} year old {user['gender']}"
            response = model.generate_content(prompt)
            suggestions = json.loads(response.text).get('suggestions', [])
        except Exception as e:
            print(f"AI suggestion error: {e}")
    
    return render_template('lab_reports/list.html', reports=reports, suggestions=suggestions)

@app.route('/lab-reports/create', methods=['GET', 'POST'])
@login_required
def lab_reports_create():
    if request.method == 'POST':
        user_id = session['user']['_id']
        file = request.files.get('report_file')
        filename = None
        
        if file and allowed_file(file.filename):
            filename = secure_filename(f"{user_id}_{datetime.now().timestamp()}.{file.filename.rsplit('.', 1)[1].lower()}")
            # Save in lab_reports subfolder
            os.makedirs(os.path.join(app.config['UPLOAD_FOLDER'], 'lab_reports'), exist_ok=True)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], 'lab_reports', filename))
        
        try:
            LabReportService.create(user_id, request.form, filename)
            flash('Lab report uploaded successfully', 'success')
            return redirect(url_for('lab_reports_list'))
        except Exception as e:
            flash(f'Error uploading lab report: {str(e)}', 'error')
    
    return render_template('lab_reports/create.html')

@app.route('/lab-reports/<report_id>/delete', methods=['POST'])
@login_required
def lab_reports_delete(report_id):
    user_id = session['user']['_id']
    result = LabReportService.delete(report_id, user_id)
    
    if result.deleted_count > 0:
        flash('Lab report deleted successfully', 'success')
    else:
        flash('Lab report not found or could not be deleted', 'error')
    
    return redirect(url_for('lab_reports_list'))

@app.route('/lab-reports/<report_id>/edit', methods=['GET', 'POST'])
@login_required
def lab_reports_edit(report_id):
    user_id = session['user']['_id']
    report = LabReportService.get_by_id(report_id, user_id)
    
    if not report:
        flash('Lab report not found', 'error')
        return redirect(url_for('lab_reports_list'))
    
    if request.method == 'POST':
        try:
            file = request.files.get('report_file')
            filename = report.get('filename')
            
            if file and allowed_file(file.filename):
                # Delete old file if it exists
                if filename:
                    old_filepath = os.path.join(app.config['UPLOAD_FOLDER'], 'lab_reports', filename)
                    if os.path.exists(old_filepath):
                        os.remove(old_filepath)
                
                # Save new file
                filename = secure_filename(f"{user_id}_{datetime.now().timestamp()}.{file.filename.rsplit('.', 1)[1].lower()}")
                os.makedirs(os.path.join(app.config['UPLOAD_FOLDER'], 'lab_reports'), exist_ok=True)
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], 'lab_reports', filename))
            
            LabReportService.update(report_id, user_id, request.form)
            
            if file and allowed_file(file.filename):
                col_lab_reports.update_one(
                    {"_id": ObjectId(report_id)},
                    {"$set": {"filename": filename}}
                )
            
            flash('Lab report updated successfully', 'success')
            return redirect(url_for('lab_reports_list'))
        except Exception as e:
            flash(f'Error updating lab report: {str(e)}', 'error')
    
    return render_template('lab_reports/edit.html', report=report)

# Emergency Notes Routes
@app.route('/emergency-notes', methods=['GET', 'POST'])
@login_required
def emergency_notes():
    user_id = session['user']['_id']
    
    if request.method == 'POST':
        files = request.files.getlist('emergency_files')
        filepaths = []
        
        for file in files:
            if file and allowed_file(file.filename):
                filename = secure_filename(f"{user_id}_{datetime.now().timestamp()}.{file.filename.rsplit('.', 1)[1].lower()}")
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], 'emergency', filename))
                filepaths.append(filename)
        
        try:
            EmergencyNotesService.create_or_update(user_id, request.form, filepaths)
            flash('Emergency notes updated successfully', 'success')
        except Exception as e:
            flash(f'Error updating emergency notes: {str(e)}', 'error')
        
        return redirect(url_for('emergency_notes'))
    
    notes = EmergencyNotesService.get(user_id)
    family = FamilyMemberService.get_all(user_id)
    return render_template('emergency_notes/view.html', notes=notes, family=family)

# Family Member Routes
@app.route('/family-members/add', methods=['POST'])
@login_required
def family_members_add():
    user_id = session['user']['_id']
    try:
        result = FamilyMemberService.create(user_id, request.form)
        if result:
            flash('Family member added successfully', 'success')
        else:
            flash('No user found with that email', 'error')
    except Exception as e:
        flash(f'Error adding family member: {str(e)}', 'error')
    
    return redirect(url_for('emergency_notes'))

@app.route('/family-members/<member_id>/delete', methods=['POST'])
@login_required
def family_members_delete(member_id):
    user_id = session['user']['_id']
    result = FamilyMemberService.delete(member_id, user_id)
    
    if result.deleted_count > 0:
        flash('Family member removed successfully', 'success')
    else:
        flash('Family member not found or could not be removed', 'error')
    
    return redirect(url_for('emergency_notes'))

# Reminder Routes
@app.route('/reminders')
@login_required
def reminders_list():
    user_id = session['user']['_id']
    reminders = ReminderService.get_all(user_id)
    return render_template('reminders/list.html', reminders=reminders)

@app.route('/reminders/create', methods=['POST'])
@login_required
def reminders_create():
    user_id = session['user']['_id']
    try:
        ReminderService.create(user_id, request.form)
        flash('Reminder set successfully', 'success')
    except Exception as e:
        flash(f'Error setting reminder: {str(e)}', 'error')
    
    return redirect(request.referrer or url_for('dashboard'))

@app.route('/reminders/<reminder_id>/delete', methods=['POST'])
@login_required
def reminders_delete(reminder_id):
    user_id = session['user']['_id']
    result = ReminderService.delete(reminder_id, user_id)
    
    if result.deleted_count > 0:
        flash('Reminder deleted successfully', 'success')
    else:
        flash('Reminder not found or could not be deleted', 'error')
    
    return redirect(url_for('reminders_list'))

# API Endpoints for all resources
@app.route('/api/vaccines', methods=['GET'])
@login_required
def api_vaccines():
    user_id = session['user']['_id']
    vaccines = VaccineService.get_all(user_id)
    return jsonify({
        'success': True,
        'data': [{
            '_id': str(v['_id']),
            'name': v['name'],
            'date': v['date'].isoformat() if v.get('date') else None,
            'booster_due': v['booster_due'].isoformat() if v.get('booster_due') else None
        } for v in vaccines]
    })

@app.route('/api/lab-reports', methods=['GET'])
@login_required
def api_lab_reports():
    user_id = session['user']['_id']
    reports = LabReportService.get_all(user_id)
    return jsonify({
        'success': True,
        'data': [{
            '_id': str(r['_id']),
            'name': r['name'],
            'test_type': r['test_type'],
            'date': r['date'].isoformat() if r.get('date') else None
        } for r in reports]
    })

@app.route('/api/emergency-notes', methods=['GET'])
@login_required
def api_emergency_notes():
    user_id = session['user']['_id']
    notes = EmergencyNotesService.get(user_id)
    return jsonify({
        'success': True,
        'data': {
            'blood_type': notes.get('blood_type') if notes else None,
            'allergies': notes.get('allergies') if notes else None,
            'emergency_contacts': notes.get('emergency_contacts') if notes else None
        }
    })

@app.route('/api/family-members', methods=['GET'])
@login_required
def api_family_members():
    user_id = session['user']['_id']
    members = FamilyMemberService.get_all(user_id)
    return jsonify({
        'success': True,
        'data': [{
            '_id': str(m['_id']),
            'name': m['name'],
            'relation': m['relation'],
            'access_level': m['access_level']
        } for m in members]
    })

@app.route('/api/reminders', methods=['GET'])
@login_required
def api_reminders():
    user_id = session['user']['_id']
    reminders = ReminderService.get_all(user_id)
    return jsonify({
        'success': True,
        'data': [{
            '_id': str(r['_id']),
            'title': r['title'],
            'due_date': r['due_date'].isoformat() if r.get('due_date') else None,
            'notes': r.get('notes')
        } for r in reminders]
    })

class PDFExportService:
    @staticmethod
    def _add_header(story, title, user=None):
        """Helper method to add consistent header to all PDFs"""
        styles = getSampleStyleSheet()
        
        # Add logo (if you have one)
        # logo_path = "static/images/logo.png"
        # if os.path.exists(logo_path):
        #     story.append(Image(logo_path, width=100, height=50))
        
        # Title and user info
        story.append(Paragraph(title, styles['Title']))
        if user:
            story.append(Paragraph(f"Patient: {user.get('name', '')}", styles['Normal']))
            if user.get('age') and user.get('gender'):
                story.append(Paragraph(f"{user['age']} year old {user['gender']}", styles['Normal']))
        story.append(Spacer(1, 12))
        
        # Add generation date
        story.append(Paragraph(f"Generated on: {datetime.now().strftime('%B %d, %Y %H:%M')}", styles['Italic']))
        story.append(Spacer(1, 12))

    @staticmethod
    def _add_footer(story):
        """Helper method to add consistent footer to all PDFs"""
        styles = getSampleStyleSheet()
        story.append(Spacer(1, 12))
        story.append(Paragraph("Confidential Medical Document - Generated by Kobatela Health", 
                             styles['Italic']))

    @staticmethod
    def generate_health_summary(user_id):
        """Generate comprehensive health summary PDF"""
        buffer = BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=letter)
        styles = getSampleStyleSheet()
        story = []
        
        # Get user data
        user = UserService.get_by_id(user_id)
        
        # Header
        PDFExportService._add_header(story, "Comprehensive Health Summary", user)
        
        # Personal Information
        story.append(Paragraph("Personal Information", styles['Heading2']))
        personal_info = [
            f"Name: {user.get('name', '')}",
            f"Age: {user.get('age', '')}",
            f"Gender: {user.get('gender', '')}",
            f"Weight: {user.get('weight', '')} kg" if user.get('weight') else ""
        ]
        story.append(Paragraph("<br/>".join(filter(None, personal_info)), styles['Normal']))
        story.append(Spacer(1, 12))
        
        # Medical History
        history = MedicalHistoryService.get_all(user_id)
        if history:
            story.append(Paragraph("Medical History", styles['Heading2']))
            for item in history:
                date_str = item['date'].strftime('%b %d, %Y') if item.get('date') else 'No date'
                story.append(Paragraph(
                    f"<b>{item['type']}</b> ({date_str}): {item['details']}",
                    styles['Normal']
                ))
                if item.get('notes'):
                    story.append(Paragraph(
                    f"<i>Notes:</i> {item['notes']}",
                    styles['Normal']
                ))
                story.append(Spacer(1, 8))
            story.append(Spacer(1, 12))
        
        # Medications
        meds = MedicationService.get_all(user_id)
        if meds:
            story.append(Paragraph("Current Medications", styles['Heading2']))
            for med in meds:
                story.append(Paragraph(
                    f"<b>{med['name']}</b> ({med['dosage']}) - {med['frequency']}",
                    styles['Normal']
                ))
                if med.get('times'):
                    story.append(Paragraph(
                        f"Times: {', '.join(med['times'])}",
                        styles['Normal']
                    ))
                if med.get('notes'):
                    story.append(Paragraph(
                        f"<i>Notes:</i> {med['notes']}",
                        styles['Normal']
                    ))
                story.append(Spacer(1, 8))
            story.append(Spacer(1, 12))
        
        # Vaccines
        vax = VaccineService.get_all(user_id)
        if vax:
            story.append(Paragraph("Vaccination Records", styles['Heading2']))
            for vaccine in vax:
                date_str = vaccine['date'].strftime('%b %d, %Y') if vaccine.get('date') else 'No date'
                booster_str = f"<br/>Booster due: {vaccine['booster_due'].strftime('%b %d, %Y')}" if vaccine.get('booster_due') else ""
                story.append(Paragraph(
                    f"<b>{vaccine['name']}</b> ({date_str}){booster_str}",
                    styles['Normal']
                ))
                story.append(Spacer(1, 8))
            story.append(Spacer(1, 12))
        
        # Emergency Notes
        notes = EmergencyNotesService.get(user_id)
        if notes:
            story.append(Paragraph("Emergency Information", styles['Heading2']))
            if notes.get('blood_type'):
                story.append(Paragraph(f"Blood Type: {notes['blood_type']}", styles['Normal']))
            if notes.get('allergies'):
                story.append(Paragraph("Allergies:", styles['Heading3']))
                story.append(Paragraph(notes['allergies'], styles['Normal']))
            if notes.get('medical_conditions'):
                story.append(Paragraph("Medical Conditions:", styles['Heading3']))
                story.append(Paragraph(notes['medical_conditions'], styles['Normal']))
            if notes.get('emergency_contacts'):
                story.append(Paragraph("Emergency Contacts:", styles['Heading3']))
                story.append(Paragraph(notes['emergency_contacts'], styles['Normal']))
        
        # Footer
        PDFExportService._add_footer(story)
        
        doc.build(story)
        buffer.seek(0)
        return buffer

    @staticmethod
    def generate_medication_list(user_id):
        """Generate medication list PDF"""
        buffer = BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=letter)
        styles = getSampleStyleSheet()
        story = []
        
        # Get user data
        user = UserService.get_by_id(user_id)
        
        # Header
        PDFExportService._add_header(story, "Medication List", user)
        
        meds = MedicationService.get_all(user_id)
        for med in meds:
            story.append(Paragraph(
                f"<b>{med['name']}</b> ({med['dosage']})",
                styles['Heading3']
            ))
            story.append(Paragraph(
                f"Frequency: {med['frequency']}",
                styles['Normal']
            ))
            if med.get('times'):
                story.append(Paragraph(
                    f"Times: {', '.join(med['times'])}",
                    styles['Normal']
                ))
            if med.get('notes'):
                story.append(Paragraph(
                    f"Notes: {med['notes']}",
                    styles['Normal']
                ))
            story.append(Spacer(1, 12))
        
        # Footer
        PDFExportService._add_footer(story)
        
        doc.build(story)
        buffer.seek(0)
        return buffer

    @staticmethod
    def generate_vaccine_record(user_id):
        """Generate vaccine record PDF"""
        buffer = BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=letter)
        styles = getSampleStyleSheet()
        story = []
        
        # Get user data
        user = UserService.get_by_id(user_id)
        
        # Header
        PDFExportService._add_header(story, "Vaccination Record", user)
        
        vaccines = VaccineService.get_all(user_id)
        for vax in vaccines:
            date_str = vax['date'].strftime('%b %d, %Y') if vax.get('date') else 'No date'
            story.append(Paragraph(
                f"<b>{vax['name']}</b>",
                styles['Heading3']
            ))
            story.append(Paragraph(
                f"Date administered: {date_str}",
                styles['Normal']
            ))
            if vax.get('booster_due'):
                story.append(Paragraph(
                    f"Booster due: {vax['booster_due'].strftime('%b %d, %Y')}",
                    styles['Normal']
                ))
            story.append(Spacer(1, 12))
        
        # Footer
        PDFExportService._add_footer(story)
        
        doc.build(story)
        buffer.seek(0)
        return buffer

    @staticmethod
    def generate_lab_report_pdf(report_data, user_data):
        """Generate a detailed PDF for a single lab report"""
        buffer = BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=letter)
        styles = getSampleStyleSheet()
        story = []
        
        # Header
        PDFExportService._add_header(story, "Lab Test Report", user_data)
        
        # Report Details
        story.append(Paragraph(report_data.get('name', 'Lab Report'), styles['Heading2']))
        
        details = []
        if report_data.get('test_type'):
            details.append(f"<b>Test Type:</b> {report_data['test_type']}")
        if report_data.get('date'):
            details.append(f"<b>Date:</b> {report_data['date'].strftime('%B %d, %Y')}")
        
        story.append(Paragraph("<br/>".join(details), styles['Normal']))
        story.append(Spacer(1, 12))
        
        # Notes
        if report_data.get('notes'):
            story.append(Paragraph("Test Results and Notes:", styles['Heading3']))
            story.append(Paragraph(report_data['notes'], styles['Normal']))
            story.append(Spacer(1, 12))
        
        # Footer
        PDFExportService._add_footer(story)
        
        doc.build(story)
        buffer.seek(0)
        return buffer

    @staticmethod
    def generate_medical_history_pdf(history_data, user_data):
        """Generate a detailed PDF for a single medical history entry"""
        buffer = BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=letter)
        styles = getSampleStyleSheet()
        story = []
        
        # Header
        PDFExportService._add_header(story, "Medical History Record", user_data)
        
        # Title
        story.append(Paragraph(history_data.get('type', 'Medical Record'), styles['Heading2']))
        
        # Details
        details = []
        if history_data.get('date'):
            details.append(f"<b>Date:</b> {history_data['date'].strftime('%B %d, %Y')}")
        
        story.append(Paragraph("<br/>".join(details), styles['Normal']))
        story.append(Spacer(1, 12))
        
        # Main content
        story.append(Paragraph("<b>Details:</b>", styles['Normal']))
        story.append(Paragraph(history_data.get('details', ''), styles['Normal']))
        story.append(Spacer(1, 12))
        
        # Notes
        if history_data.get('notes'):
            story.append(Paragraph("<b>Additional Notes:</b>", styles['Normal']))
            story.append(Paragraph(history_data['notes'], styles['Normal']))
            story.append(Spacer(1, 12))
        
        # Footer
        PDFExportService._add_footer(story)
        
        doc.build(story)
        buffer.seek(0)
        return buffer

    @staticmethod
    def generate_emergency_info_pdf(user_id):
        """Generate emergency information PDF"""
        buffer = BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=letter)
        styles = getSampleStyleSheet()
        story = []
        
        # Get user data
        user = UserService.get_by_id(user_id)
        notes = EmergencyNotesService.get(user_id)
        
        # Header - make this one stand out more
        story.append(Paragraph("EMERGENCY MEDICAL INFORMATION", styles['Title']))
        story.append(Spacer(1, 12))
        story.append(Paragraph(f"Patient: {user.get('name', '')}", styles['Heading2']))
        if user.get('age') and user.get('gender'):
            story.append(Paragraph(f"{user['age']} year old {user['gender']}", styles['Heading3']))
        story.append(Spacer(1, 12))
        
        # Critical Information
        story.append(Paragraph("Critical Information", styles['Heading2']))
        
        if notes:
            if notes.get('blood_type'):
                story.append(Paragraph(
                    f"<b>Blood Type:</b> {notes['blood_type']}",
                    styles['Normal']
                ))
            
            if notes.get('allergies'):
                story.append(Paragraph(
                    "<b>Allergies:</b>",
                    styles['Heading3']
                ))
                story.append(Paragraph(
                    notes['allergies'],
                    styles['Normal']
                ))
            
            if notes.get('medical_conditions'):
                story.append(Paragraph(
                    "<b>Medical Conditions:</b>",
                    styles['Heading3']
                ))
                story.append(Paragraph(
                    notes['medical_conditions'],
                    styles['Normal']
                ))
        
        # Emergency Contacts
        if notes and notes.get('emergency_contacts'):
            story.append(Paragraph("Emergency Contacts", styles['Heading2']))
            story.append(Paragraph(
                notes['emergency_contacts'],
                styles['Normal']
            ))
        
        # Footer with big warning
        story.append(Spacer(1, 24))
        story.append(Paragraph(
            "IN CASE OF EMERGENCY, PLEASE PROVIDE THIS DOCUMENT TO MEDICAL PERSONNEL",
            styles['Heading2']
        ))
        
        doc.build(story)
        buffer.seek(0)
        return buffer

# PDF Export Routes
@app.route('/export/health-summary')
@login_required
def export_health_summary():
    user_id = session['user']['_id']
    pdf_buffer = PDFExportService.generate_health_summary(user_id)
    
    return send_file(
        pdf_buffer,
        as_attachment=True,
        download_name=f"kobatela_health_summary_{datetime.now().strftime('%Y%m%d')}.pdf",
        mimetype='application/pdf'
    )

@app.route('/export/medications')
@login_required
def export_medications():
    user_id = session['user']['_id']
    pdf_buffer = PDFExportService.generate_medication_list(user_id)
    
    return send_file(
        pdf_buffer,
        as_attachment=True,
        download_name=f"medication_list_{datetime.now().strftime('%Y%m%d')}.pdf",
        mimetype='application/pdf'
    )

@app.route('/export/vaccines')
@login_required
def export_vaccines():
    user_id = session['user']['_id']
    pdf_buffer = PDFExportService.generate_vaccine_record(user_id)
    
    return send_file(
        pdf_buffer,
        as_attachment=True,
        download_name=f"vaccine_record_{datetime.now().strftime('%Y%m%d')}.pdf",
        mimetype='application/pdf'
    )

@app.route('/export/all-lab-reports')
@login_required
def export_all_lab_reports():
    """Export all lab reports as PDF"""
    user_id = session['user']['_id']
    user = UserService.get_by_id(user_id)
    reports = LabReportService.get_all(user_id)
    
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter)
    styles = getSampleStyleSheet()
    story = []
    
    # Header
    PDFExportService._add_header(story, "All Lab Reports", user)
    
    # Add each report
    for report in reports:
        date_str = report['date'].strftime('%b %d, %Y') if report.get('date') else 'No date'
        story.append(Paragraph(
            f"<b>{report['name']}</b> ({report.get('test_type', '')}) - {date_str}",
            styles['Heading3']
        ))
        if report.get('notes'):
            story.append(Paragraph(report['notes'], styles['Normal']))
        story.append(Spacer(1, 12))
    
    PDFExportService._add_footer(story)
    doc.build(story)
    buffer.seek(0)
    
    return send_file(
        buffer,
        as_attachment=True,
        download_name=f"all_lab_reports_{datetime.now().strftime('%Y%m%d')}.pdf",
        mimetype='application/pdf'
    )

@app.route('/export/all-medical-history')
@login_required
def export_all_medical_history():
    """Export all medical history entries as PDF"""
    user_id = session['user']['_id']
    user = UserService.get_by_id(user_id)
    history = MedicalHistoryService.get_all(user_id)
    
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter)
    styles = getSampleStyleSheet()
    story = []
    
    # Header
    PDFExportService._add_header(story, "Complete Medical History", user)
    
    # Add each entry
    for entry in history:
        date_str = entry['date'].strftime('%b %d, %Y') if entry.get('date') else 'No date'
        story.append(Paragraph(
            f"<b>{entry['type']}</b> - {date_str}",
            styles['Heading3']
        ))
        story.append(Paragraph(entry['details'], styles['Normal']))
        if entry.get('notes'):
            story.append(Paragraph(f"Notes: {entry['notes']}", styles['Normal']))
        story.append(Spacer(1, 12))
    
    PDFExportService._add_footer(story)
    doc.build(story)
    buffer.seek(0)
    
    return send_file(
        buffer,
        as_attachment=True,
        download_name=f"complete_medical_history_{datetime.now().strftime('%Y%m%d')}.pdf",
        mimetype='application/pdf'
    )

# File Download Routes
@app.route('/download/medical-history/<entry_id>')
@login_required
def download_medical_history_attachment(entry_id):
    user_id = session['user']['_id']
    entry = MedicalHistoryService.get_by_id(entry_id, user_id)
    
    if not entry or not entry.get('filename'):
        flash('File not found', 'error')
        return redirect(url_for('medical_history_list'))
    
    # Add the medical_history subfolder to the path
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], 'medical_history', entry['filename'])
    
    if not os.path.exists(filepath):
        flash('File no longer available', 'error')
        return redirect(url_for('medical_history_list'))
    
    return send_file(
        filepath,
        as_attachment=True,
        download_name=os.path.basename(entry['filename'])
    )

@app.route('/download/lab-report/<report_id>')
@login_required
def download_lab_report(report_id):
    user_id = session['user']['_id']
    report = LabReportService.get_by_id(report_id, user_id)
    
    if not report or not report.get('filename'):
        flash('Report not found', 'error')
        return redirect(url_for('lab_reports_list'))
    
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], 'lab_reports', report['filename'])
    
    if not os.path.exists(filepath):
        flash('Report file no longer available', 'error')
        return redirect(url_for('lab_reports_list'))
    
    return send_file(
        filepath,
        as_attachment=True,
        download_name=f"lab_report_{report['name']}_{report['date'].strftime('%Y%m%d') if report.get('date') else 'nodate'}.{report['filename'].split('.')[-1]}"
    )

@app.route('/download/vaccine/<vaccine_id>')
@login_required
def download_vaccine_attachment(vaccine_id):
    user_id = session['user']['_id']
    vaccine = VaccineService.get_by_id(vaccine_id, user_id)
    
    if not vaccine or not vaccine.get('attachment'):
        flash('File not found', 'error')
        return redirect(url_for('vaccines_list'))
    
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], 'vaccines', vaccine['attachment'])
    
    if not os.path.exists(filepath):
        flash('File no longer available', 'error')
        return redirect(url_for('vaccines_list'))
    
    return send_file(
        filepath,
        as_attachment=True,
        download_name=os.path.basename(vaccine['attachment'])
    )

@app.route('/view/lab-report/<report_id>')
@login_required
def view_lab_report_attachment(report_id):
    user_id = session['user']['_id']
    report = LabReportService.get_by_id(report_id, user_id)
    
    if not report or not report.get('filename'):
        flash('File not found', 'error')
        return redirect(url_for('lab_reports_list'))
    
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], 'lab_reports', report['filename'])
    
    if not os.path.exists(filepath):
        flash('File no longer available', 'error')
        return redirect(url_for('lab_reports_list'))
    
    # For images and PDFs, we can display them in the browser
    file_ext = report['filename'].split('.')[-1].lower()
    
    if file_ext in ['png', 'jpg', 'jpeg', 'pdf']:
        return send_file(filepath)
    else:
        # For other file types, force download
        return send_file(
            filepath,
            as_attachment=True,
            download_name=os.path.basename(report['filename'])
        )

@app.route('/download/medication/<med_id>')
@login_required
def download_medication_attachment(med_id):
    user_id = session['user']['_id']
    medication = MedicationService.get_by_id(med_id, user_id)
    
    if not medication or not medication.get('attachment'):
        flash('File not found', 'error')
        return redirect(url_for('medications_list'))
    
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], 'medications', medication['attachment'])
    
    if not os.path.exists(filepath):
        flash('File no longer available', 'error')
        return redirect(url_for('medications_list'))
    
    return send_file(
        filepath,
        as_attachment=True,
        download_name=os.path.basename(medication['attachment'])
    )

@app.route('/view/medication/<med_id>')
@login_required
def view_medication_attachment(med_id):
    user_id = session['user']['_id']
    medication = MedicationService.get_by_id(med_id, user_id)
    
    if not medication or not medication.get('attachment'):
        flash('File not found', 'error')
        return redirect(url_for('medications_list'))
    
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], 'medications', medication['attachment'])
    
    if not os.path.exists(filepath):
        flash('File no longer available', 'error')
        return redirect(url_for('medications_list'))
    
    # For images and PDFs, we can display them in the browser
    file_ext = medication['attachment'].split('.')[-1].lower()
    
    if file_ext in ['png', 'jpg', 'jpeg', 'pdf']:
        return send_file(filepath)
    else:
        # For other file types, force download
        return send_file(
            filepath,
            as_attachment=True,
            download_name=os.path.basename(medication['attachment'])
        )

@app.route('/api/health-recommendations')
@login_required
def api_health_recommendations():
    user_id = session['user']['_id']
    user = UserService.get_by_id(user_id)
    
    if not user.get('age') or not user.get('gender'):
        return jsonify({'success': False, 'error': 'Incomplete profile'})
    
    try:
        model = genai.GenerativeModel('gemini-pro')
        prompt = f"""
        Suggest 4-6 health screening tests for a {user['age']} year old {user['gender']}.
        For each test, provide:
        - A short name (max 3 words)
        - Brief description (1 sentence)
        - Recommended frequency (e.g., 'annually')
        
        Return as JSON with 'suggestions' array containing objects with these fields:
        name, description, frequency
        """
        response = model.generate_content(prompt)
        suggestions = json.loads(response.text).get('suggestions', [])
        
        return jsonify({'success': True, 'suggestions': suggestions})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

if __name__ == '__main__':
    app.run(debug=True)