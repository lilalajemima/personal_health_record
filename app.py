from flask import Flask, render_template, request, redirect, url_for, session, flash, send_file, jsonify
from pymongo import MongoClient
from dotenv import load_dotenv
from datetime import datetime
import os
import google.generativeai as genai
from werkzeug.utils import secure_filename
from bson.objectid import ObjectId
from typing import Dict, List, Optional
from dataclasses import dataclass
from io import BytesIO
from reportlab.pdfgen import canvas
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests
import google.auth.transport.requests
import google.oauth2.id_token
import google_auth_oauthlib.flow
import requests

# Load environment variables
load_dotenv()

# Initialize Flask app
app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "dev-secret-key")

# Configure file uploads
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Configure MongoDB




# Configure Gemini AI
genai.configure(api_key=os.getenv("GEMINI_API_KEY"))
model = genai.GenerativeModel('gemini-pro')

# Configure Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Google OAuth config
app.config['GOOGLE_CLIENT_ID'] = os.getenv("GOOGLE_CLIENT_ID")
app.config['GOOGLE_CLIENT_SECRET'] = os.getenv("GOOGLE_CLIENT_SECRET")
app.config['GOOGLE_DISCOVERY_URL'] = "https://accounts.google.com/.well-known/openid-configuration"

# Data classes for type hints
@dataclass
class SuggestTestsState:
    message: Optional[str]
    errors: Optional[Dict[str, List[str]]]
    suggestions: Optional[Dict]

class User(UserMixin):
    def __init__(self, user_data):
        self.id = str(user_data['_id'])
        self.email = user_data['email']
        self.name = user_data.get('name', '')
        self.avatar = user_data.get('avatar_url', '')

@login_manager.user_loader
def load_user(user_id):
    user_data = db.users.find_one({"_id": ObjectId(user_id)})
    if not user_data:
        return None
    return User(user_data)

def get_google_provider_cfg():
    return requests.get(app.config['GOOGLE_DISCOVERY_URL']).json()

# Custom template filters
@app.template_filter('datetimeformat')
def datetimeformat(value, format='%b %d, %Y'):
    if value is None:
        return ""
    if isinstance(value, str):
        try:
            value = datetime.strptime(value, '%Y-%m-%d')
        except:
            return value
    return value.strftime(format)

# Helper functions
def parse_ai_response(text: str) -> Dict:
    """Parse the AI response into structured data"""
    parts = text.split("\n\n")
    suggested_tests = []
    reasoning = ""
    
    for part in parts:
        if "recommended tests" in part.lower() or "suggested tests" in part.lower():
            tests = [line.strip() for line in part.split("\n") if line.strip()]
            suggested_tests = [t for t in tests if not t.lower().startswith("recommended")]
        elif "reasoning" in part.lower():
            reasoning = part.replace("Reasoning:", "").strip()
    
    return {
        "suggestedTests": suggested_tests,
        "reasoning": reasoning
    }

@app.context_processor
def inject_now():
    return {'now': datetime.utcnow()}

# Authentication routes
@app.route('/login')
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('login.html')

@app.route('/login/google')
def google_login():
    # Create flow instance to manage the OAuth 2.0 Authorization Grant Flow steps
    flow = google_auth_oauthlib.flow.Flow.from_client_config(
        client_config={
            "web": {
                "client_id": app.config['GOOGLE_CLIENT_ID'],
                "client_secret": app.config['GOOGLE_CLIENT_SECRET'],
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://accounts.google.com/o/oauth2/token",
                "redirect_uris": [url_for('google_callback', _external=True)]
            }
        },
        scopes=["openid", "https://www.googleapis.com/auth/userinfo.email", "https://www.googleapis.com/auth/userinfo.profile"]
    )
    
    # Generate authorization URL
    authorization_url, state = flow.authorization_url(
        access_type='offline',
        include_granted_scopes='true'
    )
    
    # Store the state in session
    session['state'] = state
    
    return redirect(authorization_url)

@app.route('/login/google/callback')
def google_callback():
    # Verify state
    if request.args.get('state') != session.get('state'):
        flash('Invalid state parameter', 'error')
        return redirect(url_for('login'))
    
    # Create flow instance
    flow = google_auth_oauthlib.flow.Flow.from_client_config(
        client_config={
            "web": {
                "client_id": app.config['GOOGLE_CLIENT_ID'],
                "client_secret": app.config['GOOGLE_CLIENT_SECRET'],
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://accounts.google.com/o/oauth2/token",
                "redirect_uris": [url_for('google_callback', _external=True)]
            }
        },
        scopes=["openid", "https://www.googleapis.com/auth/userinfo.email", "https://www.googleapis.com/auth/userinfo.profile"],
        state=session['state']
    )
    
    # Exchange auth code for tokens
    flow.fetch_token(authorization_response=request.url)
    
    # Get user info
    credentials = flow.credentials
    id_info = id_token.verify_oauth2_token(
        credentials.id_token,
        google_requests.Request(),
        app.config['GOOGLE_CLIENT_ID']
    )
    
    # Check if user exists or create new user
    user = db.users.find_one({"email": id_info['email']})
    if not user:
        user_data = {
            "email": id_info['email'],
            "name": id_info.get('name', ''),
            "avatar_url": id_info.get('picture', ''),
            "created_at": datetime.utcnow(),
            "last_login": datetime.utcnow()
        }
        user_id = db.users.insert_one(user_data).inserted_id
        user = db.users.find_one({"_id": user_id})
    else:
        db.users.update_one(
            {"_id": user["_id"]},
            {"$set": {"last_login": datetime.utcnow()}}
        )
    
    # Log in the user
    login_user(User(user))
    
    flash('Logged in successfully!', 'success')
    return redirect(url_for('dashboard'))

@app.route('/logout')
@login_required
def logout():
    logout_user()
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

# Application routes
@app.route('/')
@login_required
def dashboard():
    user = db.users.find_one({"_id": ObjectId(current_user.id)})
    if not user:
        logout_user()
        return redirect(url_for('login'))
    
    # Get data for dashboard
    medications = list(db.medications.find({"user_id": user["_id"]}).limit(3))
    vaccines = list(db.vaccines.find({"user_id": user["_id"]}).sort("date", -1).limit(3))
    lab_reports = list(db.lab_reports.find({"user_id": user["_id"]}).sort("date", -1).limit(3))
    
    return render_template(
        'dashboard.html',
        user=user,
        medications=medications,
        vaccines=vaccines,
        lab_reports=lab_reports,
        active_tab='dashboard'
    )

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    user = db.users.find_one({"_id": ObjectId(current_user.id)})
    if not user:
        logout_user()
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        updates = {
            "name": request.form.get('name'),
            "email": request.form.get('email'),
            "age": int(request.form.get('age', 0)),
            "weight": int(request.form.get('weight', 0)),
            "gender": request.form.get('gender'),
            "updated_at": datetime.utcnow()
        }
        
        # Handle file upload
        if 'avatar' in request.files:
            file = request.files['avatar']
            if file.filename != '':
                filename = secure_filename(file.filename)
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                updates["avatar_url"] = url_for('static', filename=f'uploads/{filename}')
        
        db.users.update_one(
            {"_id": user["_id"]},
            {"$set": updates}
        )
        flash('Profile updated successfully!', 'success')
        return redirect(url_for('profile'))
    
    return render_template(
        'profile.html',
        user=user,
        active_tab='profile'
    )

@app.route('/medical-history', methods=['GET', 'POST'])
@login_required
def medical_history():
    user = db.users.find_one({"_id": ObjectId(current_user.id)})
    if not user:
        logout_user()
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        # Handle file upload
        file = request.files.get('attachment')
        filename = None
        if file and file.filename != '':
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        
        # Create new history entry
        new_entry = {
            "user_id": user["_id"],
            "type": request.form.get('type'),
            "details": request.form.get('details'),
            "date": request.form.get('date'),
            "notes": request.form.get('notes'),
            "filename": filename,
            "created_at": datetime.utcnow()
        }
        
        db.medical_history.insert_one(new_entry)
        flash('Medical history entry added successfully!', 'success')
        return redirect(url_for('medical_history'))
    
    history = list(db.medical_history.find({"user_id": user["_id"]}).sort("date", -1))
    
    return render_template(
        'medical_history.html',
        user=user,
        history=history,
        active_tab='history'
    )

@app.route('/medications', methods=['GET', 'POST'])
@login_required
def medications():
    user = db.users.find_one({"_id": ObjectId(current_user.id)})
    if not user:
        logout_user()
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        times = request.form.get('time', '').split(',')
        times = [t.strip() for t in times if t.strip()]
        
        new_med = {
            "user_id": user["_id"],
            "name": request.form.get('name'),
            "dosage": request.form.get('dosage'),
            "frequency": request.form.get('frequency'),
            "times": times,
            "created_at": datetime.utcnow()
        }
        
        db.medications.insert_one(new_med)
        flash('Medication added successfully!', 'success')
        return redirect(url_for('medications'))
    
    meds = list(db.medications.find({"user_id": user["_id"]}))
    
    return render_template(
        'medications.html',
        user=user,
        medications=meds,
        active_tab='meds'
    )

@app.route('/delete-medication/<med_id>')
@login_required
def delete_medication(med_id):
    user = db.users.find_one({"_id": ObjectId(current_user.id)})
    if not user:
        logout_user()
        return redirect(url_for('login'))
    
    db.medications.delete_one({"_id": ObjectId(med_id), "user_id": user["_id"]})
    flash('Medication deleted successfully', 'success')
    return redirect(url_for('medications'))

@app.route('/vaccines', methods=['GET', 'POST'])
@login_required
def vaccines():
    user = db.users.find_one({"_id": ObjectId(current_user.id)})
    if not user:
        logout_user()
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        # Handle file upload
        file = request.files.get('attachment')
        filename = None
        if file and file.filename != '':
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        
        # Create new vaccine record
        new_vaccine = {
            "user_id": user["_id"],
            "name": request.form.get('name'),
            "date": request.form.get('date'),
            "booster_due": request.form.get('booster_due') or None,
            "filename": filename,
            "created_at": datetime.utcnow()
        }
        
        db.vaccines.insert_one(new_vaccine)
        flash('Vaccine record added successfully!', 'success')
        return redirect(url_for('vaccines'))
    
    # Calculate booster statuses
    today = datetime.utcnow()
    vaccines = list(db.vaccines.find({"user_id": user["_id"]}).sort("date", -1))
    for vaccine in vaccines:
        if vaccine.get('booster_due'):
            try:
                booster_date = datetime.strptime(vaccine['booster_due'], '%Y-%m-%d')
                days_until_due = (booster_date - today).days
                
                if days_until_due < 0:
                    vaccine['booster_status'] = {'text': 'Overdue', 'variant': 'destructive'}
                elif days_until_due <= 30:
                    vaccine['booster_status'] = {'text': 'Due Soon', 'variant': 'outline'}
                else:
                    vaccine['booster_status'] = {'text': booster_date.strftime('%b %d, %Y'), 'variant': 'default'}
            except:
                vaccine['booster_status'] = {'text': vaccine['booster_due'], 'variant': 'secondary'}
        else:
            vaccine['booster_status'] = {'text': 'N/A', 'variant': 'secondary'}
    
    return render_template(
        'vaccines.html',
        user=user,
        vaccines=vaccines,
        active_tab='vaccines'
    )

@app.route('/set-vaccine-reminder/<vaccine_id>')
@login_required
def set_vaccine_reminder(vaccine_id):
    user = db.users.find_one({"_id": ObjectId(current_user.id)})
    if not user:
        logout_user()
        return redirect(url_for('login'))
    
    vaccine = db.vaccines.find_one({"_id": ObjectId(vaccine_id), "user_id": user["_id"]})
    if vaccine:
        flash(f'Reminder set for {vaccine["name"]} booster', 'info')
    return redirect(url_for('vaccines'))

@app.route('/lab-reports', methods=['GET', 'POST'])
@login_required
def lab_reports():
    user = db.users.find_one({"_id": ObjectId(current_user.id)})
    if not user:
        logout_user()
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        file = request.files.get('file')
        if file and file.filename != '':
            filename = secure_filename(file.filename)
            file_id = db.lab_reports.insert_one({
                "user_id": user["_id"],
                "filename": filename,
                "name": os.path.splitext(filename)[0],
                "date": datetime.utcnow().strftime('%Y-%m-%d'),
                "type": "General",
                "uploaded_at": datetime.utcnow()
            }).inserted_id
            
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            flash(f'Report {filename} uploaded successfully!', 'success')
    
    reports = list(db.lab_reports.find({"user_id": user["_id"]}).sort("date", -1))
    medical_history = list(db.medical_history.find({"user_id": user["_id"]}))
    
    return render_template(
        'lab_reports.html',
        user=user,
        reports=reports,
        medical_history=medical_history,
        active_tab='labs'
    )

@app.route('/delete-lab-report/<report_id>')
@login_required
def delete_lab_report(report_id):
    user = db.users.find_one({"_id": ObjectId(current_user.id)})
    if not user:
        logout_user()
        return redirect(url_for('login'))
    
    report = db.lab_reports.find_one({"_id": ObjectId(report_id), "user_id": user["_id"]})
    if report:
        try:
            os.remove(os.path.join(app.config['UPLOAD_FOLDER'], report['filename']))
        except:
            pass
        
        db.lab_reports.delete_one({"_id": ObjectId(report_id)})
        flash('Lab report deleted successfully', 'success')
    
    return redirect(url_for('lab_reports'))

@app.route('/emergency-notes', methods=['GET', 'POST'])
@login_required
def emergency_notes():
    user = db.users.find_one({"_id": ObjectId(current_user.id)})
    if not user:
        logout_user()
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        updates = {
            "blood_type": request.form.get('blood_type'),
            "allergies": request.form.get('allergies'),
            "emergency_contacts": request.form.get('contacts'),
            "medical_conditions": request.form.get('conditions'),
            "updated_at": datetime.utcnow()
        }
        
        db.emergency_notes.update_one(
            {"user_id": user["_id"]},
            {"$set": updates},
            upsert=True
        )
        flash('Emergency notes updated successfully!', 'success')
        return redirect(url_for('emergency_notes'))
    
    notes = db.emergency_notes.find_one({"user_id": user["_id"]}) or {}
    family = list(db.family_members.find({"user_id": user["_id"]}))
    
    return render_template(
        'emergency_notes.html',
        user=user,
        notes=notes,
        family=family,
        active_tab='emergency'
    )

@app.route('/add-family-member', methods=['POST'])
@login_required
def add_family_member():
    user = db.users.find_one({"_id": ObjectId(current_user.id)})
    if not user:
        logout_user()
        return redirect(url_for('login'))
    
    initials = request.form.get('name', '')[:2].upper()
    new_member = {
        "user_id": user["_id"],
        "name": request.form.get('name'),
        "email": request.form.get('email'),
        "relation": request.form.get('relation'),
        "initials": initials,
        "created_at": datetime.utcnow()
    }
    
    db.family_members.insert_one(new_member)
    flash('Family member added successfully!', 'success')
    return redirect(url_for('emergency_notes'))

@app.route('/api/suggest-tests', methods=['POST'])
@login_required
def api_suggest_tests():
    user = db.users.find_one({"_id": ObjectId(current_user.id)})
    if not user:
        return jsonify({
            "message": "Unauthorized",
            "errors": {"auth": ["Please login"]},
            "suggestions": None
        }), 401
    
    data = request.get_json()
    if not data:
        return jsonify({
            "message": "Invalid request data",
            "errors": {"form": ["Invalid request format"]},
            "suggestions": None
        }), 400

    # Validate input
    errors = {}
    if not data.get('age') or not isinstance(data.get('age'), int) or data['age'] <= 0:
        errors['age'] = ["Age must be a positive number"]
    if data.get('gender') not in ['male', 'female']:
        errors['gender'] = ["Please select a valid gender"]
    if not data.get('healthHistory'):
        errors['healthHistory'] = ["Health history is required"]
    if not data.get('labReports'):
        errors['labReports'] = ["Lab reports are required"]

    if errors:
        return jsonify({
            "message": "Validation failed",
            "errors": errors,
            "suggestions": None
        }), 400

    try:
        # Generate prompt for AI
        prompt = f"""
        Suggest medical tests for a {data['age']} year old {data['gender']} based on:
        - Health History: {data['healthHistory']}
        - Previous Lab Reports: {data['labReports']}
        
        Provide:
        1. A list of recommended tests with brief explanations
        2. The clinical reasoning behind these suggestions
        """

        response = model.generate_content(prompt)
        suggestions = parse_ai_response(response.text)

        return jsonify({
            "message": "Suggestions generated successfully",
            "errors": None,
            "suggestions": suggestions
        })

    except Exception as e:
        print(f"Error generating suggestions: {str(e)}")
        return jsonify({
            "message": "An error occurred while generating suggestions",
            "errors": None,
            "suggestions": None
        }), 500

@app.route('/export-data')
@login_required
def export_data():
    user = db.users.find_one({"_id": ObjectId(current_user.id)})
    if not user:
        logout_user()
        return redirect(url_for('login'))
    
    # Create a PDF (in-memory)
    buffer = BytesIO()
    p = canvas.Canvas(buffer)
    
    # Add PDF content
    p.drawString(100, 800, f"Health Data Export for {user['name']}")
    p.drawString(100, 780, f"Generated on {datetime.now().strftime('%Y-%m-%d')}")
    
    # Add user data
    y_position = 750
    p.drawString(100, y_position, "Personal Information:")
    y_position -= 20
    p.drawString(120, y_position, f"Name: {user.get('name', '')}")
    y_position -= 20
    p.drawString(120, y_position, f"Email: {user.get('email', '')}")
    
    # Add more data as needed...
    
    p.showPage()
    p.save()
    
    buffer.seek(0)
    return send_file(
        buffer,
        as_attachment=True,
        download_name=f"health_export_{datetime.now().strftime('%Y%m%d')}.pdf",
        mimetype='application/pdf'
    )

if __name__ == '__main__':
    app.run(debug=True)  # SSL required for Google OAuth