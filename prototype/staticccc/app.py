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
app.secret_key = b'\xcc^\x91\xea\x17-\xd0W\x03\xa7\xf8J0\xac8\xc5'


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

def generate_pdf_export(user_id):
    """Generate comprehensive PDF health summary"""
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter)
    styles = getSampleStyleSheet()
    story = []
    
    # User info
    user = users.find_one({"_id": ObjectId(user_id)})
    story.append(Paragraph(f"Kobatela Health Summary for {user.get('name', '')}", styles['Title']))
    story.append(Spacer(1, 12))
    
    # Personal Information
    story.append(Paragraph("Personal Information", styles['Heading2']))
    story.append(Paragraph(f"Name: {user.get('name', '')}", styles['Normal']))
    story.append(Paragraph(f"Age: {user.get('age', '')}", styles['Normal']))
    story.append(Paragraph(f"Gender: {user.get('gender', '')}", styles['Normal']))
    story.append(Spacer(1, 12))
    
    # Medical History
    history = list(col_medical_history.find({"user_id": ObjectId(user_id)}).sort("date", -1))
    if history:
        story.append(Paragraph("Medical History", styles['Heading2']))
        for item in history:
            story.append(Paragraph(f"- {item['type']}: {item['details']} ({item['date']})", styles['Normal']))
        story.append(Spacer(1, 12))
    
    # Medications
    meds = list(col_medications.find({"user_id": ObjectId(user_id)}))
    if meds:
        story.append(Paragraph("Current Medications", styles['Heading2']))
        for med in meds:
            story.append(Paragraph(f"- {med['name']} ({med['dosage']}), {med['frequency']}", styles['Normal']))
        story.append(Spacer(1, 12))
    
    # Vaccines
    vax = list(col_vaccines.find({"user_id": ObjectId(user_id)}).sort("date", -1))
    if vax:
        story.append(Paragraph("Vaccination Records", styles['Heading2']))
        for vaccine in vax:
            booster_info = f", Booster due: {vaccine['booster_due']}" if vaccine.get('booster_due') else ""
            story.append(Paragraph(f"- {vaccine['name']} ({vaccine['date']}{booster_info})", styles['Normal']))
        story.append(Spacer(1, 12))
    
    # Emergency Notes
    notes = col_emergency_notes.find_one({"user_id": ObjectId(user_id)})
    if notes:
        story.append(Paragraph("Emergency Information", styles['Heading2']))
        if notes.get('blood_type'):
            story.append(Paragraph(f"Blood Type: {notes['blood_type']}", styles['Normal']))
        if notes.get('allergies'):
            story.append(Paragraph("Allergies:", styles['Normal']))
            story.append(Paragraph(notes['allergies'], styles['Normal']))
        if notes.get('emergency_contacts'):
            story.append(Paragraph("Emergency Contacts:", styles['Normal']))
            story.append(Paragraph(notes['emergency_contacts'], styles['Normal']))
    
    doc.build(story)
    buffer.seek(0)
    return buffer

# User class for authentication
class User:
    def start_session(self, user):
        user['_id'] = str(user['_id'])
        del user['password']
        session['logged_in'] = True
        session['user'] = user
        return redirect(url_for('dashboard'))

    def signup(self):
        # Validate input
        if not request.form.get('email') or not request.form.get('password'):
            flash("Email and password are required", "error")
            return redirect(url_for('signup'))

        user = {
            "_id": ObjectId(),
            "name": request.form.get('name', ""),
            "email": request.form.get('email'),
            "password": pbkdf2_sha256.hash(request.form.get('password')),
            "age": int(request.form.get('age', 0)) if request.form.get('age') else None,
            "gender": request.form.get('gender'),
            "weight": float(request.form.get('weight')) if request.form.get('weight') else None,
            "avatar_url": "",
            "role": "user",
            "created_at": datetime.utcnow(),
            "last_login": None
        }

        # Check for existing user
        if users.find_one({"email": user['email']}):
            flash("Email already exists", "error")
            return redirect(url_for('signup'))

        # Insert user
        if users.insert_one(user):
            return self.start_session(user)
        
        flash("Signup failed", "error")
        return redirect(url_for('signup'))

    def login(self):
        email = request.form.get('email').strip()
        password = request.form.get('password').strip()
    
        print(f"Attempting login for email: '{email}'")
        print(f"Password length: {len(password)}")
    
        user = users.find_one({"email": email})
    
        if user:
            print(f"Stored hash: {user['password']}")
            if pbkdf2_sha256.verify(password, user['password']):
                print("Password verified")
                # Update last login with timezone-aware datetime
                users.update_one(
                    {"_id": user['_id']},
                    {"$set": {"last_login": datetime.utcnow()}}
                )
                return self.start_session(user)
            else:
                print("Password verification failed - possible causes:")
                print(f"- Wrong password entered")
                print(f"- Password contains hidden whitespace")
                print(f"- Different password used during signup")
        else:
            print("No user found with that email")  
        
        flash("Invalid credentials", "error")
        return redirect(url_for('login'))

    def signout(self):
        session.clear()
        flash("You have been logged out", "info")
        return redirect(url_for('login'))

user_manager = User()

@app.context_processor
def inject_datetime():
    from datetime import datetime
    return {'datetime': datetime}

@app.context_processor
def inject_now():
    return {'now': datetime.utcnow()}

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
        result = user_manager.login()
        if result:
            return result
    
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if 'logged_in' in session:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        result = user_manager.signup()
        if result:
            return result
    
    return render_template('signup.html')

@app.route('/logout')
@login_required
def logout():
    return user_manager.signout()

# Dashboard
@app.route('/dashboard')
@login_required
def dashboard():
    user_id = ObjectId(session['user']['_id'])
    
    # Get counts for summary cards
    med_count = col_medications.count_documents({"user_id": user_id})
    upcoming_reminders = list(col_reminders.find({
        "user_id": user_id,
        "due_date": {"$gte": datetime.utcnow()}
    }).sort("due_date", 1).limit(3))
    
    # Get next vaccine due
    next_vaccine = col_vaccines.find_one({
        "user_id": user_id,
        "$or": [
            {"booster_due": {"$gte": datetime.utcnow().strftime('%Y-%m-%d')}},
            {"booster_due": {"$exists": False}}
        ]
    }, sort=[("booster_due", 1)])
    
    # Get most recent lab report
    recent_lab = col_lab_reports.find_one(
        {"user_id": user_id},
        sort=[("date", -1)]
    )
    
    return render_template('dashboard.html',
        med_count=med_count,
        reminders=upcoming_reminders,
        next_vaccine=next_vaccine,
        recent_lab=recent_lab,
        current_date=datetime.now().strftime('%B %d, %Y')
    )

# Profile
@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    user_id = ObjectId(session['user']['_id'])
    user = users.find_one({"_id": user_id})
    
    if request.method == 'POST':
        updates = {
            "name": request.form.get('name'),
            "email": request.form.get('email'),
            "age": int(request.form.get('age')) if request.form.get('age') else None,
            "weight": float(request.form.get('weight')) if request.form.get('weight') else None,
            "gender": request.form.get('gender'),
            "updated_at": datetime.utcnow()
        }
        
        # Handle file upload
        if 'avatar' in request.files:
            file = request.files['avatar']
            if file and allowed_file(file.filename):
                filename = secure_filename(f"{user_id}_{file.filename}")
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], 'avatars', filename)
                os.makedirs(os.path.dirname(filepath), exist_ok=True)
                file.save(filepath)
                updates['avatar_url'] = f"/static/uploads/avatars/{filename}"
        
        # Update password if provided
        if request.form.get('current_password') and request.form.get('new_password'):
            if pbkdf2_sha256.verify(request.form.get('current_password'), user['password']):
                updates['password'] = pbkdf2_sha256.hash(request.form.get('new_password'))
            else:
                flash("Current password is incorrect", "error")
                return redirect(url_for('profile'))
        
        users.update_one({"_id": user_id}, {"$set": updates})
        session['user'] = users.find_one({"_id": user_id})
        flash("Profile updated successfully", "success")
        return redirect(url_for('profile'))
    
    return render_template('profile.html', user=user)

# Medical History
@app.route('/medical-history', methods=['GET', 'POST'])
@login_required
def medical_history():
    user_id = ObjectId(session['user']['_id'])
    
    if request.method == 'POST':
        # Handle file upload
        file = request.files.get('attachment')
        filename = None
        if file and file.filename != '' and allowed_file(file.filename):
            filename = secure_filename(f"{user_id}_{datetime.now().strftime('%Y%m%d%H%M%S')}_{file.filename}")
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], 'medical_history', filename)
            os.makedirs(os.path.dirname(filepath), exist_ok=True)
            file.save(filepath)
            filename = f"medical_history/{filename}"
        
        # Parse the date string into a datetime object
        date_str = request.form.get('date')
        try:
            entry_date = datetime.strptime(date_str, '%Y-%m-%d') if date_str else None
        except ValueError:
            entry_date = None
            flash('Invalid date format', 'error')
            return redirect(url_for('medical_history'))
        
        # Create new entry with proper datetime object
        new_entry = {
            "user_id": user_id,
            "type": request.form.get('type'),
            "details": request.form.get('details'),
            "date": entry_date,
            "notes": request.form.get('notes'),
            "filename": filename,
            "created_at": datetime.utcnow()
        }
        
        col_medical_history.insert_one(new_entry)
        flash('Medical history entry added!', 'success')
        return redirect(url_for('medical_history'))
    
    # Retrieve and format history
    history = list(col_medical_history.find({"user_id": user_id}).sort("date", -1))
    
    # Format dates safely
    for item in history:
        if 'date' in item:
            if isinstance(item['date'], str):
                try:
                    item['date'] = datetime.strptime(item['date'], '%Y-%m-%d')
                except ValueError:
                    item['date'] = None
            item['formatted_date'] = item['date'].strftime('%b %d, %Y') if item['date'] else 'No date'
        else:
            item['formatted_date'] = 'No date'
    
    return render_template('medical_history.html', history=history)

# Medications
@app.route('/medications', methods=['GET', 'POST'])
@login_required
def medications():
    user_id = ObjectId(session['user']['_id'])
    
    if request.method == 'POST':
        # Create new medication
        new_med = {
            "user_id": user_id,
            "name": request.form.get('name'),
            "dosage": request.form.get('dosage'),
            "frequency": request.form.get('frequency'),
            "times": request.form.getlist('times'),
            "notes": request.form.get('notes'),
            "created_at": datetime.utcnow()
        }
        
        col_medications.insert_one(new_med)
        flash('Medication added!', 'success')
        return redirect(url_for('medications'))
    
    meds = list(col_medications.find({"user_id": user_id}).sort("created_at", -1))
    return render_template('medications.html', medications=meds)

@app.route('/medications/<med_id>/delete', methods=['POST'])
@login_required
def delete_medication(med_id):
    user_id = ObjectId(session['user']['_id'])
    col_medications.delete_one({"_id": ObjectId(med_id), "user_id": user_id})
    flash('Medication deleted', 'success')
    return redirect(url_for('medications'))

# Vaccines
# Vaccines - HTML Page
@app.route('/vaccines', methods=['GET'])
@login_required
def vaccines_page():
    user_id = ObjectId(session['user']['_id'])
    vaccines = list(col_vaccines.find({"user_id": user_id}).sort("date", -1))
    
    # Format dates and convert ObjectId to string
    formatted_vaccines = []
    for vaccine in vaccines:
        vaccine['_id'] = str(vaccine['_id'])
        
        # Ensure dates are either datetime objects or None
        if isinstance(vaccine.get('date'), str):
            try:
                vaccine['date'] = datetime.strptime(vaccine['date'], '%Y-%m-%d')
            except ValueError:
                vaccine['date'] = None
                
        if isinstance(vaccine.get('booster_due'), str):
            try:
                vaccine['booster_due'] = datetime.strptime(vaccine['booster_due'], '%Y-%m-%d')
            except ValueError:
                vaccine['booster_due'] = None
        
        formatted_vaccines.append(vaccine)
    
    return render_template('vaccines.html', vaccines=formatted_vaccines)

# Vaccines API Endpoint
@app.route('/vaccines', methods=['POST'])
@login_required
def add_or_update_vaccine():
    user_id = ObjectId(session['user']['_id'])
    try:
        # Handle file upload
        file = request.files.get('attachment')
        filename = None
        if file and file.filename != '' and allowed_file(file.filename):
            filename = secure_filename(f"{user_id}_{datetime.now().strftime('%Y%m%d%H%M%S')}_{file.filename}")
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], 'vaccines', filename)
            os.makedirs(os.path.dirname(filepath), exist_ok=True)
            file.save(filepath)
            filename = filename  # Store just the filename, not full path
        
        date_str = request.form.get('date')
        booster_due_str = request.form.get('booster_due')
        vaccine_id = request.form.get('vaccine_id')
        
        # Parse dates
        vaccine_date = datetime.strptime(date_str, '%Y-%m-%d') if date_str else None
        booster_due = datetime.strptime(booster_due_str, '%Y-%m-%d') if booster_due_str else None
        
        vaccine_data = {
            "user_id": user_id,
            "name": request.form.get('name'),
            "date": vaccine_date,
            "booster_due": booster_due,
            "attachment": filename,
            "updated_at": datetime.utcnow()
        }
        
        if vaccine_id:
            # Update existing vaccine
            result = col_vaccines.update_one(
                {"_id": ObjectId(vaccine_id), "user_id": user_id},
                {"$set": vaccine_data}
            )
            if result.modified_count == 0:
                return jsonify({"success": False, "error": "Failed to update vaccine"})
            message = "Vaccine updated successfully"
        else:
            # Create new vaccine
            vaccine_data["created_at"] = datetime.utcnow()
            col_vaccines.insert_one(vaccine_data)
            message = "Vaccine added successfully"
        
        return jsonify({
            "success": True,
            "message": message
        })
        
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 400

@app.route('/vaccines/<vaccine_id>', methods=['DELETE'])
@login_required
def delete_vaccine(vaccine_id):
    try:
        user_id = ObjectId(session['user']['_id'])
        vaccine_object_id = ObjectId(vaccine_id)
        
        # Verify vaccine exists and belongs to user
        vaccine = col_vaccines.find_one({
            "_id": vaccine_object_id,
            "user_id": user_id
        })
        
        if not vaccine:
            return jsonify({
                "success": False,
                "error": "Vaccine not found or not authorized"
            }), 404
        
        # Delete the vaccine
        result = col_vaccines.delete_one({"_id": vaccine_object_id})
        
        if result.deleted_count == 1:
            return jsonify({
                "success": True,
                "message": "Vaccine deleted successfully"
            })
        else:
            return jsonify({
                "success": False,
                "error": "Failed to delete vaccine"
            }), 500
            
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 400

# Lab Reports
@app.route('/lab-reports', methods=['GET', 'POST'])
@login_required
def lab_reports_page():
    user_id = ObjectId(session['user']['_id'])
    
    if request.method == 'POST':
        file = request.files.get('report_file')
        if not file or file.filename == '':
            flash("No file selected", "error")
            return redirect(url_for('lab_reports_page'))
        
        if not allowed_file(file.filename):
            flash("Invalid file type. Only PDF, PNG, JPG allowed", "error")
            return redirect(url_for('lab_reports_page'))
        
        filename = secure_filename(f"{user_id}_{datetime.now().strftime('%Y%m%d%H%M%S')}_{file.filename}")
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], 'lab_reports', filename)
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        file.save(filepath)
        
        # Create lab report entry
        new_report = {
            "user_id": user_id,
            "name": request.form.get('name'),
            "test_type": request.form.get('test_type'),
            "date": request.form.get('date'),
            "notes": request.form.get('notes'),
            "filename": f"lab_reports/{filename}",
            "created_at": datetime.utcnow()
        }
        
        col_lab_reports.insert_one(new_report)
        flash('Lab report uploaded!', 'success')
        return redirect(url_for('lab_reports_page'))
    
    reports = list(col_lab_reports.find({"user_id": user_id}).sort("date", -1))
    
    # Get user profile for AI suggestions
    user = users.find_one({"_id": user_id})
    suggestions = []
    
    if user.get('age') and user.get('gender'):
        # Generate AI suggestions based on profile
        prompt = f"""
        Act as a medical expert recommending health tests. Based on this profile:
        - Age: {user['age']}
        - Gender: {user['gender']}
        - Weight: {user.get('weight', 'not specified')} kg
        
        Provide 3-5 recommended medical tests with brief explanations.
        Format your response as a JSON array with 'test' and 'reason' fields.
        Example:
        {{
            "suggestions": [
                {{
                    "test": "Blood Pressure",
                    "reason": "Routine check recommended annually for adults"
                }},
                {{
                    "test": "Cholesterol",
                    "reason": "Recommended every 4-6 years for adults over 20"
                }}
            ]
        }}
        """
        
        try:
            model = genai.GenerativeModel('gemini-pro')
            response = model.generate_content(prompt)
            # Parse the JSON response from Gemini
            suggestions = json.loads(response.text).get('suggestions', [])
            
            # Store the suggestions for future reference
            col_lab_reports.update_one(
                {"user_id": user_id},
                {"$set": {"last_ai_suggestions": suggestions}},
                upsert=True
            )
        except Exception as e:
            print(f"Error getting AI suggestions: {e}")
            # Fallback to stored suggestions if available
            last_report = col_lab_reports.find_one(
                {"user_id": user_id},
                sort=[("created_at", -1)]
            )
            if last_report and 'last_ai_suggestions' in last_report:
                suggestions = last_report['last_ai_suggestions']
    
    return render_template('lab_reports.html', 
                         reports=reports, 
                         suggestions=suggestions)

# Emergency Notes
@app.route('/emergency', methods=['GET', 'POST'])
@login_required
def emergency_notes_page():
    user_id = ObjectId(session['user']['_id'])
    notes = col_emergency_notes.find_one({"user_id": user_id})
    
    if request.method == 'POST':
        # Handle file uploads
        files = request.files.getlist('emergency_files')
        filepaths = []
        
        for file in files:
            if file and file.filename != '' and allowed_file(file.filename):
                filename = secure_filename(f"{user_id}_{datetime.now().strftime('%Y%m%d%H%M%S')}_{file.filename}")
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], 'emergency', filename)
                os.makedirs(os.path.dirname(filepath), exist_ok=True)
                file.save(filepath)
                filepaths.append(f"emergency/{filename}")
        
        # Update or create emergency notes
        emergency_data = {
            "user_id": user_id,
            "blood_type": request.form.get('blood_type'),
            "allergies": request.form.get('allergies'),
            "medical_conditions": request.form.get('medical_conditions'),
            "emergency_contacts": request.form.get('emergency_contacts'),
            "files": filepaths,
            "updated_at": datetime.utcnow()
        }
        
        if notes:
            col_emergency_notes.update_one(
                {"_id": notes['_id']},
                {"$set": emergency_data}
            )
        else:
            col_emergency_notes.insert_one(emergency_data)
        
        flash('Emergency notes updated!', 'success')
        return redirect(url_for('emergency_notes_page'))
    
    family = list(col_family_members.find({"user_id": user_id}))
    return render_template('emergency.html', notes=notes, family=family)

# Family Access
@app.route('/family-access/add', methods=['POST'])
@login_required
def add_family_member():
    user_id = ObjectId(session['user']['_id'])
    email = request.form.get('email')
    
    # Check if email exists
    family_user = users.find_one({"email": email})
    if not family_user:
        flash("No user found with that email", "error")
        return redirect(url_for('emergency_notes_page'))
    
    # Check if already added
    existing = col_family_members.find_one({
        "user_id": user_id,
        "family_user_id": family_user['_id']
    })
    if existing:
        flash("This family member is already added", "error")
        return redirect(url_for('emergency_notes_page'))
    
    # Add family member
    col_family_members.insert_one({
        "user_id": user_id,
        "family_user_id": family_user['_id'],
        "name": family_user.get('name'),
        "email": family_user.get('email'),
        "relation": request.form.get('relation'),
        "access_level": "view_emergency",
        "created_at": datetime.utcnow()
    })
    
    flash("Family member added with emergency notes access", "success")
    return redirect(url_for('emergency_notes_page'))

@app.route('/family-access/remove/<member_id>', methods=['POST'])
@login_required
def remove_family_member(member_id):
    user_id = ObjectId(session['user']['_id'])
    col_family_members.delete_one({
        "_id": ObjectId(member_id),
        "user_id": user_id
    })
    flash("Family member access removed", "success")
    return redirect(url_for('emergency_notes_page'))

# PDF Exports
@app.route('/export/health-summary')
@login_required
def export_health_summary():
    user_id = ObjectId(session['user']['_id'])
    pdf_buffer = generate_pdf_export(user_id)
    
    return send_file(
        pdf_buffer,
        as_attachment=True,
        download_name=f"kobatela_health_summary_{datetime.now().strftime('%Y%m%d')}.pdf",
        mimetype='application/pdf'
    )

@app.route('/export/medications')
@login_required
def export_medications():
    user_id = ObjectId(session['user']['_id'])
    meds = list(col_medications.find({"user_id": user_id}))
    
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter)
    styles = getSampleStyleSheet()
    story = []
    
    story.append(Paragraph("Medication List", styles['Title']))
    story.append(Spacer(1, 12))
    
    for med in meds:
        story.append(Paragraph(f"- {med['name']} ({med['dosage']})", styles['Normal']))
        story.append(Paragraph(f"  Frequency: {med['frequency']}", styles['Normal']))
        if med.get('times'):
            story.append(Paragraph(f"  Times: {', '.join(med['times'])}", styles['Normal']))
        story.append(Spacer(1, 8))
    
    doc.build(story)
    buffer.seek(0)
    return send_file(
        buffer,
        as_attachment=True,
        download_name=f"medication_list_{datetime.now().strftime('%Y%m%d')}.pdf",
        mimetype='application/pdf'
    )

# API Endpoints
@app.route('/api/set-reminder', methods=['POST'])
@login_required
def set_reminder():
    user_id = ObjectId(session['user']['_id'])
    data = request.get_json()
    
    reminder = {
        "user_id": user_id,
        "type": data.get('type'),
        "item_id": ObjectId(data.get('item_id')),
        "title": data.get('title'),
        "due_date": data.get('due_date'),
        "notes": data.get('notes'),
        "created_at": datetime.utcnow()
    }
    
    col_reminders.insert_one(reminder)
    return jsonify({"success": True, "message": "Reminder set"})

@app.route('/migrate-dates')
@login_required
def migrate_dates():
    if not session.get('user', {}).get('role') == 'admin':
        abort(403)
    
    count = 0
    for item in col_medical_history.find({"date": {"$type": "string"}}):
        try:
            new_date = datetime.strptime(item['date'], '%Y-%m-%d')
            col_medical_history.update_one(
                {"_id": item['_id']},
                {"$set": {"date": new_date}}
            )
            count += 1
        except Exception as e:
            print(f"Failed to update {item['_id']}: {str(e)}")
    
    return f"Updated {count} records", 200

@app.route('/migrate-vaccine-dates')
@login_required
def migrate_vaccine_dates():
    if not session.get('user', {}).get('role') == 'admin':
        abort(403)
    
    count = 0
    for vaccine in col_vaccines.find({"$or": [{"date": {"$type": "string"}}, {"booster_due": {"$type": "string"}}]}):
        updates = {}
        if isinstance(vaccine.get('date'), str):
            try:
                updates['date'] = datetime.strptime(vaccine['date'], '%Y-%m-%d')
            except ValueError:
                updates['date'] = None
        
        if isinstance(vaccine.get('booster_due'), str):
            try:
                updates['booster_due'] = datetime.strptime(vaccine['booster_due'], '%Y-%m-%d')
            except ValueError:
                updates['booster_due'] = None
        
        if updates:
            col_vaccines.update_one({"_id": vaccine["_id"]}, {"$set": updates})
            count += 1
    
    return f"Successfully migrated {count} vaccine records", 200

if __name__ == '__main__':
    app.run(debug=True)