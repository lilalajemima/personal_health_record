# Kobatela 
## Overview
Kobatela is a  personal health management web application that allows users to track their medical history, medications, lab reports, vaccinations, and emergency information in one secure place. The system provides tools for managing health records, setting reminders, and generating printable reports.

## Features 
- User Authentication: Secure signup/login with password hashing
Medical History Tracking: Record and manage past medical conditions, procedures, and events
- Medication Management: Track current medications with dosages, frequencies, and notes
- Vaccination Records: Maintain immunization history with booster due dates
- Lab Reports: Store and organize test results and medical documents
- Emergency Information: Critical health details for emergency situations
- PDF Export: Generate printable reports for doctors or emergency use
- Reminders: Set alerts for medications, appointments, and boosters
- AI Recommendations: Get personalized health screening suggestions based on profile

## Technology Stack 
- Backend
 Python/Flask
 MongoDB (with PyMongo) for database
 Passlib for secure password hashing
 ReportLab for PDF generation
 Google Gemini API for AI recommendations

- Frontend
 HTML, CSS, JavaScript
 Flask templating (Jinja2)
 Bootstrap for responsive design
 AJAX for asynchronous requests


- Development Tools
 VS Code
 Python virtual environment
 MongoDB Atlas and  Local MongoDB
 dotenv for environment variables

## Setup Instructions
### Prerequisites
* Python 3.x installed
* MongoDB (either Atlas cloud service or Compass for local installation)
* VS Code  or other code editor

### Local Installation 
1. Clone the repository and  go to the root directory for this project with: 
 git clone https://github.com/lilalajemima/personal_health_record.git  then cd kobatela

2. Create and activate a virtual environment with: 
 python -m venv venv then source venv/bin/activate

3. Install dependencies: 
 pip install -r requirements.txt

4. Create a .env file in the root directory( whereby the app.py is ) with your configuration 
 SECRET_KEY=your flask secret key
 MONGO_URI= your connection string 
 GEMINI_API_KEY=your google gemini api key

5. Run the application to get your web link with:
 python app.py

## Common errors you might encounter from experience: 
1. MongoDB Connection Issues: Verify connection string in .env file, If  you can't connect to your cloud database, running local MongoDB is easier with less requirements like SSL Certification. This will help you build your flask backend routes as you debug your cloud database.

2. File Upload Problems: Verify that the  UPLOAD_FOLDER exists and has write permissions and Check file size and allowed extensions

3. Environment Variables Not Loading: Ensure that the  .env file is in the root directory and restart Flask after making changes to .env

4. AI Recommendation Failures: Verify Gemini API key is valid Check user profile has age and gender filled. Refer to Google's documentation concerning Gemini Implementation

## Challenges
- The AI-powered health recommendation feature is currently experiencing technical issues due to limitations with the Google Gemini API's free tier. While the feature remains accessible in the interface, it frequently returns errors or incomplete suggestions because of strict daily request quotas and response size restrictions.

## User guide and Deployed Solution 
1. Registration: Create an account with your email and basic information

2. Dashboard: Overview of medications, upcoming reminders, and recent activity

3. Medical History: Add past conditions, surgeries, or hospitalizations

4. Medications: Track current prescriptions with dosage instructions

5. Lab Reports: Upload and organize test results

6. Vaccinations: Maintain immunization records

7. Emergency Info: Store critical health information for emergencies

8. PDF Export: Generate printable versions of your health records

- https://kobatelaa.onrender.com/

## Contributor
Lilala Runiga Jemima 