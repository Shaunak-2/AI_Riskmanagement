from flask import Blueprint, request, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from pymongo import MongoClient
import os
import uuid  
import jwt
import random
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from datetime import datetime, timedelta
import re


MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017")
client = MongoClient(MONGO_URI)
mongo_db = client.PassionInfotech  # Changed to your Atlas DB name
users_collection = mongo_db.users  # Now using a separate 'users' collection for authentication

# Define the auth blueprint
auth = Blueprint('auth', __name__)

# Secret key for JWT
SECRET_KEY = os.getenv("JWT_SECRET_KEY", "your-secret-key-change-in-production")

# Security and rate limiting settings from environment
OTP_EXPIRY_MINUTES = int(os.getenv("OTP_EXPIRY_MINUTES", 10))
MAX_OTP_ATTEMPTS = int(os.getenv("MAX_OTP_ATTEMPTS", 5))
RESEND_COOLDOWN_SECONDS = int(os.getenv("RESEND_COOLDOWN_SECONDS", 60))
MAX_LOGIN_ATTEMPTS = int(os.getenv("MAX_LOGIN_ATTEMPTS", 5))
LOCKOUT_DURATION_MINUTES = int(os.getenv("LOCKOUT_DURATION_MINUTES", 15))

def validate_email(email):
    """Validate email format"""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def validate_password(password):
    """Validate password strength"""
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter"
    if not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter"
    if not re.search(r'\d', password):
        return False, "Password must contain at least one number"
    return True, "Password is valid"

@auth.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    name = data.get('name', '').strip()
    email = data.get('email', '').strip().lower()
    password = data.get('password', '')

    if not name or not email or not password:
        return jsonify({"error": "All fields are required"}), 400

    # Validate email format
    if not validate_email(email):
        return jsonify({"error": "Invalid email format"}), 400

    # Validate password strength
    is_valid, message = validate_password(password)
    if not is_valid:
        return jsonify({"error": message}), 400

    if users_collection.find_one({"email": email}):
        return jsonify({"error": "Email already exists"}), 400

    hashed_password = generate_password_hash(password)
    user_id = str(uuid.uuid4())  # Generate a unique user ID
    new_user = {
        "user_id": user_id,
        "name": name,
        "email": email,
        "password": hashed_password,
        "created_at": datetime.utcnow(),
        "email_verified": False
    }
    users_collection.insert_one(new_user)

    return jsonify({
        "success": True,
        "user": {
            "id": user_id,
            "name": name,
            "email": email
        }
    })

@auth.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email', '').strip().lower()
    password = data.get('password', '')

    if not email or not password:
        return jsonify({"error": "Email and password are required"}), 400

    user = users_collection.find_one({"email": email})
    if not user or not check_password_hash(user["password"], password):
        return jsonify({"error": "Invalid email or password"}), 401

    # Generate JWT token
    token = jwt.encode(
        {"user_id": user["user_id"], "exp": datetime.utcnow() + timedelta(days=1)},
        SECRET_KEY,
        algorithm="HS256"
    )
    if isinstance(token, bytes):
        token = token.decode('utf-8')

    return jsonify({
        "success": True,
        "token": token,
        "user": {
            "id": user["user_id"],
            "name": user["name"],
            "email": user["email"]
        }
    })

def token_required(f):
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        
        if not token:
            return jsonify({'error': 'Token is missing'}), 401
            
        if token.startswith('Bearer '):
            token = token[7:]
        
        try:
            data = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
            current_user = users_collection.find_one({'user_id': data['user_id']})
        except:
            return jsonify({'error': 'Token is invalid'}), 401
            
        return f(current_user, *args, **kwargs)
    return decorated

# Enhanced helper function to send OTP email with better formatting
def send_otp_email(to_email, otp, user_name=None, purpose="login"):
    """Send OTP email with improved formatting to avoid spam filters"""
    sender_email = os.getenv("EMAIL_USER")
    sender_password = os.getenv("EMAIL_PASS")
    
    if not sender_email or not sender_password:
        print("[ERROR] Email credentials not set in environment.")
        return False
    
    try:
        # Set up sender display name
        from_name = "Airisk Security"
        display_sender = f"{from_name} <{sender_email}>"
        
        # Prepare email content with better formatting
        name = user_name or "User"
        action = "log in" if purpose == "login" else "reset your password"
        
        subject = f"Your Airisk verification code (OTP): {otp}"
        
        # Enhanced plain text version
        text = f"""Hi {name},

We received a request to {action} to your Airisk account.

Your verification code is: {otp}

This code will expire in 10 minutes for your security.

If you didn't request this verification, please ignore this email and your account will remain secure.

For your security:
• Never share this code with anyone
• This code is only valid for 10 minutes
• Only use this code on the official Airisk website

Thanks for using Airisk!
The Airisk Security Team

---
Need help? Contact us at {sender_email}
This is an automated security message — please do not reply to this email.

© 2025 Airisk. All rights reserved.
"""

        # Enhanced HTML version with better styling
        html = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Airisk Verification Code</title>
</head>
<body style="font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; line-height: 1.6; margin: 0; padding: 0; background-color: #f8f9fa;">
    <div style="max-width: 600px; margin: 0 auto; background-color: #ffffff; border-radius: 10px; overflow: hidden; box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);">
        
        <!-- Header -->
        <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 30px 20px; text-align: center;">
            <h1 style="color: #ffffff; margin: 0; font-size: 28px; font-weight: 600;">Airisk</h1>
            <p style="color: #e8e8ff; margin: 5px 0 0 0; font-size: 14px;">Security Verification</p>
        </div>
        
        <!-- Content -->
        <div style="padding: 40px 30px;">
            <h2 style="color: #2c3e50; margin: 0 0 20px 0; font-size: 24px;">Hi {name}!</h2>
            
            <p style="color: #555555; font-size: 16px; margin-bottom: 25px;">
                We received a request to <strong>{action}</strong> to your Airisk account.
            </p>
            
            <!-- OTP Box -->
            <div style="background-color: #f8f9ff; border: 2px dashed #667eea; border-radius: 8px; padding: 25px; text-align: center; margin: 30px 0;">
                <p style="color: #666; margin: 0 0 10px 0; font-size: 14px;">Your verification code is:</p>
                <div style="font-size: 32px; font-weight: bold; color: #667eea; letter-spacing: 3px; font-family: 'Courier New', monospace;">
                    {otp}
                </div>
                <p style="color: #999; margin: 10px 0 0 0; font-size: 12px;">Valid for 10 minutes</p>
            </div>
            
            <div style="background-color: #fff3cd; border-left: 4px solid #ffc107; padding: 15px; margin: 25px 0; border-radius: 4px;">
                <p style="margin: 0; color: #856404; font-size: 14px;">
                    <strong>Security Tips:</strong><br>
                    • Never share this code with anyone<br>
                    • Only use this code on the official Airisk website<br>
                    • This code expires in 10 minutes
                </p>
            </div>
            
            <p style="color: #555555; font-size: 14px; margin-top: 30px;">
                If you didn't request this verification, please ignore this email and your account will remain secure.
            </p>
            
            <p style="color: #555555; font-size: 16px; margin-top: 30px;">
                Thanks for using Airisk!<br>
                <strong>The Airisk Security Team</strong>
            </p>
        </div>
        
        <!-- Footer -->
        <div style="background-color: #f8f9fa; padding: 20px 30px; border-top: 1px solid #dee2e6;">
            <p style="margin: 0; font-size: 12px; color: #6c757d; text-align: center;">
                Need help? Contact us at <a href="mailto:{sender_email}" style="color: #667eea; text-decoration: none;">{sender_email}</a><br>
                This is an automated security message — please do not reply to this email.
            </p>
            <p style="margin: 15px 0 0 0; font-size: 11px; color: #adb5bd; text-align: center;">
                © 2025 Airisk. All rights reserved.
            </p>
        </div>
        
    </div>
</body>
</html>
"""

        # Build message with proper headers
        msg = MIMEMultipart('alternative')
        msg['Subject'] = subject
        msg['From'] = display_sender
        msg['To'] = to_email
        msg['Reply-To'] = sender_email
        
        # Add custom headers to improve deliverability
        msg['X-Priority'] = '3'
        msg['X-Mailer'] = 'Airisk Security System'
        msg['X-MSMail-Priority'] = 'Normal'
        
        # Attach both text and HTML versions
        text_part = MIMEText(text, 'plain', 'utf-8')
        html_part = MIMEText(html, 'html', 'utf-8')
        
        msg.attach(text_part)
        msg.attach(html_part)
        
        # Send email with improved error handling
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as server:
            server.login(sender_email, sender_password)
            server.sendmail(sender_email, [to_email], msg.as_string())
        
        print(f"[SUCCESS] OTP email sent successfully to {to_email}")
        return True
        
    except smtplib.SMTPAuthenticationError:
        print(f"[ERROR] SMTP Authentication failed. Check email credentials.")
        return False
    except smtplib.SMTPRecipientsRefused:
        print(f"[ERROR] Recipient email address rejected: {to_email}")
        return False
    except smtplib.SMTPException as e:
        print(f"[ERROR] SMTP error occurred: {e}")
        return False
    except Exception as e:
        print(f"[ERROR] Failed to send email: {e}")
        return False

@auth.route('/forgot-password', methods=['POST'])
def forgot_password():
    data = request.get_json()
    email = data.get('email', '').strip().lower()
    
    if not email:
        return jsonify({"error": "Email is required"}), 400
    
    # Validate email format
    if not validate_email(email):
        return jsonify({"error": "Invalid email format"}), 400
    
    user = users_collection.find_one({"email": email})
    if not user:
        # Don't reveal if email exists or not for security
        return jsonify({"success": True, "message": "If this email is registered, you will receive an OTP."}), 200
    
    # Generate secure OTP
    otp = str(random.randint(100000, 999999))
    expiry = datetime.utcnow() + timedelta(minutes=OTP_EXPIRY_MINUTES)
    
    # Store OTP with additional security measures
    users_collection.update_one(
        {"email": email}, 
        {
            "$set": {
                "reset_otp": otp, 
                "otp_expiry": expiry,
                "otp_attempts": 0,  # Track failed attempts
                "otp_generated_at": datetime.utcnow()
            }
        }
    )
    
    user_name = user.get('name', 'User')
    if send_otp_email(email, otp, user_name, "password_reset"):
        return jsonify({"success": True, "message": "OTP sent to your email address."})
    else:
        return jsonify({"error": "Failed to send OTP email. Please try again later."}), 500

@auth.route('/reset-password', methods=['POST'])
def reset_password():
    data = request.get_json()
    email = data.get('email', '').strip().lower()
    otp = data.get('otp', '').strip()
    new_password = data.get('new_password', '')
    
    if not email or not otp or not new_password:
        return jsonify({"error": "All fields are required"}), 400
    
    # Validate email format
    if not validate_email(email):
        return jsonify({"error": "Invalid email format"}), 400
    
    # Validate new password strength
    is_valid, message = validate_password(new_password)
    if not is_valid:
        return jsonify({"error": message}), 400
    
    user = users_collection.find_one({"email": email})
    if not user:
        return jsonify({"error": "Invalid request"}), 400
    
    # Check for too many failed attempts
    if user.get('otp_attempts', 0) >= MAX_OTP_ATTEMPTS:
        return jsonify({"error": "Too many failed attempts. Please request a new OTP."}), 429
    
    # Verify OTP
    if user.get('reset_otp') != otp:
        # Increment failed attempts
        users_collection.update_one(
            {"email": email}, 
            {"$inc": {"otp_attempts": 1}}
        )
        return jsonify({"error": "Invalid OTP"}), 400
    
    # Check if OTP has expired
    if datetime.utcnow() > user.get('otp_expiry', datetime.utcnow()):
        return jsonify({"error": "OTP has expired. Please request a new one."}), 400
    
    # Reset password and clean up OTP data
    hashed_password = generate_password_hash(new_password)
    users_collection.update_one(
        {"email": email}, 
        {
            "$set": {"password": hashed_password, "password_updated_at": datetime.utcnow()}, 
            "$unset": {
                "reset_otp": "", 
                "otp_expiry": "", 
                "otp_attempts": "",
                "otp_generated_at": ""
            }
        }
    )
    
    print(f"[SUCCESS] Password reset successful for user: {email}")
    return jsonify({"success": True, "message": "Password reset successful. You can now log in with your new password."})

# Optional: Add endpoint to resend OTP
@auth.route('/resend-otp', methods=['POST'])
def resend_otp():
    data = request.get_json()
    email = data.get('email', '').strip().lower()
    
    if not email:
        return jsonify({"error": "Email is required"}), 400
    
    if not validate_email(email):
        return jsonify({"error": "Invalid email format"}), 400
    
    user = users_collection.find_one({"email": email})
    if not user:
        return jsonify({"success": True, "message": "If this email is registered, you will receive an OTP."}), 200
    
    # Check if last OTP was sent less than 1 minute ago (rate limiting)
    last_otp_time = user.get('otp_generated_at')
    if last_otp_time and datetime.utcnow() - last_otp_time < timedelta(seconds=RESEND_COOLDOWN_SECONDS):
        return jsonify({"error": "Please wait before requesting another OTP"}), 429
    
    # Generate new OTP
    otp = str(random.randint(100000, 999999))
    expiry = datetime.utcnow() + timedelta(minutes=OTP_EXPIRY_MINUTES)
    
    users_collection.update_one(
        {"email": email}, 
        {
            "$set": {
                "reset_otp": otp, 
                "otp_expiry": expiry,
                "otp_attempts": 0,
                "otp_generated_at": datetime.utcnow()
            }
        }
    )
    
    user_name = user.get('name', 'User')
    if send_otp_email(email, otp, user_name, "password_reset"):
        return jsonify({"success": True, "message": "New OTP sent to your email address."})
    else:
        return jsonify({"error": "Failed to send OTP email. Please try again later."}), 500