from flask import Flask, request, jsonify
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_jwt_extended.exceptions import NoAuthorizationError
from flask_cors import CORS
import bcrypt
import mysql.connector
from datetime import datetime
import os
from openai import OpenAI

app = Flask(__name__)

# ✅ CORS Configuration - Allow all origins
CORS(app, 
     resources={r"/*": {"origins": "*"}}, 
     allow_headers=["Content-Type", "Authorization"],
     methods=["GET", "POST", "OPTIONS"])

# ✅ JWT Configuration - Use environment variable in production
app.config["JWT_SECRET_KEY"] = os.getenv("JWT_SECRET_KEY", "super-secret-key-change-in-production")
jwt = JWTManager(app)

# ✅ OpenAI Configuration - Use environment variable
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
if not OPENAI_API_KEY:
    print("⚠️ WARNING: OPENAI_API_KEY not set!")
client = OpenAI(api_key=OPENAI_API_KEY) if OPENAI_API_KEY else None

# ✅ Database Connection - Use environment variables for production
def get_db_connection():
    try:
        db_config = {
    "host": os.getenv("DB_HOST", "localhost"),
    "user": os.getenv("DB_USER", "root"),
    "password": os.getenv("DB_PASSWORD", ""),
    "database": os.getenv("DB_NAME", "railway"),
    "port": int(os.getenv("DB_PORT", 3306)),
    "connect_timeout": 10
}


        
        # Add SSL for cloud databases if needed
        db_ssl = os.getenv("DB_SSL")
        if db_ssl:
            db_config["ssl_disabled"] = False
            
        connection = mysql.connector.connect(**db_config)
        return connection
    except mysql.connector.Error as err:
        print(f"❌ Database connection error: {err}")
        raise

# ============================================
# AUTHENTICATION ROUTES
# ============================================

@app.route("/register", methods=["POST"])
def register():
    """Register a new user account"""
    try:
        data = request.json
        
        # Validate required fields
        required_fields = ["fullname", "age", "email", "password"]
        for field in required_fields:
            if field not in data:
                return jsonify({"error": f"Missing required field: {field}"}), 400
        
        # Hash password
        hashed = bcrypt.hashpw(data["password"].encode(), bcrypt.gensalt())
        
        db = get_db_connection()
        cursor = db.cursor(dictionary=True)
        
        # Check if email already exists
        cursor.execute("SELECT id FROM accounts WHERE email = %s", (data["email"],))
        if cursor.fetchone():
            cursor.close()
            db.close()
            return jsonify({"error": "Email already registered"}), 400
        
        # Insert new user
        cursor.execute(
            "INSERT INTO accounts (fullname, age, email, password) VALUES (%s, %s, %s, %s)",
            (data["fullname"], data["age"], data["email"], hashed)
        )
        db.commit()
        user_id = cursor.lastrowid
        
        cursor.close()
        db.close()
        
        return jsonify({
            "message": "User registered successfully",
            "user_id": user_id
        }), 201
        
    except Exception as e:
        print(f"❌ Registration error: {e}")
        return jsonify({"error": "Registration failed"}), 500

@app.route("/login", methods=["POST"])
def login():
    """User login - returns access token"""
    try:
        data = request.json
        
        if not data.get("email") or not data.get("password"):
            return jsonify({"error": "Email and password required"}), 400
        
        db = get_db_connection()
        cursor = db.cursor(dictionary=True)
        
        cursor.execute("SELECT * FROM accounts WHERE email = %s", (data["email"],))
        user = cursor.fetchone()
        
        cursor.close()
        db.close()
        
        if not user:
            return jsonify({"error": "Invalid credentials"}), 401
        
        # Verify password
        if not bcrypt.checkpw(data["password"].encode(), user["password"].encode()):
            return jsonify({"error": "Invalid credentials"}), 401
        
        # Create access token
        token = create_access_token(identity=str(user["id"]))
        
        return jsonify({
            "access_token": token,
            "user_id": user["id"],
            "fullname": user["fullname"]
        }), 200
        
    except Exception as e:
        print(f"❌ Login error: {e}")
        return jsonify({"error": "Login failed"}), 500

# ============================================
# USER ROUTES
# ============================================

@app.route("/user/<int:user_id>", methods=["GET"])
@jwt_required()
def get_user(user_id):
    """Get user information"""
    try:
        current_user_id = get_jwt_identity()
        
        # Users can only access their own info
        if str(user_id) != current_user_id:
            return jsonify({"error": "Unauthorized"}), 403
        
        db = get_db_connection()
        cursor = db.cursor(dictionary=True)
        
        cursor.execute(
            "SELECT id, fullname, age, email FROM accounts WHERE id = %s",
            (user_id,)
        )
        user = cursor.fetchone()
        
        cursor.close()
        db.close()
        
        if not user:
            return jsonify({"error": "User not found"}), 404
        
        return jsonify(user), 200
        
    except Exception as e:
        print(f"❌ Get user error: {e}")
        return jsonify({"error": "Failed to fetch user"}), 500

@app.route("/user-info", methods=["GET"])
@jwt_required()
def user_info():
    """Get current user's basic information"""
    try:
        user_id = get_jwt_identity()
        
        db = get_db_connection()
        cursor = db.cursor(dictionary=True)
        
        cursor.execute("SELECT fullname, email, age FROM accounts WHERE id = %s", (user_id,))
        user = cursor.fetchone()
        
        cursor.close()
        db.close()
        
        if not user:
            return jsonify({"error": "User not found"}), 404
        
        return jsonify(user), 200
        
    except Exception as e:
        print(f"❌ User info error: {e}")
        return jsonify({"error": "Failed to fetch user info"}), 500

# ============================================
# SENSOR DATA ROUTES
# ============================================

@app.route("/sensor-readings", methods=["GET", "POST", "OPTIONS"])
def sensor_readings():
    """Receive sensor data from ESP32 (no authentication required)"""
    
    # Handle CORS preflight
    if request.method == "OPTIONS":
        response = jsonify({"message": "CORS preflight OK"})
        response.headers.add("Access-Control-Allow-Origin", "*")
        response.headers.add("Access-Control-Allow-Headers", "Content-Type")
        response.headers.add("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        return response, 200
    
    if request.method == "GET":
        return jsonify({"message": "Sensor readings endpoint active"}), 200
    
    # Handle POST
    try:
        data = request.get_json()
        print(f"✅ Received sensor data: {data}")
        
        # Validate data
        user_id = data.get("user_id", 1)
        heart_rate = data.get("heart_rate")
        spo2 = data.get("spo2")
        ir = data.get("ir")
        red = data.get("red")
        
        db = get_db_connection()
        cursor = db.cursor(dictionary=True)
        
        # Insert sensor reading
        cursor.execute(
            """INSERT INTO sensor_readings (user_id, heart_rate, spo2, ir, red, timestamp) 
               VALUES (%s, %s, %s, %s, %s, %s)""",
            (user_id, heart_rate, spo2, ir, red, datetime.now())
        )
        db.commit()
        reading_id = cursor.lastrowid
        
        cursor.close()
        db.close()
        
        response = jsonify({
            "message": "Data received and stored",
            "reading_id": reading_id,
            "timestamp": datetime.now().isoformat()
        })
        response.headers.add("Access-Control-Allow-Origin", "*")
        return response, 200
        
    except Exception as e:
        print(f"❌ Sensor reading error: {e}")
        response = jsonify({"error": str(e)})
        response.headers.add("Access-Control-Allow-Origin", "*")
        return response, 500

@app.route("/sensor", methods=["POST"])
@jwt_required()
def receive_sensor_data():
    """Receive authenticated sensor data"""
    try:
        user_id = get_jwt_identity()
        data = request.json
        
        db = get_db_connection()
        cursor = db.cursor(dictionary=True)
        
        cursor.execute(
            "INSERT INTO sensor_readings (user_id, heart_rate, spo2, timestamp) VALUES (%s, %s, %s, %s)",
            (user_id, data["heart_rate"], data["spo2"], datetime.now())
        )
        db.commit()
        
        cursor.close()
        db.close()
        
        return jsonify({"message": "Reading stored"}), 200
        
    except Exception as e:
        print(f"❌ Sensor data error: {e}")
        return jsonify({"error": "Failed to store reading"}), 500

# ============================================
# HEALTH LOGS ROUTES
# ============================================

@app.route("/healthlogs", methods=["GET"])
@jwt_required()
def get_logs():
    """Fetch user's health logs"""
    try:
        user_id = get_jwt_identity()
        
        db = get_db_connection()
        cursor = db.cursor(dictionary=True)
        
        cursor.execute(
            """SELECT id, heart_rate, spo2, ir, red, timestamp
               FROM sensor_readings
               WHERE user_id = %s
               ORDER BY timestamp DESC
               LIMIT 50""",
            (user_id,)
        )
        logs = cursor.fetchall()
        
        cursor.close()
        db.close()
        
        # Format timestamps for JSON
        for log in logs:
            if log.get("timestamp"):
                log["timestamp"] = log["timestamp"].isoformat()
        
        return jsonify(logs), 200
        
    except Exception as e:
        print(f"❌ Health logs error: {e}")
        return jsonify({"error": "Failed to fetch health logs"}), 500

# ============================================
# AI ASSISTANT ROUTE
# ============================================

@app.route("/ai-assistant", methods=["POST"])
def ai_assistant():
    """AI health assistant powered by OpenAI"""
    try:
        if not client:
            return jsonify({"error": "AI service not configured"}), 503
        
        data = request.json
        messages = data.get("messages", [])
        
        if not messages:
            return jsonify({"error": "No messages provided"}), 400
        
        # Extract user input
        user_input = ""
        for msg in messages:
            if msg.get("role") == "user":
                user_input += msg.get("content", "") + "\n"
        
        # Call OpenAI API
        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {
                    "role": "system",
                    "content": "You are a helpful health assistant specializing in heart rate monitoring and exercise recommendations for elderly users. Provide clear, concise, and supportive advice."
                },
                {
                    "role": "user",
                    "content": user_input
                }
            ],
            max_tokens=500,
            temperature=0.7
        )
        
        ai_message = response.choices[0].message.content
        
        return jsonify({
            "content": [{"text": ai_message}]
        }), 200
        
    except Exception as e:
        print(f"❌ AI Assistant error: {e}")
        return jsonify({
            "error": "AI service temporarily unavailable",
            "details": str(e)
        }), 500

# ============================================
# JWT ERROR HANDLERS
# ============================================

@jwt.unauthorized_loader
def unauthorized_response(callback):
    return jsonify({"error": "Authorization header missing"}), 401

@jwt.invalid_token_loader
def invalid_token_callback(reason):
    return jsonify({"error": "Invalid token", "details": reason}), 401

@jwt.expired_token_loader
def expired_token_callback(jwt_header, jwt_payload):
    return jsonify({"error": "Token expired"}), 401

@jwt.revoked_token_loader
def revoked_token_callback(jwt_header, jwt_payload):
    return jsonify({"error": "Token has been revoked"}), 401

@app.errorhandler(NoAuthorizationError)
def handle_auth_error(e):
    print(f"❌ Auth error: {e}")
    return jsonify({"error": str(e)}), 401

# ============================================
# HEALTH CHECK ROUTE
# ============================================

@app.route("/", methods=["GET"])
def health_check():
    """API health check"""
    return jsonify({
        "status": "healthy",
        "message": "AI Health Monitor Backend API",
        "version": "1.0.0",
        "timestamp": datetime.now().isoformat()
    }), 200

@app.route("/health", methods=["GET"])
def health():
    """Detailed health check"""
    try:
        # Test database connection
        db = get_db_connection()
        cursor = db.cursor()
        cursor.execute("SELECT 1")
        cursor.close()
        db.close()
        db_status = "connected"
    except Exception as e:
        db_status = f"error: {str(e)}"
    
    return jsonify({
        "status": "ok",
        "database": db_status,
        "ai_service": "configured" if client else "not configured",
        "timestamp": datetime.now().isoformat()
    }), 200

# ============================================
# RUN APPLICATION
# ============================================

if __name__ == "__main__":
    port = int(os.getenv("PORT", 5000))
    debug_mode = os.getenv("FLASK_DEBUG", "False").lower() == "true"
    
    print("=" * 60)
    print("🚀 Starting AI Health Monitor Backend")
    print("=" * 60)
    print(f"📡 Port: {port}")
    print(f"🔧 Debug Mode: {debug_mode}")
    print(f"🔐 JWT Secret: {'Set' if app.config['JWT_SECRET_KEY'] else 'Not Set'}")
    print(f"🤖 OpenAI: {'Configured' if client else 'Not Configured'}")
    print(f"🗄️  Database Host: {os.getenv('DB_HOST', 'localhost')}")
    print("=" * 60)
    
    app.run(host="0.0.0.0", port=port, debug=debug_mode)