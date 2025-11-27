from fastapi import FastAPI, Depends, HTTPException, Security
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session
from schemas import UserLogin
import models, schemas, crud, utils
from database import SessionLocal, engine, Base
from fastapi.middleware.cors import CORSMiddleware
from models import User
from utils import verify_password, create_access_token
from schemas import UserCreate
from auth import router as auth_router
from schemas import UserCreate, UserOut
from utils import hash_password
from datetime import datetime
from database import get_db
from models import SensorReading
from pydantic import BaseModel
from schemas import SensorReadingCreate
from fastapi.responses import JSONResponse, Response
from fastapi.requests import Request
from fastapi.exceptions import RequestValidationError



# Create database tables
Base.metadata.create_all(bind=engine)

app = FastAPI()
app.include_router(auth_router)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allows all origins (e.g., http://127.0.0.1:5500). For production, restrict to specific domains.
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Dependency
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

class SensorReadingCreate(BaseModel):
    user_id: int
    heart_rate: int
    spo2: int
    ir: int
    red: int

def get_current_user(token: str = Security(oauth2_scheme)):
   payload = utils.verify_access_token(token)
   if not payload:
     raise HTTPException(status_code=401, detail="Invalid or expired token")
    return payload

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    return JSONResponse(
        status_code=422,
        content={"detail": exc.errors()},
        headers={"Access-Control-Allow-Origin": "*"}
    )

@app.get("/")
def root():
    return {"message": "Elderly Health Risk Dashboard Backend Running..."}

# Create a patient
@app.post("/patients/", response_model=schemas.Patient)
def create_patient(patient: schemas.PatientCreate, db: Session = Depends(get_db)):
    return crud.create_patient(db=db, patient=patient)

# Get patient by name
@app.get("/patients/{name}", response_model=schemas.Patient)
def read_patient(name: str, db: Session = Depends(get_db)):
    db_patient = crud.get_patient_by_name(db, name=name)
    if db_patient is None:
        raise HTTPException(status_code=404, detail="Patient not found")
    return db_patient

# Add health record for patient
@app.post("/patients/{patient_id}/records/", response_model=schemas.HealthRecord)
def create_health_record(patient_id: int, record: schemas.HealthRecordCreate, db: Session = Depends(get_db)):
    db_record = crud.create_health_record(db, record, patient_id)
    if not db_record:
        raise HTTPException(status_code=404, detail="Patient not found")
    return db_record

@app.delete("/records/{record_id}")
def delete_record(record_id: int, db: Session = Depends(get_db)):
    success = crud.delete_record(db, record_id)
    if not success:
        raise HTTPException(status_code=404, detail="Record not found")
    return {"message": "Record deleted successfully"}

# Get health history for patient
@app.get("/patients/{patient_id}/records/", response_model=list[schemas.HealthRecord])
def read_records(
    patient_id: int,
    db: Session = Depends(get_db),
    # current_user: dict = Depends(get_current_user)
):
    records = crud.get_health_records(db, patient_id)
    if not records:
        raise HTTPException(status_code=404, detail="No records found for this patient")
    return records

# Signup
@app.post("/signup", response_model=UserOut)
def signup(user: UserCreate, db: Session = Depends(get_db)):
    try:
        print("Incoming signup data:", user)

        existing = db.query(User).filter(User.username == user.username).first()
        if existing:
            raise HTTPException(status_code=400, detail="Username already exists")

        hashed = hash_password(user.password)

        new_user = User(
            username=user.username,
            hashed_password=hashed,
            role=user.role,
            full_name=user.full_name,
            age=user.age
        )
        db.add(new_user)
        db.commit()
        db.refresh(new_user)
        return new_user

    except Exception as e:
        print("❌ Signup error:", e)
        raise HTTPException(status_code=500, detail="Internal Server Error")

# Login
@app.post("/login")
def login(user: UserLogin, db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.username == user.username).first()
    if not db_user or not verify_password(user.password, db_user.hashed_password):
        raise HTTPException(status_code=400, detail="Invalid username or password")
    
    token = create_access_token({"sub": db_user.username})
    return {
        "access_token": token,
        "token_type": "bearer",
        "username": db_user.username,
        "age": db_user.age,
        "patient_id": db_user.id
    }

@app.post("/healthlogs")
def receive_health_data(data: schemas.LiveHealthData, db: Session = Depends(get_db)):
    try:
        crud.create_health_record(
            db=db,
            record=schemas.HealthRecordCreate(
                heart_rate=data.heart_rate,
                spo2=data.spo2,
                timestamp=datetime.now()
            ),
            patient_id=data.patient_id
        )
        return {"status": "received", "timestamp": datetime.now()}
    except Exception as e:
        print("❌ ESP32 data error:", e)
        raise HTTPException(status_code=500, detail="Failed to store health data")

# POST /sensor-readings (for storing sensor data) - with explicit CORS headers and error handling
@app.post("/sensor-readings")
async def receive_sensor_reading(data: SensorReadingCreate, db: Session = Depends(get_db)):
    try:
        print("📥 Incoming sensor data:", data)
        reading = SensorReading(
            user_id=data.user_id,
            heart_rate=data.heart_rate,
            spo2=data.spo2,
            ir=data.ir,
            red=data.red,
            timestamp=datetime.utcnow()
        )
        db.add(reading)
        db.commit()
        print("✅ Data stored successfully")
        return JSONResponse(
            content={"status": "stored"},
            headers={"Access-Control-Allow-Origin": "*"}
        )
    except Exception as e:
        print("❌ Database error in /sensor-readings:", str(e))
        db.rollback()  # Roll back on error
        return JSONResponse(
            content={"error": "Failed to store data", "details": str(e)},
            status_code=500,
            headers={"Access-Control-Allow-Origin": "*"}
        )

# OPTIONS /sensor-readings (explicit handler for preflight CORS requests with manual headers)
@app.options("/sensor-readings")
async def options_sensor_readings():
    response = Response()
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Methods"] = "POST, OPTIONS"
    response.headers["Access-Control-Allow-Headers"] = "*"
    return response

# GET /healthlogs (retrieve sensor readings for authenticated user)
@app.get("/healthlogs")
def get_health_logs(current_user: dict = Depends(get_current_user), db: Session = Depends(get_db)):

    readings = db.query(SensorReading).order_by(SensorReading.timestamp.desc()).all()

    result = [
        {
            "id": r.id,
            "user_id": r.user_id,
            "heart_rate": r.heart_rate,
            "spo2": r.spo2,
            "ir": r.ir,
            "red": r.red,
            "timestamp": r.timestamp.isoformat() if r.timestamp else None
        }
        for r in readings
    ]

    return result

@app.get("/user/{user_id}")
def get_user(user_id: int, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return {
        "id": user.id,
        "fullname": user.fullname,
        "age": user.age,
        "email": user.email
    }

