from sqlalchemy.orm import Session
from utils import compute_risk_ml
import models, schemas

# Create patient
def create_patient(db: Session, patient: schemas.PatientCreate):
    db_patient = models.Patient(name=patient.name, age=patient.age)
    db.add(db_patient)
    db.commit()
    db.refresh(db_patient)
    return db_patient

# Get patient by ID
def get_patient(db: Session, patient_id: int):
    return db.query(models.Patient).filter(models.Patient.id == patient_id).first()

# Get patient by name
def get_patient_by_name(db: Session, name: str):
    return db.query(models.Patient).filter(models.Patient.name == name).first()

# List all patients
def get_patients(db: Session, skip: int = 0, limit: int = 10):
    return db.query(models.Patient).offset(skip).limit(limit).all()

# Add a health record
def create_health_record(db: Session, record: schemas.HealthRecordCreate, patient_id: int):
    # Check if patient exists
    patient = db.query(models.Patient).filter(models.Patient.id == patient_id).first()
    if not patient:
        return None   #Important: para ma-handle later sa API kung wala yung patient

    # Compute risk using ML model (with fallback)
    status = compute_risk_ml(record.heart_rate, record.spo2, patient.age)


    db_record = models.HealthRecord(
        patient_id=patient_id,
        heart_rate=record.heart_rate,
        spo2=record.spo2,
        status=status
    )
    db.add(db_record)
    db.commit()
    db.refresh(db_record)
    return db_record

# Get health records by patient ID
def get_health_records(db: Session, patient_id: int):
    return db.query(models.HealthRecord).filter(models.HealthRecord.patient_id == patient_id).all()

# Delete record
def delete_record(db: Session, record_id: int):
    record = db.query(models.HealthRecord).filter(models.HealthRecord.id == record_id).first()
    if record:
        db.delete(record)
        db.commit()
        return True
    return False

def create_sensor_reading(db: Session, reading: SensorReadingCreate):
    new_reading = models.SensorReading(**reading.dict())
    db.add(new_reading)
    db.commit()
    db.refresh(new_reading)
    return new_reading