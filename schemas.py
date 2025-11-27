from pydantic import BaseModel
from typing import List, Optional, Generic, TypeVar
from pydantic.generics import GenericModel
import datetime

T = TypeVar("T")

# Standard response wrapper
class StandardResponse(GenericModel, Generic[T]):
    success: bool
    data: Optional[T] = None
    message: Optional[str] = None
    error: Optional[str | list] = None

# ==== Health Record ====
class HealthRecordBase(BaseModel):
    user_id: int
    reading_id: int

class HealthRecordCreate(HealthRecordBase):
    pass

class HealthRecord(HealthRecordBase):
    id: int
    record_date: datetime.datetime

    class Config:
        orm_mode = True

# ==== Patient ====
class PatientBase(BaseModel):
    fullname: str  # Matches DB (used as name)
    age: int

class PatientCreate(PatientBase):
    pass

class Patient(PatientBase):
    id: int
    records: List[HealthRecord] = []

    class Config:
        orm_mode = True

# ==== User / Auth ====
class UserCreate(BaseModel):
    username: str
    password: str
    role: str = "patient"  # Matches DB
    full_name: str  # Matches DB
    age: int  # Matches DB
    
class UserOut(BaseModel):
    id: int
    username: str
    role: str  # Matches DB
    full_name: str  # Matches DB
    age: int  # Matches DB

    class Config:
        orm_mode = True

class UserLogin(BaseModel):
    username: str
    password: str

class LoginRequest(BaseModel):
    username: str
    password: str

class LiveHealthData(BaseModel):
    heart_rate: int
    spo2: int
    patient_id: int

class SensorReadingCreate(BaseModel):
    user_id: int
    spo2: float  # Matches DB
    heart_rate: float  # Matches DB
    ir: int
    red: int

class SensorReadingOut(SensorReadingCreate):
    id: int
    timestamp: datetime.datetime

    class Config:
        orm_mode = True
