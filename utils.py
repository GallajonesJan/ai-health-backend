import bcrypt, joblib
from datetime import datetime, timedelta
from jose import jwt, JWTError
from passlib.context import CryptContext

SECRET_KEY = "supersecretkey123"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
# Load ML model and encoder
ml_model = joblib.load("risk_model.pkl")
ml_encoder = joblib.load("label_encoder.pkl")

def compute_risk_ml(heart_rate: int, spo2: int, age: int) -> str:
    """Use trained ML model for risk classification."""
    try:
        X = [[heart_rate, spo2, age]]
        pred_encoded = ml_model.predict(X)[0]
        return ml_encoder.inverse_transform([pred_encoded])[0]
    except Exception:
        # fallback to rule-based if ML fails
        return classify_risk(heart_rate, spo2)

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def verify_access_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload  # contains user info (like username, role)
    except JWTError:
        return None

def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def classify_risk(heart_rate: int, spo2: int) -> str:
    """Fallback rule-based risk classification."""
    if spo2 < 90 or heart_rate > 120:
        return "At Risk"
    elif 90 <= spo2 <= 94 or 100 < heart_rate <= 120:
        return "Slightly Normal"
    else:
        return "Normal"
