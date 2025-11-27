import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import LabelEncoder
import joblib

# Load dataset
data = pd.read_csv("health_records.csv")

# Encode status labels to numbers
le = LabelEncoder()
data['status_encoded'] = le.fit_transform(data['status'])

# Features & target
X = data[['heart_rate', 'spo2', 'age']]
y = data['status_encoded']

# Train model
model = LogisticRegression(max_iter=200)
model.fit(X, y)

# Save model & encoder
joblib.dump(model, 'risk_model.pkl')
joblib.dump(le, 'label_encoder.pkl')

print("Model and label encoder saved!")
