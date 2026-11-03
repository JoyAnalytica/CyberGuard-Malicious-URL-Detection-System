
# ================================================
# Phishing URL Classification using FastAPI
# ================================================

# ================================================
# 1. Import Libraries
# ================================================

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from pydantic import BaseModel

from urllib.parse import urlparse, parse_qsl

import ipaddress
import re
import joblib
import pandas as pd
import numpy as np
import os


# ================================================
# 2. Initialize FastAPI
# ================================================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

PROJECT_ROOT = os.path.dirname(BASE_DIR)

app = FastAPI(
    title="Phishing URL Classification API",
    description="Multi-Class URL Classification using Machine Learning",
    version="1.0.0"
)


# ================================================
# 3. Static Files and HTML Templates
# ================================================

# Static Files
app.mount(
    "/static",
    StaticFiles(
        directory=os.path.join(PROJECT_ROOT, "static")
    ),
    name="static"
)

# HTML Templates
templates = Jinja2Templates(
    directory=os.path.join(PROJECT_ROOT, "templates")
)


# ================================================
# 4. Frontend Route
# ================================================

@app.get("/ui")
def home_page(request: Request):

    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={"request": request}
    )


# ================================================
# 5. CORS Configuration
# ================================================

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"]
)


# ================================================
# 6. Load Trained Model
# ================================================

MODEL_PATH = os.path.join(
    BASE_DIR,
    "model (1).pkl"
)

if not os.path.exists(MODEL_PATH):
    raise FileNotFoundError(
        f"Model file not found: {MODEL_PATH}"
    )

model = joblib.load(MODEL_PATH)

print("Model loaded successfully!")


# ================================================
# 7. Class Mapping
# ================================================

CLASS_MAPPING = {
    0: "Benign",
    1: "Defacement",
    2: "Malware",
    3: "Phishing"
}


# ================================================
# 8. Extract URL Features
# ================================================

def extract_features(url):

    url = str(url).strip()
    lower_url = url.lower()

    # URL Parsing
    try:

        normalized_url = (
            url if "://" in url else "//" + url
        )

        parsed = urlparse(normalized_url)

        hostname = parsed.hostname or ""
        path = parsed.path or ""
        query = parsed.query or ""

        # Port Validation
        try:

            port = parsed.port
            has_port = int(port is not None)

        except ValueError:

            has_port = 0

    except ValueError:

        hostname = ""
        path = ""
        query = ""
        has_port = 0

    # IP Address Checking
    try:

        ipaddress.ip_address(hostname)
        has_ip = 1

    except ValueError:

        has_ip = 0

    # Subdomain Count
    parts = hostname.split(".") if hostname else []

    num_subdomains = max(
        0,
        len(parts) - 2
    )

    # Query Parameters
    try:

        num_params = len(
            parse_qsl(
                query,
                keep_blank_values=True
            )
        )

    except ValueError:

        num_params = 0

    # Feature Dictionary
    features = {

        # Basic Features
        "url_length": len(url),
        "num_digits": sum(c.isdigit() for c in url),
        "num_letters": sum(c.isalpha() for c in url),

        # Special Characters
        "num_dots": url.count("."),
        "num_hyphens": url.count("-"),
        "num_underscores": url.count("_"),
        "num_at": url.count("@"),
        "num_slashes": url.count("/"),
        "num_percent": url.count("%"),

        "num_special_chars": len(
            re.findall(r"[^a-zA-Z0-9]", url)
        ),

        # URL Structure
        "has_https": int(lower_url.startswith("https://")),
        "has_http": int(lower_url.startswith("http://")),
        "hostname_length": len(hostname),
        "num_subdomains": num_subdomains,
        "path_length": len(path),
        "query_length": len(query),
        "num_params": num_params,
        "has_ip": has_ip,
        "has_port": has_port,

        # Keyword Indicators
        "has_login": int("login" in lower_url),
        "has_verify": int("verify" in lower_url),
        "has_account": int("account" in lower_url),
        "has_secure": int("secure" in lower_url),
        "has_password": int("password" in lower_url)

    }

    return features


# ================================================
# 9. Input Schema
# ================================================

class URLInput(BaseModel):

    url: str


# ================================================
# 10. Home Route
# ================================================

@app.get("/")
def home():

    return {
        "message": "Phishing URL Classification API",
        "status": "Running"
    }


# ================================================
# 11. Prediction API
# ================================================

@app.post("/predict")
def predict(data: URLInput):

    try:

        # Get URL
        url = data.url.strip()

        if not url:

            raise HTTPException(
                status_code=400,
                detail="URL cannot be empty"
            )

        # Extract Features
        features = extract_features(url)

        # Convert Features into DataFrame
        input_data = pd.DataFrame([features])

        # Match Training Feature Order
        if hasattr(model, "feature_names_in_"):

            expected_features = list(
                model.feature_names_in_
            )

            missing_features = [
                col for col in expected_features
                if col not in input_data.columns
            ]

            if missing_features:

                raise HTTPException(
                    status_code=400,
                    detail=f"Missing features: {missing_features}"
                )

            input_data = input_data[expected_features]

        elif hasattr(model, "n_features_in_"):

            if input_data.shape[1] != model.n_features_in_:

                raise HTTPException(
                    status_code=400,
                    detail="Feature count mismatch"
                )

        # Model Prediction
        prediction = model.predict(input_data)[0]

        prediction = int(prediction)

        # Predicted Class
        predicted_class = CLASS_MAPPING.get(
            prediction,
            "Unknown"
        )

        # Result
        result = {

            "url": url,

            "prediction": prediction,

            "class": predicted_class

        }

        # Prediction Probability
        if hasattr(model, "predict_proba"):

            probabilities = model.predict_proba(
                input_data
            )[0]

            probability_result = {}

            for cls, prob in zip(
                model.classes_,
                probabilities
            ):

                class_id = int(cls)

                class_name = CLASS_MAPPING.get(
                    class_id,
                    str(class_id)
                )

                probability_result[class_name] = round(
                    float(prob) * 100,
                    2
                )

            result["probabilities"] = probability_result

            result["confidence"] = round(
                float(np.max(probabilities)) * 100,
                2
            )

        # Final API Response
        return {

            "status": "success",

            "result": result

        }

    except HTTPException:

        raise

    except Exception as e:

        raise HTTPException(
            status_code=500,
            detail=str(e)
        )


# ================================================
# 12. Health Check
# ================================================

@app.get("/health")
def health_check():

    return {
        "status": "healthy",
        "model_loaded": model is not None
    }
