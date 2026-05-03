# 🔐 Phishing URL Detection & Network Analysis System

## 📌 Project Overview

This project is a **hybrid cybersecurity system** that detects malicious activity using:

* 🔹 URL-based phishing detection (Machine Learning)
* 🔹 Network traffic analysis (PCAP-based)

It combines **static + dynamic analysis** to improve detection accuracy.

---

## 🚀 Live Demo

👉 *(Paste your Render link here after deployment)*

---

## 🧠 Features

* ✅ Detect phishing URLs using trained ML model
* ✅ REST API for predictions
* ✅ PCAP file upload support (for traffic analysis)
* ✅ Lightweight and fast backend (Flask)
* ✅ Deployment-ready system

---

## 🏗️ Architecture

```
User Input (URL / PCAP)
        ↓
Feature Extraction
        ↓
Machine Learning Models
        ↓
Prediction Output (Phishing / Legit)
```

---

## ⚙️ Tech Stack

* Python
* Flask
* Scikit-learn
* Pandas, NumPy
* Gunicorn
* Deployed on cloud

---

## 📂 Project Structure

```
project/
│── app.py
│── requirements.txt
│── url_model_4.pkl
│── features.pkl
│── README.md
```

---

## 🔧 Installation (Local Setup)

```bash
git clone https://github.com/your-username/phising-detector.git
cd phising-detector
pip install -r requirements.txt
python app.py
```

---

## 🔌 API Endpoints

### 🔹 Home

```
GET /
```

Response:

```
Project is Live 🚀
```

---

### 🔹 Predict URL

```
POST /predict-url
```

#### Request:

```json
{
  "url": "https://example.com"
}
```

#### Response:

```json
{
  "prediction": 0
}
```

---

## 🧪 Model Details

* Algorithm: Machine Learning (Scikit-learn)
* Features: 20 extracted URL features
* Accuracy: ~89.4%

---

## ⚠️ Limitations

* Live traffic capture not supported on cloud
* Network analysis works via PCAP upload or local setup

---

## 📌 Future Improvements

* Real-time traffic monitoring
* Frontend dashboard (React)
* Database logging (MongoDB)
* Browser extension

---

## 👨‍💻 Author

Harsh Vardhan

---

## ⭐ Note

This project is developed for academic and demonstration purposes.
