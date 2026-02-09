# Network Intrusion Detection System (NIDS)

A machine learning-based Network Intrusion Detection System that monitors network traffic in real-time, classifies connections as normal or malicious, and alerts administrators through a web dashboard and email notifications.

**Final Year Project** — University of Botswana, Department of Computer Science
**Supervisor:** Dr T Mapoka

## System Architecture

```
[Network Traffic]
       |
       v
[Packet Capture Module - Python/Scapy]
       |
       v
[Feature Extractor - Python]
       |
       v
[ML Classifier - Python/scikit-learn]
       |
       v
[Backend API - Node.js/Express on Vercel Serverless Functions]
       |
       ├──> [Database - Supabase/PostgreSQL]
       ├──> [Real-time Updates - Supabase Realtime] ──> [Dashboard - React on Vercel]
       └──> [Email - Nodemailer/Gmail SMTP]
```

## Tech Stack

| Component | Technology |
|-----------|-----------|
| ML Model | Python, scikit-learn (Random Forest, Decision Tree, KNN, Gradient Boosting) |
| Packet Capture | Python, Scapy |
| Backend API | Node.js, Express (Vercel Serverless Functions) |
| Frontend | React (Vercel) |
| Database | PostgreSQL (Supabase) |
| Real-time | Supabase Realtime |
| Email | Nodemailer, Gmail SMTP |
| Dataset | NSL-KDD (41 features, 5 classes) |

## Attack Categories

| Category | Examples |
|----------|---------|
| DoS | Neptune, Smurf, Pod, Teardrop, Land, Back |
| Probe | Portsweep, IPsweep, Nmap, Satan |
| R2L | Guess_password, FTP_write, Imap, Phf, Multihop, Warezmaster |
| U2R | Buffer_overflow, Loadmodule, Rootkit, Perl |

## Project Structure

```
network-ids/
├── ml/                  # Machine learning pipeline
│   ├── train_model.py   # Train and compare 4 algorithms
│   ├── preprocess.py    # Data cleaning, encoding, normalisation
│   ├── evaluate.py      # Generate performance reports
│   └── model/           # Saved trained model (.pkl)
├── capture/             # Real-time packet capture
│   ├── packet_capture.py
│   ├── feature_extractor.py
│   └── classifier.py
├── backend/             # Vercel serverless API
│   ├── api/
│   ├── services/
│   └── config/
├── frontend/            # React dashboard
│   └── src/components/
├── data/                # NSL-KDD dataset
└── README.md
```

## Setup & Running

### 1. ML Model Training
```bash
cd ml
pip install -r requirements.txt
python train_model.py
```

### 2. Backend (Vercel)
```bash
cd backend
npm install
vercel dev   # local development
```

### 3. Frontend (Vercel)
```bash
cd frontend
npm install
npm run dev
```

### 4. Packet Capture (requires root/admin)
```bash
cd capture
sudo python packet_capture.py
```

## Confidence Thresholds

| Confidence | Action |
|-----------|--------|
| > 80% | Alert + Email notification |
| 50-80% | Suspicious activity flag |
| < 50% | Flagged for review |

## License

This project is developed for academic purposes at the University of Botswana.
