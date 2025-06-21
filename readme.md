# Risk Assessment Web Application

This project is a full-stack web application for risk assessment, featuring a React frontend and a Flask backend. It allows users to upload documents, perform risk analysis, and view results through interactive dashboards and charts.

## Table of Contents
- [Features](#features)
- [Project Structure](#project-structure)
- [Backend Setup (Flask)](#backend-setup-flask)
- [Frontend Setup (React)](#frontend-setup-react)
- [Usage](#usage)
- [License](#license)

## Features
- User authentication (login/signup)
- File upload for risk analysis
- Automated risk assessment and reporting
- Interactive dashboards and charts
- History tracking of previous assessments

## Project Structure
```
.
├── backend/                # Flask backend (API, authentication, database)
│   ├── app.py
│   ├── auth.py
│   ├── requirements.txt
│   └── ...
├── riskassessment/         # React frontend (UI, components)
│   ├── src/
│   │   ├── components/
│   │   └── ...
│   ├── package.json
│   └── ...
├── Software Requirement Specification.pdf
├── SRSExample-webapp.pdf
├── ...
```

## Backend Setup (Flask)
1. Navigate to the `backend` directory:
   ```powershell
   cd backend
   ```
2. (Optional) Create and activate a virtual environment:
   ```powershell
   python -m venv venv
   .\venv\Scripts\activate
   ```
3. Install dependencies:
   ```powershell
   pip install -r requirements.txt
   ```
4. Run the Flask server:
   ```powershell
   python app.py
   ```

## Frontend Setup (React)
1. Navigate to the `riskassessment` directory:
   ```powershell
   cd riskassessment
   ```
2. Install dependencies:
   ```powershell
   npm install
   ```
3. Start the React development server:
   ```powershell
   npm start
   ```

## Environment Variables
1. Copy the file `backend/.env.example` to `backend/.env`:
   ```powershell
   copy backend\.env.example backend\.env
   ```
2. Edit `backend/.env` and fill in your own credentials and secrets for the required variables.

## Usage
- Access the frontend at `http://localhost:3000` (default React port).
- The backend API runs at `http://localhost:5000` (default Flask port).
- Register or log in, upload documents, and view risk assessment results.