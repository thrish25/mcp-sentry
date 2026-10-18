# Windows PowerShell Setup & Run Guide

This document provides exact Windows PowerShell commands to set up, test, and run **MCP-Sentry** (Backend and Frontend).

---

## 1. Prerequisites

Verify your installed runtimes in PowerShell:

```powershell
python --version
node -v
npm -v
```

> **Note**: Node.js is located at `C:\Users\Thrisha\AppData\Local\Programs\nodejs`. If running in a new terminal window, ensure it is present in `$env:PATH`:
> ```powershell
> $env:Path = "C:\Users\Thrisha\AppData\Local\Programs\nodejs;" + $env:Path
> ```

---

## 2. Backend Setup & Run

### 2.1 Set Up Environment

Open PowerShell in the project root (`c:\Users\Thrisha\Desktop\mcp sentry`):

```powershell
# 1. Create a virtual environment (optional but recommended)
python -m venv .venv

# 2. Activate the virtual environment
.\.venv\Scripts\Activate.ps1
# If PowerShell script execution is restricted, temporarily run:
# Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned

# 3. Copy example environment file
Copy-Item backend\.env.example backend\.env

# 4. Install backend dependencies
python -m pip install -r backend\requirements.txt
```

### 2.2 Run Backend Tests

```powershell
# From project root:
python -m pytest backend\tests -v
```

### 2.3 Start the FastAPI Backend Server

```powershell
# From project root:
python -m uvicorn app.main:app --app-dir backend --reload --host 127.0.0.1 --port 8000
```

Verify the health check from another PowerShell window:

```powershell
Invoke-RestMethod -Uri "http://127.0.0.1:8000/health"
```

Expected Response:
```json
{
  "status": "healthy",
  "service": "mcp-sentry-backend",
  "version": "0.1.0",
  "environment": "development"
}
```

Interactive API documentation will be available at:
- **Swagger UI**: [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)
- **ReDoc**: [http://127.0.0.1:8000/redoc](http://127.0.0.1:8000/redoc)

---

## 3. Frontend Setup & Run

### 3.1 Install Dependencies

In PowerShell:

```powershell
cd frontend

# Copy environment example
Copy-Item .env.example .env.local

# Install frontend dependencies
npm install
```

### 3.2 Run Frontend Development Server

```powershell
# Inside frontend directory:
npm run dev
```

Visit the application in your browser:
- [http://localhost:3000](http://localhost:3000)

---

## 4. Concurrent Development Run (Two Terminals)

- **Terminal 1 (Backend)**:
  ```powershell
  python -m uvicorn app.main:app --app-dir backend --reload --host 127.0.0.1 --port 8000
  ```

- **Terminal 2 (Frontend)**:
  ```powershell
  cd frontend
  npm run dev
  ```
