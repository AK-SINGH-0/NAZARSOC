@echo off
REM NazarSOC — Windows launcher
REM Creates a local virtual environment, installs dependencies,
REM and starts the dashboard on localhost only (no public exposure).

REM ── Step 1: Create venv if it does not already exist ──────────────────────
if not exist "venv\Scripts\activate.bat" (
    echo [NazarSOC] Creating virtual environment...
    python -m venv venv
    if errorlevel 1 (
        echo [NazarSOC] ERROR: Failed to create virtual environment.
        echo            Make sure Python 3.9+ is installed and on PATH.
        exit /b 1
    )
)

REM ── Step 2: Activate venv ─────────────────────────────────────────────────
call venv\Scripts\activate.bat

REM ── Step 3: Install / upgrade dependencies ────────────────────────────────
echo [NazarSOC] Installing dependencies from requirements.txt...
python -m pip install --quiet --upgrade pip
python -m pip install --quiet -r requirements.txt
if errorlevel 1 (
    echo [NazarSOC] ERROR: pip install failed.
    exit /b 1
)

REM ── Step 4: Launch dashboard ──────────────────────────────────────────────
echo [NazarSOC] Starting dashboard at http://127.0.0.1:8501
python -m streamlit run app.py --server.address 127.0.0.1 --server.port 8501
