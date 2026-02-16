# Running SigmaAssistant on Mac

## Prerequisites
- **Python 3.8+**: Ensure you have Python installed (`python3 --version`).

## Quick Start
1.  **Open Terminal** and navigate to the project directory:
    ```bash
    cd /path/to/SigmaAssistant
    ```
2.  **Run the setup script**:
    ```bash
    chmod +x run_mac.sh
    ./run_mac.sh
    ```
3.  **Access the App**:
    Open your browser and go to `http://localhost:8000`.

## Manual Setup
If you prefer to run commands manually:

1.  **Create a Virtual Environment**:
    ```bash
    python3 -m venv .venv
    source .venv/bin/activate
    ```
2.  **Install Dependencies**:
    ```bash
    pip install -r requirements.txt
    ```
3.  **Environment Variables**:
    - Ensure you have a `.env` file with `GEMINI_API_KEY`.
4.  **Run the Backend**:
    ```bash
    uvicorn backend.main:app --reload
    ```
