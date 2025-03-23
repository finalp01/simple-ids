# Setting Up Simple IDS and React Dashboard

## 1. Initialize Python Virtual Environment

1. Open a terminal and navigate to the `simple_ids` directory:
   ```sh
   cd simple_ids

    Create and activate a virtual environment:

        On macOS/Linux:

python3 -m venv venv
source venv/bin/activate

On Windows:

    python -m venv venv
    venv\Scripts\activate

Install dependencies:

    pip install -r requirements.txt

2. Run the Simple IDS API

    Move back to the parent directory:

cd ..

Start the API server:

    python -m simple_ids.api.app

3. Set Up React Dashboard

    Navigate to the dashboard directory:

cd ids-dashboard

Install dependencies:

npm install

Start the React app:

    npm start

Now, the Simple IDS backend and frontend should be running! 🚀
