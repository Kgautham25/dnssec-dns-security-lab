Open 3 terminals:

1st terminal - run "docker compose --up build"
2nd terminal - 
        command:
                cd frontend
                npm install
                npm run dev

                the website open in http://localhost:5173
3rd terminal -
            cd backend / api
            python3 -m venv env
            source env/bin/activate
            pip install flask
            pip install flask_cors
            python3 server.py
