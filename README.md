Instalar dependencias
npm init -y
npm install express ws sqlite3
pip install fastapi uvicorn

Para iniciar el servidor Websocket
node server.js

Para iniciar el FastApi
uvicorn app:app --reload --port 8000