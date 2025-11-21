Instalar dependencias
npm init -y
npm install express ws sqlite3
pip install fastapi uvicorn

Para iniciar el servidor Websocket
# Ejecutar en desarrollo
npm run dev
# Ejecutar en producción
npm start

Para iniciar el FastApi
# Instalar dependencias
pip install -r requirements.txt
# Ejecutar servidor
python run.py
# O directamente con uvicorn:
uvicorn main:app --reload --host 0.0.0.0 --port 8000