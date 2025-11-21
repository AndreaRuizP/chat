const express = require('express');
const path = require('path');
const cors = require('cors');
const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Servir archivos estáticos
app.use(express.static(path.join(__dirname)));
app.use('/public', express.static(path.join(__dirname, 'public')));
app.use('/pages', express.static(path.join(__dirname, 'pages')));

// Ruta principal
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// Rutas para las páginas
app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'pages', 'login.html'));
});

app.get('/registro', (req, res) => {
  res.sendFile(path.join(__dirname, 'pages', 'registro.html'));
});

// Manejo de errores 404
app.use((req, res) => {
  res.status(404).send(`
    <!DOCTYPE html>
    <html>
    <head>
      <title>404 - Página no encontrada</title>
      <style>
        body {
          background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
          display: flex;
          justify-content: center;
          align-items: center;
          height: 100vh;
          margin: 0;
          font-family: Arial, sans-serif;
          color: white;
          text-align: center;
        }
        .container {
          background: rgba(255, 255, 255, 0.1);
          padding: 40px;
          border-radius: 20px;
          backdrop-filter: blur(10px);
        }
        h1 { font-size: 72px; margin: 0; }
        p { font-size: 24px; }
        a {
          color: #fff;
          text-decoration: none;
          background: rgba(255, 255, 255, 0.2);
          padding: 10px 20px;
          border-radius: 10px;
          display: inline-block;
          margin-top: 20px;
        }
        a:hover { background: rgba(255, 255, 255, 0.3); }
      </style>
    </head>
    <body>
      <div class="container">
        <h1>404</h1>
        <p>Página no encontrada</p>
        <a href="/">Volver al inicio</a>
      </div>
    </body>
    </html>
  `);
});

// Manejo de errores general
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: 'Algo salió mal en el servidor!' });
});

// Iniciar servidor
app.listen(PORT, () => {
  console.log(`
                                         
  🚀 Servidor Node.js corriendo exitosamente         
                                                
  📍 URL: http://localhost:${PORT}                      
  📁 Sirviendo archivos estáticos                     
  🔗 Backend API: http://localhost:8000               
                                                    
  Páginas disponibles:                              
  • http://localhost:${PORT}/                          
  • http://localhost:${PORT}/login                     
  • http://localhost:${PORT}/registro                  

  `);
});

module.exports = app;