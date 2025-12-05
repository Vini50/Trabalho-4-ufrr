require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const session = require('express-session');
const helmet = require('helmet');
const csurf = require('csurf');
const rateLimit = require('express-rate-limit');
const cookieParser = require('cookie-parser');
const isAuth = require('./middleware/auth'); 
const authController = require('./controllers/authController');

const app = express();
const PORT = process.env.PORT || 3000;

// Configuração de Conexão (Usa .env)
const connectionURL = process.env.DB_CONNECTION_STRING;

// Verifica se a chave de conexão existe antes de tentar conectar
if (!connectionURL) {
    console.error("❌ ERRO CRÍTICO: DB_CONNECTION_STRING não definida no arquivo .env");
}

mongoose.connect(connectionURL)
  .then(() => {
    console.log('Conexão ao Database estabelecida.');
  })
  .catch((err) => {
    console.error(' Erro na Conexão:', err);
  });

app.set('view engine', 'ejs');
app.set('views', 'views');

// ==========================================
// MIDDLEWARES DE SEGURANÇA (Ordem Correta!)
// ==========================================

// 1. Hardening HTTP Headers (Helmet)
app.use(helmet());

// 2. Body Parsers (Lê dados POST)
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// 3. Cookie Parser (DEVE vir antes da sessão e do csurf)
app.use(cookieParser()); 

// 4. Gerenciamento de Sessão
app.use(session({
    secret: process.env.SESSION_SECRET || 'chave_de_backup_nao_segura_para_express',
    resave: false,
    saveUninitialized: false,
    cookie: { 
        httpOnly: true,
        maxAge: 3600000 
    }
}));

// 5. Proteção Anti-CSRF (Após a sessão e o cookie-parser)
const csrfProtection = csurf({ cookie: true });
app.use(csrfProtection);

// Middleware para disponibilizar o Token nas Views
app.use((req, res, next) => {
    res.locals.csrfToken = req.csrfToken();
    next();
});

// Limitação de Taxa (Rate Limiter)
const authRateLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: 5,
    message: "Acesso temporariamente suspenso. Excesso de tentativas."
});

// ==========================================
// DEFINIÇÃO DAS ROTAS (Routing)
// ==========================================

// ROTA RAÍZ MODIFICADA: Redireciona para o Cadastro
app.get('/', (req, res) => {
    if (req.session.userId) {
        return res.redirect('/perfil');
    }
    res.redirect('/register'); 
});


// Rota de Cadastro (Pública)
app.get('/register', (req, res) => {
    res.send(`
        <h2>Página de Cadastro</h2>
        <form action="/register" method="POST">
            <input type="hidden" name="_csrf" value="${req.csrfToken()}"> 
            <input type="text" name="nome" placeholder="Nome" required><br>
            <input type="email" name="email" placeholder="Email" required><br>
            <input type="password" name="senha" placeholder="Senha" required><br>
            <button type="submit">Cadastrar (Protegido por CSRF)</button>
        </form>
        <p>Já tem conta? <a href="/login">Fazer Login</a></p>
        <hr>
        <!-- BOTÃO DE TESTE DE BAC -->
        <a href="/perfil"><button style="background-color: #ffcccc; color: #cc0000; border: none; padding: 8px;">Tentar Acessar Página Secreta (Teste BAC)</button></a>
    `);
});

// ROTA PÚBLICA de POST para Cadastro
app.post('/register', authController.register);


// Rota Simples de Login (Pública)
app.get('/login', (req, res) => {
    res.send(`
        <h2>Página de Login</h2>
        <form action="/login" method="POST">
            <input type="hidden" name="_csrf" value="${req.csrfToken()}"> 
            <input type="email" name="email" placeholder="Email"><br>
            <input type="password" name="senha" placeholder="Senha"><br>
            <button type="submit">Logar (Testar Rate Limit e CSRF)</button>
        </form>
        <p>Não tem conta? <a href="/register">Cadastre-se</a></p>
        <hr>
        <!-- BOTÃO DE TESTE DE BAC -->
        <a href="/perfil"><button style="background-color: #ffcccc; color: #cc0000; border: none; padding: 8px;">Tentar Acessar Página Secreta (Teste BAC)</button></a>
    `);
});

// ROTA PÚBLICA de POST para Login com defesa Rate Limit e CSRF
app.post('/login', authRateLimiter, authController.login);

// ROTA PROTEGIDA: isAuth garante a Autorização (AuthZ)
app.get('/perfil', isAuth, (req, res) => {
    res.send(`
        <h1>Página Protegida (AuthZ OK)!</h1>
        <p>Bem-vindo, ${req.session.userName}!</p>
        <p>Seu acesso foi verificado pelo isAuth middleware.</p>
        <a href="/logout">Logout</a>
    `);
});

// Rota de Logout
app.get('/logout', authController.logout);

// ==========================================
// TRATAMENTO DE ERROS (Final Middleware Chain)
// ==========================================

// Captura erros de Token CSRF (EBADCSRFTOKEN)
app.use((err, req, res, next) => {
    if (err.code !== 'EBADCSRFTOKEN') return next(err);
    res.status(403).send('Erro de Segurança: Token de Formulário Inválido.');
});

// ==========================================
// INICIALIZAÇÃO
// ==========================================
app.listen(PORT, () => {
    console.log(`🚀 Servidor rodando em http://localhost:${PORT}`);
});