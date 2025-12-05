Relatório Final: Trabalho 4 - Implementando Defesas Arquiteturais

Disciplina: DCC 704 - Arquitetura e Tecnologias de Sistemas WEB
Professor: Jean Bertrand
Aluno:Helian vinicius Filinto da Silva
Matricula: 2022008985


🎯 Objetivo do Trabalho

Fortificar a arquitetura do projeto web (baseado nas Aulas 18 e 19) contra as vulnerabilidades mais críticas da OWASP, aplicando middlewares de segurança e boas práticas na camada do servidor.

🛡️ Vulnerabilidades Mitigadas e Mecanismos de Defesa

A tabela a seguir lista as vulnerabilidades críticas tratadas e especifica os mecanismos de defesa implementados no projeto:

OWASP TOP 10

Vulnerabilidade

Mecanismo de Defesa Aplicado

Localização da Defesa

A03

SQL Injection (SQLi)

Queries Parametrizadas

models/User.js e app.js (Via Mongoose)

A07

Cross-Site Scripting (XSS)

Output Escaping por Padrão

Todas as Views (.ejs)

A04

Cross-Site Request Forgery (CSRF)

Tokens Anti-CSRF

app.js (csurf middleware) e rotas POST

A04

Broken Access Control (BAC)

Middleware de Autorização (AuthZ)

middleware/auth.js (isAuth) e rotas restritas (/perfil)

N/A

Ataques de Força Bruta

Limitação de Taxa (Rate Limiting)

app.js (express-rate-limit) na rota POST /login

N/A

Exposição de Credenciais

Variáveis de Ambiente

app.js (dotenv) e arquivo .env

N/A

Hardening de HTTP

HTTP Security Headers

app.js (helmet middleware)

⚙️ Detalhamento das Implementações (Trabalho 4)

1. Defesas Contra SQLi e XSS (Revisão e Validação)

Defesa SQLi: O projeto utiliza Mongoose (um ODM para MongoDB), que previne ataques de SQLi ao construir todas as consultas com Queries Parametrizadas por padrão. Não há concatenação manual de strings com comandos de banco de dados no código.

Defesa XSS: Foi verificado que todas as Views (simuladas ou reais) renderizam dados de usuário utilizando a sintaxe de Output Escaping do EJS (<%= variavel %>), que converte caracteres HTML especiais (<, >) em entidades seguras.

2. Defesa Contra Força Bruta (Rate Limiting)

O middleware express-rate-limit foi configurado e aplicado à rota de login para limitar o número de tentativas de autenticação:

Configuração: Regra de 5 tentativas por minuto (max: 5, windowMs: 60 * 1000).

Implementação: Aplicado diretamente na rota sensível: app.post('/login', authRateLimiter, authController.login).

3. Hardening HTTP e Proteção de Credenciais

Proteção de Headers (Helmet): O app.js aplica o middleware helmet() logo no topo da cadeia de middlewares, garantindo a inclusão de cabeçalhos essenciais como X-Frame-Options e X-Content-Type-Options para mitigar ataques como Clickjacking e MIME type sniffing.

Proteção de Credenciais (dotenv): A chave secreta da sessão (SESSION_SECRET) e a string de conexão do MongoDB Atlas (DB_CONNECTION_STRING) foram movidas para o arquivo .env e lidas via process.env, mantendo as credenciais fora do código-fonte e do repositório Git.

4. Defesa Contra CSRF (Tokens Anti-CSRF)

O middleware csurf foi implementado para proteger todas as requisições POST de falsificações:

Configuração: O middleware csurf() foi ativado após o express-session no app.js.

Injeção do Token: Um middleware global (app.use((req, res, next) => { res.locals.csrfToken = req.csrfToken(); next(); });) injeta o token secreto na variável res.locals.csrfToken, tornando-o acessível em todas as views.

Uso na View: Todos os formulários POST exigem o campo oculto:

<input type="hidden" name="_csrf" value="<%= csrfToken %>">


Isso garante que apenas formulários gerados pelo nosso servidor serão aceitos, bloqueando tentativas de ataque externas.

🛠️ Instruções de Execução

Instalação: npm install helmet csurf express-rate-limit dotenv express-session mongoose bcrypt

Configuração: Crie e preencha o arquivo .env na raiz do projeto.

Execução: node app.js

Testes: As defesas podem ser testadas conforme o guia, verificando o bloqueio 403 (CSRF) e 429 (Rate Limit).