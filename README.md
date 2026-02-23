# 🚀 LuauHub — Plataforma de Hospedagem de Scripts Luau

**Plataforma 100% gratuita** para hospedar, compartilhar e gerenciar scripts Luau (Roblox) com segurança enterprise.

---

## 📦 Estrutura do Projeto

```
luauhub/
├── index.html        ← Frontend completo (auto-contido, sem dependências)
├── server.js         ← Backend Node.js completo
├── package.json      ← Dependências
├── .env.example      ← Template de variáveis de ambiente
└── README.md
```

---

## ⚡ Instalação Rápida

### 1. Pré-requisitos
- Node.js 18+
- MongoDB 6+ (local ou MongoDB Atlas gratuito)
- npm

### 2. Clone e instale

```bash
# Clonar / copiar arquivos para uma pasta
cd luauhub

# Instalar dependências
npm install

# Configurar variáveis de ambiente
cp .env.example .env
nano .env  # Edite com seus valores
```

### 3. Configure o `.env`

```env
PORT=3000
MONGODB_URI=mongodb://localhost:27017/luauhub
JWT_SECRET=seu_segredo_forte_aqui
```

### 4. Inicie o servidor

```bash
# Produção
npm start

# Desenvolvimento (com auto-reload)
npm run dev
```

### 5. Acesse

Abra `index.html` no navegador, ou sirva-o com o Express:

```
http://localhost:3000
```

---

## 🌐 Deploy em Produção

### Opção A — Railway (recomendado, gratuito)
1. Crie conta em [railway.app](https://railway.app)
2. Novo projeto → Deploy from GitHub
3. Adicione o MongoDB: Add Plugin → MongoDB
4. Configure as env vars no dashboard
5. Deploy automático!

### Opção B — VPS (Ubuntu)

```bash
# Instalar Node.js
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt-get install -y nodejs

# Instalar MongoDB
sudo apt-get install -y mongodb
sudo systemctl start mongodb

# Instalar PM2 (gerenciador de processos)
npm install -g pm2

# Iniciar a aplicação
pm2 start server.js --name luauhub
pm2 startup  # Iniciar automaticamente no boot
pm2 save

# Configurar Nginx como proxy reverso
sudo apt install nginx
```

**Configuração Nginx:**
```nginx
server {
    listen 80;
    server_name seudominio.com;

    location / {
        proxy_pass http://localhost:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_cache_bypass $http_upgrade;
    }
}
```

```bash
# Ativar HTTPS (Let's Encrypt gratuito)
sudo apt install certbot python3-certbot-nginx
sudo certbot --nginx -d seudominio.com
```

### Opção C — MongoDB Atlas (cloud gratuito)
1. Crie conta em [mongodb.com/atlas](https://mongodb.com/atlas)
2. Cluster gratuito (M0)
3. Copie a connection string
4. Cole no `MONGODB_URI` do `.env`

---

## 🔐 Segurança Implementada

| Recurso | Implementação |
|---------|--------------|
| DDoS/DoS | Rate limiting por IP (100 req/min global, 10/15min em auth) |
| WAF | Helmet.js com CSP, HSTS, XSS Protection |
| SQL/NoSQL Injection | express-mongo-sanitize |
| XSS | Sanitização de inputs + CSP headers |
| CSRF | Token JWT stateless |
| Senhas | bcrypt com 12 rounds |
| Tokens | JWT com expiração de 7 dias |
| IP Bloqueado | Middleware verifica BD antes de cada request |
| Script Scan | Padrões maliciosos detectados automaticamente |
| Blacklist | Email, username, IP e padrões de conteúdo |

---

## 📡 API Endpoints

### Auth
```
POST /api/auth/register          Criar conta
POST /api/auth/login             Login
POST /api/auth/forgot-password   Solicitar reset
POST /api/auth/reset-password    Redefinir senha
GET  /api/auth/me                Perfil atual (requer token)
```

### Scripts
```
GET    /api/scripts              Listar scripts públicos
GET    /api/scripts/:id          Obter script
POST   /api/scripts              Upload (requer auth)
PUT    /api/scripts/:id          Editar (requer auth)
DELETE /api/scripts/:id          Excluir (requer auth)
GET    /api/scripts/user/me      Meus scripts (requer auth)
```

### API Keys
```
GET    /api/keys                 Listar minhas chaves
POST   /api/keys                 Gerar nova chave
DELETE /api/keys/:id             Revogar chave
```

### Admin (apenas naotemsuporte@gmail.com)
```
GET    /api/admin/stats          Estatísticas
GET    /api/admin/users          Listar usuários
PATCH  /api/admin/users/:id/ban  Banir/desbanir
GET    /api/admin/logs           Logs completos
GET    /api/admin/scripts        Todos os scripts
DELETE /api/admin/scripts/:id    Excluir script
GET    /api/admin/ips            IPs e atividade
POST   /api/admin/ips/block      Bloquear IP
DELETE /api/admin/ips/:ip/unblock Desbloquear IP
POST   /api/admin/blacklist      Adicionar ao blacklist
GET    /api/admin/blacklist      Ver blacklist
```

### Autenticação
```http
Authorization: Bearer <seu-token-jwt>
X-API-Key: <sua-chave-api>     (para scripts protegidos por chave)
```

---

## 🎛️ Acesso Admin

O painel admin é acessível **somente** pelo email:
```
naotemsuporte@gmail.com
```

Crie uma conta com esse email para ter acesso ao painel administrativo completo.

---

## 📊 Logs Discord

Os webhooks enviam automaticamente embeds organizadas para:
- **Registro:** Novo usuário criado
- **Login:** Login bem-sucedido ou falha

Cada embed contém: username, email, ID, IP, país, data/hora, user agent e status.

---

## 🛠️ Tecnologias

- **Frontend:** HTML5 + CSS3 + JavaScript (vanilla, zero dependências)
- **Backend:** Node.js + Express.js
- **Banco de Dados:** MongoDB + Mongoose
- **Segurança:** Helmet, bcrypt, JWT, express-rate-limit, express-mongo-sanitize
- **Notificações:** Discord Webhooks via axios
- **Deploy:** PM2 + Nginx (VPS) ou Railway/Render (PaaS)

---

## 📝 Licença

MIT — Uso livre para fins pessoais e comerciais.
