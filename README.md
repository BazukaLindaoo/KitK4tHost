# 🐱 KitK4t Host — Plataforma de Scripts Luau

Plataforma **100% gratuita** para hospedar, compartilhar e gerenciar scripts Luau (Roblox).

---

## 📦 Estrutura do Projeto

```
kitk4t-host/
├── index.html      ← Frontend completo
├── server.js       ← Backend Node.js
├── package.json    ← Dependências
├── .env.example    ← Template de variáveis de ambiente
└── README.md
```

---

## ⚡ Instalação

### 1. Pré-requisitos
- Node.js 18+
- MongoDB 6+
- npm

### 2. Instalar dependências

```bash
npm install
```

### 3. Configurar variáveis de ambiente

```bash
cp .env.example .env
# Edite o .env com seus dados
```

### 4. Iniciar

```bash
# Produção
npm start

# Desenvolvimento
npm run dev
```

---

## 🌐 Deploy

### Railway (recomendado)
1. Suba os arquivos no GitHub
2. Conecte o repositório no [railway.app](https://railway.app)
3. Adicione o plugin MongoDB
4. Configure as variáveis do `.env` no dashboard
5. Deploy automático!

### VPS (Ubuntu)

```bash
# Node.js
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt-get install -y nodejs

# MongoDB
sudo apt-get install -y mongodb
sudo systemctl start mongodb

# Dependências e iniciar
npm install
npm install -g pm2
pm2 start server.js --name kitk4t
pm2 startup && pm2 save
```

**Nginx como proxy reverso:**
```nginx
server {
    listen 80;
    server_name seudominio.com;

    location / {
        proxy_pass http://localhost:3000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}
```

```bash
# SSL gratuito
sudo apt install certbot python3-certbot-nginx
sudo certbot --nginx -d seudominio.com
```

---

## 🔐 Segurança

- Rate limiting por IP
- Proteção contra DDoS/DoS
- WAF com Helmet.js
- Sanitização contra NoSQL Injection
- Senhas com bcrypt
- Tokens JWT com expiração
- Scanner de scripts maliciosos
- Sistema de blacklist e bloqueio de IP

---

## 🛠️ Tecnologias

- **Frontend:** HTML5 + CSS3 + JavaScript
- **Backend:** Node.js + Express.js
- **Banco de dados:** MongoDB + Mongoose
- **Segurança:** Helmet, bcrypt, JWT, express-rate-limit
