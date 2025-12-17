<p align="center">
  <img src="./assets/megagig-logo.png" alt="Megagig Software Solutions" width="200"/>
</p>

<h1 align="center">🔐 Advanced Authentication Boilerplate</h1>

<p align="center">
  <strong>A production-ready authentication system built with Node.js, Express, MongoDB, and modern security practices</strong>
</p>

<p align="center">
  <a href="#features">Features</a> •
  <a href="#tech-stack">Tech Stack</a> •
  <a href="#getting-started">Getting Started</a> •
  <a href="#api-endpoints">API Endpoints</a> •
  <a href="#deployment">Deployment</a> •
  <a href="#license">License</a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Node.js-339933?style=for-the-badge&logo=nodedotjs&logoColor=white" alt="Node.js"/>
  <img src="https://img.shields.io/badge/Express-000000?style=for-the-badge&logo=express&logoColor=white" alt="Express"/>
  <img src="https://img.shields.io/badge/MongoDB-47A248?style=for-the-badge&logo=mongodb&logoColor=white" alt="MongoDB"/>
  <img src="https://img.shields.io/badge/TypeScript-3178C6?style=for-the-badge&logo=typescript&logoColor=white" alt="TypeScript"/>
  <img src="https://img.shields.io/badge/JWT-000000?style=for-the-badge&logo=jsonwebtokens&logoColor=white" alt="JWT"/>
</p>

---

## 📋 Overview

This project demonstrates how to build a **secure, production-grade authentication system** from scratch. It covers the same patterns and practices used in real SaaS products, focusing on clarity, security, and real-world architecture.

Whether you're learning backend authentication, preparing for production deployments, or need a solid foundation for your next project — this boilerplate has you covered.

---

## ✨ Features

| Feature | Description |
|---------|-------------|
| 🔐 **JWT Authentication** | Access tokens, refresh tokens, and HttpOnly cookies |
| 🔁 **Token Refresh & Invalidation** | Secure logout and password reset handling with token versioning |
| 📧 **Email Verification** | Block unverified users from accessing protected resources |
| 🔑 **Forgot & Reset Password** | Secure, expiring reset tokens via email |
| 🌐 **Google OAuth Login** | Social login integrated with the same JWT infrastructure |
| 🔐 **Two-Factor Authentication** | TOTP support for Google Authenticator / Authy |
| 👤 **Protected Routes & RBAC** | Role-based access control (User vs Admin) |
| 🧑‍💼 **Admin Users API** | Securely list and manage users (admin-only) |
| 🧪 **API Testing** | Fully tested with Postman & curl |
| 🚀 **Production Ready** | PM2, Nginx, HTTPS, real SMTP deployment |

---

## 🛠️ Tech Stack

### Backend
- **Node.js** - JavaScript runtime
- **Express.js** - Web framework
- **MongoDB** - NoSQL database
- **Mongoose** - MongoDB ODM
- **TypeScript** - Type safety

### Authentication & Security
- **JWT** - Access & Refresh Tokens
- **HttpOnly Cookies** - Secure token storage
- **bcrypt** - Password hashing
- **RBAC** - Role-Based Access Control
- **otplib** - TOTP Two-Factor Authentication

### Social Login
- **Google OAuth 2.0** - Google sign-in integration

### Email & Notifications
- **Nodemailer** - Email sending
- **Mailtrap** - Development email testing
- **Production SMTP** - Real email delivery

### Deployment & Infrastructure
- **Linux VPS** - Hostinger
- **PM2** - Process manager
- **Nginx** - Reverse proxy
- **Let's Encrypt** - HTTPS/SSL certificates

---

## 🚀 Getting Started

### Prerequisites

- Node.js v18+ 
- MongoDB (local or Atlas)
- npm or yarn

### Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/Megagig/nodejs_advanced_auth.git
   cd nodejs_advanced_auth
   ```

2. **Install dependencies**
   ```bash
   npm install
   ```

3. **Set up environment variables**
   ```bash
   cp .env.example .env
   ```
   
   Configure your `.env` file:
   ```env
   NODE_ENV=development
   PORT=5000
   
   MONGO_URI=mongodb://localhost:27017/advanced_auth_db
   
   JWT_ACCESS_SECRET=your_access_secret_here
   JWT_REFRESH_SECRET=your_refresh_secret_here
   
   SMTP_HOST=sandbox.smtp.mailtrap.io
   SMTP_PORT=2525
   SMTP_USER=your_mailtrap_user
   SMTP_PASS=your_mailtrap_pass
   EMAIL_FROM="My App <no-reply@myapp.com>"
   
   GOOGLE_CLIENT_ID=your_google_client_id
   GOOGLE_CLIENT_SECRET=your_google_client_secret
   GOOGLE_REDIRECT_URI=http://localhost:5000/auth/google/callback
   ```

4. **Start the development server**
   ```bash
   npm run dev
   ```

5. **Build for production**
   ```bash
   npm run build
   npm start
   ```

---

## 📡 API Endpoints

### Authentication

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/auth/register` | Register a new user |
| `POST` | `/auth/login` | Login with email & password |
| `POST` | `/auth/logout` | Logout and invalidate tokens |
| `POST` | `/auth/refresh` | Refresh access token |
| `GET` | `/auth/verify-email` | Verify email with token |
| `POST` | `/auth/forgot-password` | Request password reset |
| `POST` | `/auth/reset-password` | Reset password with token |

### Google OAuth

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/auth/google` | Initiate Google OAuth |
| `GET` | `/auth/google/callback` | Google OAuth callback |

### Two-Factor Authentication

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/auth/2fa/setup` | Generate 2FA secret & QR code |
| `POST` | `/auth/2fa/verify` | Verify and enable 2FA |
| `POST` | `/auth/2fa/validate` | Validate 2FA code on login |
| `POST` | `/auth/2fa/disable` | Disable 2FA |

### User Routes

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/user/me` | Get current user profile |

### Admin Routes

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/admin/users` | List all users (admin only) |

---

## 📁 Project Structure

```
├── src/
│   ├── config/
│   │   └── db.ts              # Database connection
│   ├── controllers/
│   │   └── auth/
│   │       ├── auth.controller.ts
│   │       └── auth.schema.ts  # Zod validation
│   ├── lib/
│   │   ├── email.ts           # Email utilities
│   │   ├── googleClient.ts    # Google OAuth client
│   │   ├── hash.ts            # Password hashing
│   │   └── token.ts           # JWT utilities
│   ├── middlewares/
│   │   ├── requireAuth.ts     # Authentication middleware
│   │   └── requireRole.ts     # RBAC middleware
│   ├── models/
│   │   └── user.model.ts      # User schema
│   ├── routes/
│   │   ├── admin.routes.ts
│   │   ├── auth.routes.ts
│   │   └── user.routes.ts
│   ├── app.ts                 # Express app setup
│   └── server.ts              # Server entry point
├── scripts/
│   └── generate-qr.ts         # 2FA QR code generator
├── .env.example
├── package.json
├── tsconfig.json
└── README.md
```

---

## 🔒 Security Features

- **Password Hashing** - bcrypt with salt rounds
- **JWT Token Rotation** - Short-lived access tokens, long-lived refresh tokens
- **HttpOnly Cookies** - Protection against XSS attacks
- **Token Versioning** - Invalidate all sessions on password change
- **Rate Limiting** - Prevent brute force attacks (production)
- **Input Validation** - Zod schema validation
- **HTTPS** - TLS encryption in production

---

## 🚢 Deployment

### VPS Deployment (Hostinger)

1. **Set up your VPS** with Ubuntu/Debian
2. **Install Node.js, MongoDB, Nginx, and PM2**
3. **Clone and build the project**
4. **Configure Nginx as reverse proxy**
5. **Set up SSL with Let's Encrypt**
6. **Start with PM2**

```bash
# Build the project
npm run build

# Start with PM2
pm2 start dist/server.js --name "auth-api"
pm2 save
pm2 startup
```

---

## 🧪 Testing

Use **Postman** or **curl** to test the API endpoints.

```bash
# Register a new user
curl -X POST http://localhost:5000/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email": "test@example.com", "password": "SecurePass123!"}'

# Login
curl -X POST http://localhost:5000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email": "test@example.com", "password": "SecurePass123!"}'
```

---

## 👥 Who This Project Is For

- 🎓 Developers learning backend authentication
- 🏗️ Engineers preparing for real-world Node.js projects
- 🔍 Anyone who wants to understand how authentication works in production
- 🚀 Developers deploying secure APIs to a VPS

---

## 📄 License

This project is licensed under the **ISC License**.

---

## 👨‍💻 Author

**Obi Anthony**  
[Megagig Software Solutions](https://github.com/Megagig)

---

<p align="center">
  <sub>Built with ❤️ by Megagig Software Solutions</sub>
</p>
