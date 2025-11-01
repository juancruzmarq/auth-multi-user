# 🔐 Auth Multi-User — Sistema de Autenticación y Gestión de Usuarios

**Auth Multi-User** es una aplicación backend construida con **NestJS**, **Prisma**, **PostgreSQL** y **Node.js**, que provee un sistema completo de autenticación, verificación por email, gestión de sesiones y recuperación de contraseñas.

Actualmente implementa un flujo seguro y escalable para manejar múltiples usuarios, sesiones concurrentes, tokens JWT, y un sistema de envío de mails con outbox y plantillas en Handlebars.

---

## 🚀 Tecnologías principales

- **NestJS** — (Node.js framework) 
- **Prisma ORM** — Mapeo objeto-relacional
- **PostgreSQL** — Base de datos relacional 
- **Docker** — Contenedores para desarrollo y despliegue
---

## 🔄 Flujo actual de autenticación

### 1. **Registro (`POST /auth/signup`)**
- Crea un usuario con estado `PENDING`.
- Guarda su credencial con hash bcrypt.
- Genera un token de verificación y encola un email con link de verificación.
- El mail se procesa por el `MailService` vía cron job.

### 2. **Verificación de Email (`POST /auth/verify-email`)**
- El usuario recibe un enlace con token (hash SHA-256).
- Al verificar:
  - Se activa la cuenta (`UserStatus.ACTIVE`).
  - Se marca el email como verificado.
  - Se encola un mail de bienvenida.

### 3. **Login (`POST /auth/login`)**
- Verifica credenciales con bcrypt.
- Rechaza usuarios suspendidos o no verificados.
- Genera:
  - `access_token` (JWT corto, 15 min)
  - `refresh_token` (JWT largo, 7–30 días)
- Guarda la sesión con hash del refresh token.
- Setea cookie `httpOnly` con el refresh token.

### 4. **Refresh Token (`POST /auth/refresh`)**
- Valida el refresh token desde la cookie.
- Previene “token reuse” (detección de reuso).
- Rota el token (emite uno nuevo y actualiza hash).
- Devuelve un nuevo `access_token`.

### 5. **Logout (`POST /auth/logout`)**
- Revoca la sesión actual y borra la cookie.

### 6. **Logout All (`POST /auth/logout-all`)**
- Revoca todas las sesiones activas del usuario.

### 7. **Reset Password Request (`POST /auth/reset-password-request`)**
- Genera un token de restablecimiento de contraseña.
- Encola un mail con un enlace de reseteo válido por 1 hora.

### 8. **Reset Password (`POST /auth/reset-password`)**
- Verifica el token recibido.
- Actualiza el hash de la contraseña (bcrypt).
- Borra el token usado.

---

## ✉️ Sistema de Emails (Outbox Pattern)

El módulo `MailService` implementa un **patrón Outbox** para asegurar el envío confiable de correos.

- Los correos se encolan en la tabla `mail_outbox` con estado `PENDING`.
- Cada 5 segundos (`CronJob`), se procesan y envían los pendientes.
- Si el envío falla, el registro se marca como `FAILED` con reintento controlado.

### Plantillas disponibles
Ubicadas en `src/mail/templates/`:

| Archivo | Propósito |
|----------|------------|
| `verify-email.hbs` | Verificación de cuenta |
| `welcome-email.hbs` | Bienvenida tras verificación |
| `reset-password.hbs` | Restablecimiento de contraseña |

---

## 🔒 Seguridad

- Contraseñas almacenadas con **bcrypt** (hash con salt interno).
- Tokens (`refresh`, `verification`, `password reset`) se **hashean con SHA-256** antes de guardarse.
- Detección de **reuso de refresh tokens** para invalidar sesiones comprometidas.
- Cookies `httpOnly`, `sameSite`, `secure` configurables vía `.env`.
- JWT firmados con secretos separados (`JWT_ACCESS_SECRET` / `JWT_REFRESH_SECRET`).

---


## ⚙️ Variables de entorno (.env)

El proyecto utiliza un archivo `.env` para configurar todos los servicios.  
A continuación, se detalla el significado de cada variable y su función.

### 🗄️ Base de datos
| Variable | Descripción | Ejemplo |
|-----------|-------------|----------|
| `POSTGRES_USER` | Usuario de la base de datos | `user` |
| `POSTGRES_PASSWORD` | Contraseña del usuario | `password` |
| `POSTGRES_DB` | Nombre de la base de datos | `authdb` |
| `DB_PORT` | Puerto local de PostgreSQL | `5432` |
| `DATABASE_URL` | Cadena completa de conexión usada por Prisma | `postgresql://user:password@localhost:5432/authdb` |

---

### 🔐 Autenticación JWT
| Variable | Descripción | Ejemplo |
|-----------|-------------|----------|
| `JWT_ACCESS_SECRET` | Clave secreta para firmar access tokens | `d54b82f4bf57bf88f9cd6448ac5d67a1` |
| `JWT_REFRESH_SECRET` | Clave secreta para firmar refresh tokens | `e2c3f1a9b6d4e8f7a1b2c3d4e5f60718` |
| `ACCESS_TOKEN_TTL` | Duración del access token (en segundos) | `900` *(15 minutos)* |
| `REFRESH_TOKEN_TTL` | Duración del refresh token (en segundos o días)* | `604800` *(7 días)* |

---

### 🍪 Cookies
| Variable | Descripción | Ejemplo |
|-----------|-------------|----------|
| `REFRESH_COOKIE_NAME` | Nombre del cookie de refresh token | `rt` |
| `COOKIE_SECURE` | `true` en producción (HTTPS), `false` en local | `false` |
| `COOKIE_SAMESITE` | Política SameSite (`lax`, `strict`, `none`) | `lax` |
| `COOKIE_DOMAIN` | Dominio donde se comparte la cookie | `localhost` |

---

### 🔑 Hashing y cifrado
| Variable | Descripción | Ejemplo |
|-----------|-------------|----------|
| `PASSWORD_ALGO` | Algoritmo de hash de contraseñas | `bcrypt` |
| `TOKEN_HASH_PEPPER` | Pepper adicional para tokens (no almacenado en DB) | `pepper_32+chars` |

---

### 🌐 URLs y configuración general
| Variable | Descripción | Ejemplo |
|-----------|-------------|----------|
| `APP_FRONTEND_URL` | URL del frontend para generar enlaces en mails | `http://localhost:5173` |
| `APP_NAME` | Nombre de la aplicación (usado en templates) | `Auth Multi-User` |
| `APP_PORT` | Puerto del servidor NestJS | `3000` |
| `ENVIRONMENT` | Entorno actual (`development` o `production`) | `development` |

---

### ✉️ Correo (Mailer)
| Variable | Descripción | Ejemplo |
|-----------|-------------|----------|
| `MAIL_HOST` | Servidor SMTP | `smtp.mailersend.net` |
| `MAIL_PORT` | Puerto SMTP | `587` |
| `MAIL_USER` | Usuario del servicio SMTP | `api_user@test-domain.com` |
| `MAIL_PASS` | Contraseña o token del servicio SMTP | `secret_password` |
| `MAIL_FROM` | Dirección del remitente por defecto | `Auth App <noreply@yourdomain.com>` |

> ⚠️ Asegurate de que `MAIL_FROM` sea una dirección válida según el proveedor SMTP.  
> Ejemplo para MailerSend:  
> `MAIL_FROM="Auth Multi-User <no-reply@tudominio.com>"`

---

### 🧩 Throttling / Rate Limiting
| Variable | Descripción | Ejemplo |
|-----------|-------------|----------|
| `THROTTLE_TTL` | Ventana de tiempo para conteo de requests (ms) | `60000` *(1 minuto)* |
| `THROTTLE_LIMIT` | Límite de requests por ventana | `20` |

---
## 🧩 Endpoints principales

| Método | Ruta | Descripción |
|--------|------|-------------|
| `POST` | `/auth/signup` | Registro de nuevo usuario |
| `POST` | `/auth/login` | Login con email y contraseña |
| `POST` | `/auth/verify-email` | Verificación de cuenta |
| `POST` | `/auth/reset-password-request` | Solicitar reseteo de contraseña |
| `POST` | `/auth/reset-password` | Restablecer contraseña |
| `POST` | `/auth/refresh` | Renovar tokens (rotación) |
| `POST` | `/auth/logout` | Cerrar sesión actual |
| `POST` | `/auth/logout-all` | Cerrar todas las sesiones |
| `GET` | `/auth/check` | Health check protegido por JWT |



---

## 📥 Instalación y ejecución

Requisitos previos:
- Node.js v18+
- PostgreSQL en ejecución (local o Docker)
- [pnpm](https://pnpm.io/) instalado globalmente
- Docker (opcional, para contenedores)
- Crear un archivo `.env` basado en el `.env.example`
- Configurar las variables de entorno adecuadamente
- Tener Prisma CLI instalado (`npm install -g prisma`)
- Tener Nest CLI instalado (`npm install -g @nestjs/cli`)
- Tener una cuenta SMTP para envío de emails (MailerSend, SendGrid, etc.)
- Tener Docker instalado (opcional, para contenedores)

1. Clona el repositorio:
   ```bash
   git clone
   ```
2. Instala las dependencias:
  ```bash
   cd auth-multi-user
   pnpm install
   ```
3. Configura la base de datos:
   ```bash
   npx prisma migrate dev
   ```
4. Inicia la aplicación:
   ```bash
   pnpm run start:dev
    ```
5. La API estará disponible en `http://localhost:3000`
6. Usa herramientas como Postman o Insomnia para probar los endpoints.
7. Monitorea los logs en la consola para verificar el envío de emails y otras operaciones.
8. Asegúrate de que el servicio SMTP esté correctamente configurado para el envío de correos.
   
---

## 🧑‍💻 Autor

**Juan Cruz Márquez**  
Full Stack / Backend Developer — [GitHub](https://github.com/juancruzmarq)

---
