# Sistema de Login (Express + SQLite + JWT)

## Requisitos
- Node.js 18+

## Instalación
```bash
npm install
```

## Ejecutar
```bash
npm start
```
Luego abre `http://localhost:3000`.

## Variables de entorno (opcional)
Crea un archivo `.env` en la raíz con:
```
PORT=3000
JWT_SECRET=cambia_esto_por_un_valor_secreto
```

## Endpoints
- POST `/api/register` { username, password }
- POST `/api/login` { username, password }
- GET `/api/profile` con `Authorization: Bearer <token>`
- POST `/api/authorize` { action } con `Authorization: Bearer <token>`

Las contraseñas se guardan con hash usando `bcryptjs`. El login responde con un JWT que se usa para acceder a `/api/profile`.

## Roles y permisos
Roles soportados:
- Personal: lectura
- Jefe de Área: lectura, edición
- Supervisor: lectura, edición
- Gerente: lectura, edición, aprobación
- Director: lectura, edición, aprobación
- Administrador del Sistema: lectura, edición, aprobación, administración

En el registro puedes elegir el rol. La autorización se prueba desde la UI con botones de acciones.
