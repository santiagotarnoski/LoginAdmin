// API Configuration
const API_URL = window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1'
  ? 'http://localhost:3000'
  : 'https://tu-backend.onrender.com'; // Cambiarás esto después del deploy

const $ = (sel) => document.querySelector(sel);

// ... resto del código igual hasta la función api()

async function api(path, opts={}){
  const token = getToken();
  const headers = { 'Content-Type': 'application/json', ...(opts.headers||{}) };
  if (token) headers['Authorization'] = `Bearer ${token}`;
  const res = await fetch(API_URL + path, { ...opts, headers });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw Object.assign(new Error(data.error||'Error'), { status: res.status, data });
  return data;
}
