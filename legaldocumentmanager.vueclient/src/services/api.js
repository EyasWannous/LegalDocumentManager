// src/services/api.js
import axios from 'axios';

const api = axios.create({
  baseURL: 'https://localhost:7011/api', // Replace with your API base URL
});

api.interceptors.request.use((config) => {
  const token = localStorage.getItem('token');
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

export default api;
