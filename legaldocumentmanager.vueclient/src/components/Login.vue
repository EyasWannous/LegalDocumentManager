<template>
    <div>
      <h1>Login</h1>
      <form @submit.prevent="login">
        <input v-model="nationalNumber" placeholder="National Number" required />
        <input v-model="password" type="password" placeholder="Password" required />
        <input v-model="publicKey" placeholder="Public Key" required />
        <button type="submit">Login</button>
      </form>
      <p v-if="error">{{ error }}</p>
    </div>
  </template>

  <script>
  import api from '../services/api';

  export default {
    data() {
      return {
        nationalNumber: '',
        password: '',
        publicKey: '',
        error: null,
      };
    },
    methods: {
      async login() {
        try {
          const response = await api.post('/Account/Login', {
            nationalNumber: this.nationalNumber,
            password: this.password,
            publicKey: this.publicKey,
          });
          localStorage.setItem('token', response.data.token);
          this.$router.push('/dashboard'); // Navigate to dashboard after login
        } catch (err) {
          this.error = err.response?.data || 'Login failed';
        }
      },
    },
  };
  </script>
