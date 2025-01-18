// import './assets/main.css'

// import { createApp } from 'vue'
// import App from './App.vue'

// createApp(App).mount('#app')

// src/main.js
import { createApp } from 'vue';
import App from './App.vue';
import router from './router';
import './assets/styles.css'; // Add global styles if needed

createApp(App).use(router).mount('#app');
