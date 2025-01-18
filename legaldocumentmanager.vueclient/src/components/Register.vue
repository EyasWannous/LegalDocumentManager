<template>
  <div class="register-container">
    <h1>Register</h1>
    <form @submit.prevent="register" class="register-form">
      <div class="form-group">
        <label for="fullName">Full Name</label>
        <input id="fullName" v-model="fullName" placeholder="Full Name" required />
      </div>
      <div class="form-group">
        <label for="nationalNumber">National Number</label>
        <input id="nationalNumber" v-model="nationalNumber" placeholder="National Number" required />
      </div>
      <div class="form-group">
        <label for="phoneNumber">Phone Number</label>
        <input id="phoneNumber" v-model="phoneNumber" placeholder="Phone Number" required />
      </div>
      <div class="form-group">
        <label for="birthday">Birthday</label>
        <input id="birthday" v-model="birthday" type="date" required />
      </div>
      <div class="form-group">
        <label for="password">Password</label>
        <input id="password" v-model="password" type="password" placeholder="Password" required />
      </div>
      <div class="form-group">
        <label for="confirmPassword">Confirm Password</label>
        <input
          id="confirmPassword"
          v-model="confirmPassword"
          type="password"
          placeholder="Confirm Password"
          required
        />
      </div>
      <div class="form-group">
        <label for="isGovernmentAccount">
          <input id="isGovernmentAccount" type="checkbox" v-model="isGovernmentAccount" />
          Is Government Account
        </label>
      </div>
      <button type="submit" class="btn-register">Register</button>
    </form>
    <p v-if="error" class="error-message">{{ error }}</p>
  </div>
</template>

<script>
import forge from "node-forge";
import api from "../services/api";

export default {
  data() {
    return {
      fullName: "",
      nationalNumber: "",
      phoneNumber: "",
      birthday: "",
      password: "",
      confirmPassword: "",
      isGovernmentAccount: false,
      error: null,
    };
  },
  methods: {
    async register() {
      try {
        // Generate RSA key pair
        const keys = this.generateKeyPair();
        const publicKey = keys.publicKey;
        const privateKey = keys.privateKey;

        console.log(publicKey);
        console.log(privateKey);

        // Store private key in localStorage
        localStorage.setItem("privateKey", privateKey);
        localStorage.setItem("publicKey", publicKey);


        const cleanedPrivateKey = privateKey
          .replace(/-----BEGIN RSA PRIVATE KEY-----/g, '')
          .replace(/-----END RSA PRIVATE KEY-----/g, '')
          .replace(/\r\n/g, '')
          .replace(/\n/g, '');

        // console.log(cleanedPrivateKey);

        const cleanedPublicKey = publicKey
          .replace(/-----BEGIN PUBLIC KEY-----/g, '')
          .replace(/-----END PUBLIC KEY-----/g, '')
          .replace(/\r\n/g, '')
          .replace(/\n/g, '');


        // Send public key to the server
        const response = await api.post("/Account/Register", {
          fullName: this.fullName,
          nationalNumber: this.nationalNumber,
          phoneNumber: this.phoneNumber,
          birthday: this.birthday,
          password: this.password,
          confirmPassword: this.confirmPassword,
          publicKey: cleanedPublicKey,
          isGovernmentAccount: this.isGovernmentAccount,
        });

        // Store the token and redirect to the dashboard
        localStorage.setItem("token", response.data.token);
        // console.log(response.data.token)

        console.log(response.data.hashedKey)

        const encryptedBytes = forge.util.decode64(response.data.hashedKey);
        console.log("Encrypted Bytes: ", encryptedBytes);

        // Get the private key from localStorage and load it
        const privateKeyPem = localStorage.getItem("privateKey");
        const realPrivateKey = forge.pki.privateKeyFromPem(privateKeyPem);
        console.log("Private key loaded successfully");

        // const decryptedBytes = realPrivateKey.decrypt(encryptedBytes, 'RSA-OAEP');
        // console.log("Decrypted Bytes: ", decryptedBytes);

        // const decryptedKey = forge.util.decodeUtf8(decryptedBytes);
        // console.log("Decrypted Key: ", decryptedKey);

        // localStorage.setItem("key", decryptedKey);
        // console.log("Decrypted key saved to localStorage");

        this.$router.push("/dashboard");
      } catch (err) {
        console.log(err)
        this.error = err.response?.data || "Registration failed";
      }
    },
    generateKeyPair() {
      const keypair = forge.pki.rsa.generateKeyPair({ bits: 2048 });
      const publicKeyPem = forge.pki.publicKeyToPem(keypair.publicKey);
      const privateKeyPem = forge.pki.privateKeyToPem(keypair.privateKey);

      return {
        privateKey: privateKeyPem,
        publicKey: publicKeyPem
      };
    },
  },
};
</script>

<style scoped>
.register-container {
  max-width: 400px;
  margin: 0 auto;
  padding: 20px;
  border: 1px solid #ddd;
  border-radius: 5px;
  box-shadow: 0 2px 5px rgba(0, 0, 0, 0.1);
  background-color: #fff;
}

h1 {
  text-align: center;
  margin-bottom: 20px;
  color: #333;
}

.register-form {
  display: flex;
  flex-direction: column;
}

.form-group {
  margin-bottom: 15px;
}

label {
  display: block;
  font-weight: bold;
  margin-bottom: 5px;
  color: #555;
}

input {
  width: 100%;
  padding: 10px;
  border: 1px solid #ccc;
  border-radius: 4px;
  font-size: 14px;
}

input[type="checkbox"] {
  width: auto;
  margin-right: 5px;
}

.btn-register {
  padding: 10px 20px;
  background-color: #007bff;
  color: white;
  border: none;
  border-radius: 4px;
  font-size: 16px;
  cursor: pointer;
  transition: background-color 0.3s;
}

.btn-register:hover {
  background-color: #0056b3;
}

.error-message {
  margin-top: 10px;
  color: red;
  text-align: center;
}
</style>
