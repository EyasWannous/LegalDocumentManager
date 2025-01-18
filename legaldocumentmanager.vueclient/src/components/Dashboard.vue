<template>
  <div>
    <h1>Dashboard</h1>

    <!-- Upload File Section -->
    <h2>Upload File</h2>
    <form @submit.prevent="uploadFile">
      <input type="file" ref="fileInput" required />
      <button type="submit">Upload File</button>
    </form>

    <!-- Attachments List Section -->
    <h2>Attachments</h2>
    <div v-if="attachments.length">
      <ul>
        <li v-for="attachment in attachments" :key="attachment.id">
          <div>
            <span>{{ attachment.fileName }}</span>
            <button @click="downloadFile(attachment.id)">Download</button>
            <button @click="deleteAttachment(attachment.id)">Delete</button>
            <button @click="getSignature(attachment.id)">Get Signature</button>
          </div>
        </li>
      </ul>
    </div>
    <div v-else>
      <p>No attachments found.</p>
    </div>

  </div>
</template>

<script>
import api from '../services/api'; // Assuming you have api.js for Axios

export default {
  data() {
    return {
      attachments: [], // Store list of attachments
      errorMessage: null,
    };
  },
  mounted() {
    this.getAttachments(); // Fetch attachments when the page loads
  },
  methods: {
    // Fetch all attachments
    async getAttachments() {
      try {
        const response = await api.get('/Attachment/List');
        this.attachments = response.data;
      } catch (err) {
        this.errorMessage = 'Error fetching attachments: ' + (err.response?.data || err.message);
      }
    },

    // Upload file (you will need the file's content encrypted as per your API)
    async uploadFile() {
      const fileInput = this.$refs.fileInput;
      const file = fileInput.files[0];
      const reader = new FileReader();

      reader.onloadend = async () => {
        try {
          const encryptedFile = await this.encryptFile(reader.result);
          const fileName = file.name;

          const response = await api.post(`/Attachment/Upload/${encryptedFile}/${fileName}`);
          this.getAttachments(); // Refresh the attachment list
          alert('File uploaded successfully');
        } catch (err) {
          alert('Error uploading file: ' + err.message);
        }
      };

      reader.readAsDataURL(file);
    },

    // Encrypt the file content (you may have your own encryption logic here)
    async encryptFile(fileContent) {
      // Assume you have a method to encrypt the file content here.
      const encryptedFile = await someEncryptionFunction(fileContent);
      return encryptedFile;
    },

    // Download file
    async downloadFile(attachmentId) {
      try {
        const response = await api.get(`/Attachment/Download/${attachmentId}`, { responseType: 'blob' });
        const url = window.URL.createObjectURL(new Blob([response.data]));
        const link = document.createElement('a');
        link.href = url;
        link.setAttribute('download', 'file');
        document.body.appendChild(link);
        link.click();
      } catch (err) {
        alert('Error downloading file: ' + err.message);
      }
    },

    // Get file signature
    async getSignature(attachmentId) {
      try {
        const response = await api.get(`/Attachment/GetSignature/${attachmentId}`);
        alert('Signature: ' + response.data);
      } catch (err) {
        alert('Error fetching signature: ' + err.message);
      }
    },

    // Delete attachment
    async deleteAttachment(attachmentId) {
      if (confirm('Are you sure you want to delete this attachment?')) {
        try {
          await api.post(`/Attachment/Delete/${attachmentId}`);
          this.getAttachments(); // Refresh the attachment list
          alert('Attachment deleted successfully');
        } catch (err) {
          alert('Error deleting attachment: ' + err.message);
        }
      }
    },
  },
};
</script>

<style scoped>
h1 {
  text-align: center;
}
h2 {
  margin-top: 20px;
}
ul {
  list-style-type: none;
  padding: 0;
}
li {
  margin-bottom: 10px;
}
button {
  margin-left: 10px;
}
</style>
