// wwwroot/js/fileDownload.js
function downloadFile(fileName, byteArray) {
    // Convert the byte array to a Blob
    const blob = new Blob([byteArray], { type: "application/octet-stream" });

    // Create a temporary <a> element to trigger the download
    const link = document.createElement("a");
    link.href = window.URL.createObjectURL(blob);
    link.download = fileName; // Set the file name for the download
    document.body.appendChild(link); // Append the link to the DOM
    link.click(); // Trigger the download

    // Clean up
    document.body.removeChild(link);
    window.URL.revokeObjectURL(link.href);
}