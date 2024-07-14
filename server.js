const express = require('express');
const fileUpload = require('express-fileupload');
const fs = require('fs');
const path = require('path');
const cors = require('cors');

const app = express();
const port = 3000;

app.use(cors());
app.use(fileUpload());
app.use(express.static(path.join(__dirname, 'public')));

app.post('/save-encrypted', (req, res) => {
    if (!req.files || Object.keys(req.files).length === 0) {
        return res.status(400).send('No files were uploaded.');
    }

    let encryptedImage = req.files.file;
    let savePath = path.join(__dirname, 'encrypted_image.bin');

    encryptedImage.mv(savePath, (err) => {
        if (err) return res.status(500).send(err);
        res.send('Encrypted image saved!');
    });
});

app.post('/save-decrypted', (req, res) => {
    if (!req.files || Object.keys(req.files).length === 0) {
        return res.status(400).send('No files were uploaded.');
    }

    let decryptedImage = req.files.file;
    let savePath = path.join(__dirname, 'decrypted_image.jpg');

    decryptedImage.mv(savePath, (err) => {
        if (err) return res.status(500).send(err);
        res.send('Decrypted image saved!');
    });
});

app.post('/save-hash-signature', (req, res) => {
    if (!req.files || Object.keys(req.files).length === 0) {
        return res.status(400).send('No files were uploaded.');
    }

    let hashSignatureFile = req.files.file;
    let savePath = path.join(__dirname, 'hash_and_signature.txt');

    hashSignatureFile.mv(savePath, (err) => {
        if (err) return res.status(500).send(err);
        res.send('Hash and signature file saved!');
    });
});

app.listen(port, () => {
    console.log(`Server is running at http://localhost:${port}`);
});
