let rsaKeyPairPSS;
let rsaKeyPairOAEP;
let symmetricKeys = { k1: null, k2: null, k3: null };
let encryptedSymmetricKeys = { k1: null, k2: null };
let messageHash;
let signature;
let lastEncryptedBlob;
let lastDecryptedBlob;

function bufferToHex(buffer) {
    return Array.prototype.map.call(new Uint8Array(buffer), x => ('00' + x.toString(16)).slice(-2)).join('');
}

function hexToBuffer(hex) {
    let typedArray = new Uint8Array(hex.match(/[\da-f]{2}/gi).map(h => parseInt(h, 16)));
    return typedArray.buffer;
}

async function generateRSAKeys() {
    try {
        rsaKeyPairPSS = await window.crypto.subtle.generateKey(
            { name: "RSA-PSS", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
            true, ["sign", "verify"]
        );

        rsaKeyPairOAEP = await window.crypto.subtle.generateKey(
            { name: "RSA-OAEP", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
            true, ["encrypt", "decrypt"]
        );

        const publicKeyPSS = await window.crypto.subtle.exportKey("spki", rsaKeyPairPSS.publicKey);
        const privateKeyPSS = await window.crypto.subtle.exportKey("pkcs8", rsaKeyPairPSS.privateKey);
        const publicKeyOAEP = await window.crypto.subtle.exportKey("spki", rsaKeyPairOAEP.publicKey);
        const privateKeyOAEP = await window.crypto.subtle.exportKey("pkcs8", rsaKeyPairOAEP.privateKey);

        document.getElementById('rsa-keys-output').innerText = `RSA-PSS Public Key:\n${bufferToHex(new Uint8Array(publicKeyPSS))}\n\nRSA-PSS Private Key:\n${bufferToHex(new Uint8Array(privateKeyPSS))}\n\nRSA-OAEP Public Key:\n${bufferToHex(new Uint8Array(publicKeyOAEP))}\n\nRSA-OAEP Private Key:\n${bufferToHex(new Uint8Array(privateKeyOAEP))}`;
    } catch (error) {
        console.error("Error generating RSA keys:", error);
    }
}

async function generateSymmetricKeys() {
    try {
        // Generate a 128-bit AES key for CBC mode
        symmetricKeys.k1 = await window.crypto.subtle.generateKey(
            { name: "AES-CBC", length: 128 },
            true,
            ["encrypt", "decrypt"]
        );

        // Generate a 256-bit AES key for CBC mode
        symmetricKeys.k2 = await window.crypto.subtle.generateKey(
            { name: "AES-CBC", length: 256 },
            true,
            ["encrypt", "decrypt"]
        );

        // Generate a 256-bit AES key for CTR mode
        symmetricKeys.k3 = await window.crypto.subtle.generateKey(
            { name: "AES-CTR", length: 256 },
            true,
            ["encrypt", "decrypt"]
        );

        const k1Exported = await window.crypto.subtle.exportKey("raw", symmetricKeys.k1);
        const k2Exported = await window.crypto.subtle.exportKey("raw", symmetricKeys.k2);
        const k3Exported = await window.crypto.subtle.exportKey("raw", symmetricKeys.k3);

        document.getElementById('symmetric-keys-output').innerText = `Generated Symmetric Keys:\nK1 (AES-CBC-128): ${bufferToHex(new Uint8Array(k1Exported))}\nK2 (AES-CBC-256): ${bufferToHex(new Uint8Array(k2Exported))}\nK3 (AES-CTR-256): ${bufferToHex(new Uint8Array(k3Exported))}`;
    } catch (error) {
        console.error("Error generating symmetric keys:", error);
    }
}

async function encryptSymmetricKeys() {
    try {
        const k1Exported = await window.crypto.subtle.exportKey("raw", symmetricKeys.k1);
        const k2Exported = await window.crypto.subtle.exportKey("raw", symmetricKeys.k2);

        encryptedSymmetricKeys.k1 = await window.crypto.subtle.encrypt({ name: "RSA-OAEP" }, rsaKeyPairOAEP.publicKey, k1Exported);
        encryptedSymmetricKeys.k2 = await window.crypto.subtle.encrypt({ name: "RSA-OAEP" }, rsaKeyPairOAEP.publicKey, k2Exported);

        document.getElementById('encrypted-symmetric-keys-output').innerText = `Encrypted Symmetric Keys:\nEncrypted K1: ${bufferToHex(new Uint8Array(encryptedSymmetricKeys.k1))}\nEncrypted K2: ${bufferToHex(new Uint8Array(encryptedSymmetricKeys.k2))}`;
    } catch (error) {
        console.error("Error encrypting symmetric keys:", error);
    }
}

async function decryptSymmetricKeys() {
    try {
        const decryptedK1 = await window.crypto.subtle.decrypt({ name: "RSA-OAEP" }, rsaKeyPairOAEP.privateKey, encryptedSymmetricKeys.k1);
        const decryptedK2 = await window.crypto.subtle.decrypt({ name: "RSA-OAEP" }, rsaKeyPairOAEP.privateKey, encryptedSymmetricKeys.k2);

        symmetricKeys.k1 = await window.crypto.subtle.importKey("raw", decryptedK1, { name: "AES-CBC" }, true, ["encrypt", "decrypt"]);
        symmetricKeys.k2 = await window.crypto.subtle.importKey("raw", decryptedK2, { name: "AES-CBC" }, true, ["encrypt", "decrypt"]);

        document.getElementById('decrypted-symmetric-keys-output').innerText = `Decrypted Symmetric Keys:\nDecrypted K1: ${bufferToHex(new Uint8Array(decryptedK1))}\nDecrypted K2: ${bufferToHex(new Uint8Array(decryptedK2))}`;
    } catch (error) {
        console.error("Error decrypting symmetric keys:", error);
    }
}

async function signMessage() {
    try {
        let message = document.getElementById('message').value;
        let encoder = new TextEncoder();
        let data = encoder.encode(message);

        messageHash = await window.crypto.subtle.digest("SHA-256", data);

        signature = await window.crypto.subtle.sign({ name: "RSA-PSS", saltLength: 32 }, rsaKeyPairPSS.privateKey, messageHash);

        const hashHex = bufferToHex(new Uint8Array(messageHash));
        const signatureHex = bufferToHex(new Uint8Array(signature));

        document.getElementById('signature-output').innerText = `Message:\n${message}\n\nSHA-256 Hash: ${hashHex}\n\nDigital Signature: ${signatureHex}`;

        saveToServer("hash_and_signature.txt", `Message:\n${message}\n\nSHA-256 Hash: ${hashHex}\n\nDigital Signature: ${signatureHex}`);
    } catch (error) {
        console.error("Error signing message:", error);
    }
}

async function verifySignature() {
    try {
        let message = document.getElementById('message').value;
        let encoder = new TextEncoder();
        let data = encoder.encode(message);
        let hash = await window.crypto.subtle.digest("SHA-256", data);

        let isValid = await window.crypto.subtle.verify({ name: "RSA-PSS", saltLength: 32 }, rsaKeyPairPSS.publicKey, signature, hash);
        document.getElementById('verification-output').innerText = `Digital signature verification: ${isValid}\n\nIf the digital signature is verified, it indicates that the message was indeed signed by the private key holder and the message has not been altered.`;
    } catch (error) {
        console.error("Error verifying signature:", error);
    }
}

function previewImage() {
    const imageFile = document.getElementById('image-file').files[0];
    if (imageFile) {
        const reader = new FileReader();
        reader.onload = function (event) {
            document.getElementById('image-preview').src = event.target.result;
        };
        reader.readAsDataURL(imageFile);
    }
}

async function processImage(encryptMode, decryptMode, key, fileName) {
    console.log(`Starting encryption using ${encryptMode} mode.`);
    const imageFile = document.getElementById('image-file').files[0];
    if (!imageFile) {
        document.getElementById('image-processing-output').innerText = 'No file selected.';
        return;
    }

    const reader = new FileReader();
    reader.onload = async function (event) {
        const imageData = event.target.result;
        const originalSize = imageData.byteLength;

        try {
            const ivOrNonce = window.crypto.getRandomValues(new Uint8Array(16));
            const startTime = performance.now();
            let cipher;
            if (encryptMode === 'AES-CTR') {
                cipher = await window.crypto.subtle.encrypt(
                    { name: encryptMode, counter: ivOrNonce, length: 128 },
                    key,
                    imageData
                );
            } else {
                cipher = await window.crypto.subtle.encrypt(
                    { name: encryptMode, iv: ivOrNonce },
                    key,
                    imageData
                );
            }
            const endTime = performance.now();
            const encryptionTime = endTime - startTime;
            const encryptedSize = cipher.byteLength;

            console.log(`Encryption completed in ${encryptionTime} ms. Encrypted size: ${encryptedSize} bytes.`);

            lastEncryptedBlob = new Blob([cipher]);

            console.log(`Starting decryption using ${decryptMode} mode.`);
            let decipher;
            if (decryptMode === 'AES-CTR') {
                decipher = await window.crypto.subtle.decrypt(
                    { name: decryptMode, counter: ivOrNonce, length: 128 },
                    key,
                    cipher
                );
            } else {
                decipher = await window.crypto.subtle.decrypt(
                    { name: decryptMode, iv: ivOrNonce },
                    key,
                    cipher
                );
            }

            const decryptedSize = decipher.byteLength;

            console.log(`Decryption completed. Decrypted size: ${decryptedSize} bytes.`);

            lastDecryptedBlob = new Blob([decipher]);
            const decryptedUrl = URL.createObjectURL(lastDecryptedBlob);
            const decryptedImage = new Image();
            decryptedImage.src = decryptedUrl;
            decryptedImage.onload = () => URL.revokeObjectURL(decryptedUrl);

            document.getElementById('image-processing-output').innerText = `Image encrypted and decrypted successfully.\nOriginal size: ${originalSize} bytes\nEncrypted size: ${encryptedSize} bytes\nDecrypted size: ${decryptedSize} bytes\nEncryption time: ${encryptionTime} ms`;
            document.getElementById('decrypted-image-output').innerHTML = '<p>Decrypted Image:</p>';
            document.getElementById('decrypted-image-output').appendChild(decryptedImage);

            saveToServer(lastEncryptedBlob, `encrypted_${fileName}`);
            saveToServer(lastDecryptedBlob, `decrypted_${fileName}`);
        } catch (error) {
            document.getElementById('image-processing-output').innerText = `Error processing image: ${error.message}`;
            console.error("Error processing image:", error);
        }
    };

    reader.readAsArrayBuffer(imageFile);
}

function saveToServer(blob, fileName) {
    const formData = new FormData();
    formData.append('file', blob, `${fileName}.${fileName.startsWith('encrypted') ? 'bin' : 'jpg'}`);

    fetch(`http://localhost:3000/save-${fileName.startsWith('encrypted') ? 'encrypted' : 'decrypted'}`, {
        method: 'POST',
        body: formData
    })
    .then(response => response.text())
    .then(data => {
        console.log(`${fileName.charAt(0).toUpperCase() + fileName.slice(1)} image saved to server:`, data);
    })
    .catch(error => {
        console.error(`Error saving ${fileName} image:`, error);
    });
}

function saveToServer(filename, content) {
    const blob = new Blob([content], { type: 'text/plain' });
    const formData = new FormData();
    formData.append('file', blob, filename);

    fetch(`http://localhost:3000/save-hash-signature`, {
        method: 'POST',
        body: formData
    })
    .then(response => response.text())
    .then(data => {
        console.log(`${filename} saved to server:`, data);
    })
    .catch(error => {
        console.error(`Error saving ${filename}:`, error);
    });
}

document.getElementById('encrypt-image-cbc-128').onclick = function () {
    processImage('AES-CBC', 'AES-CBC', symmetricKeys.k1, 'AES-CBC-128');
};

document.getElementById('encrypt-image-cbc-256').onclick = function () {
    processImage('AES-CBC', 'AES-CBC', symmetricKeys.k2, 'AES-CBC-256');
};

document.getElementById('encrypt-image-ctr-256').onclick = function () {
    processImage('AES-CTR', 'AES-CTR', symmetricKeys.k3, 'AES-CTR-256');
};
