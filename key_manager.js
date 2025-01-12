const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

class KeyManager {
    constructor(config) {
        if (!config.paths) {
            throw new Error('Configuration missing required paths section');
        }

        this.privateKeyPath = path.resolve(config.paths.private_key);
        this.publicKeyPath = path.resolve(config.paths.public_key);
        this.base64PublicKeyPath = path.resolve(config.paths.base64_public_key);

        this.rsaKeySize = parseInt(config.rsa_settings.rsa_key_size) || 2048;
        this.rsaPublicEncoding = config.rsa_settings.rsa_public_encoding || 'spki';
        this.rsaPrivateEncoding = config.rsa_settings.rsa_private_encoding || 'pkcs8';
    }

    async generateKeyPair() {
        if (!this.privateKeyPath) {
            throw new Error('Private key path is not defined in configuration');
        }

        const dir = path.dirname(this.privateKeyPath);
        if (!fs.existsSync(dir)) {
            fs.mkdirSync(dir, { recursive: true });
        }

        if (!fs.existsSync(this.privateKeyPath)) {
            const keyPair = crypto.generateKeyPairSync('rsa', {
                modulusLength: this.rsaKeySize,
                publicKeyEncoding: {
                    type: this.rsaPublicEncoding,
                    format: 'pem'
                },
                privateKeyEncoding: {
                    type: this.rsaPrivateEncoding,
                    format: 'pem'
                }
            });

            fs.writeFileSync(this.privateKeyPath, keyPair.privateKey);
            fs.writeFileSync(this.publicKeyPath, keyPair.publicKey);
            
            const base64PublicKey = Buffer.from(keyPair.publicKey).toString('base64');
            fs.writeFileSync(this.base64PublicKeyPath, base64PublicKey);
            
            console.log('Key pair generated successfully');
        } else {
            console.log('Using existing key pair');
        }
    }
}

module.exports = { KeyManager }; 