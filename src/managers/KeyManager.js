/**
 * Key Manager Class
 * ===============
 * Handles RSA key loading and management for Epic FHIR API authentication.
 * 
 * Features:
 * - Key loading and verification
 * - Key format validation
 * - Base64 encoding support
 * - X.509 certificate handling
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

class KeyManager {
    constructor(config) {
        this.config = config;
        this.keySize = parseInt(config.rsa_settings.rsa_key_size);
        this.publicEncoding = config.rsa_settings.rsa_public_encoding;
        this.privateKeyPath = config.paths.private_key;
        this.publicKeyPath = config.paths.public_key;
        this.base64PublicKeyPath = config.paths.base64_public_key;
        this.x509CertPath = 'publickey509.pem';
        this.base64CertPath = 'publickey509.b64';
    }

    loadKeys() {
        console.log('Loading RSA keys...');
        try {
            if (!this.keysExist()) {
                throw new Error('Required keys not found. Please ensure private.key and publickey509.pem exist.');
            }

            const privateKey = fs.readFileSync(this.privateKeyPath, 'utf8');
            const publicCert = fs.readFileSync(this.publicKeyPath, 'utf8');

            // Verify the keys are in correct format
            if (!privateKey.includes('-----BEGIN PRIVATE KEY-----')) {
                throw new Error('Private key is not in PKCS#8 format');
            }
            if (!publicCert.includes('-----BEGIN CERTIFICATE-----')) {
                throw new Error('Public key is not in X.509 certificate format');
            }

            if (!this.verifyKeyPair({ privateKey, publicCert })) {
                throw new Error('Key pair verification failed');
            }

            console.log('Key pair loaded and verified successfully');
            return { privateKey, publicKey: publicCert };
        } catch (error) {
            console.error('Error loading keys:', error.message);
            throw error;
        }
    }

    async ensureKeys() {
        console.log('Loading existing keys...');
        return this.loadKeys();
    }

    keysExist() {
        return (
            fs.existsSync(this.privateKeyPath) &&
            fs.existsSync(this.publicKeyPath)
        );
    }

    verifyKeyPair({ privateKey, publicCert }) {
        try {
            const testData = 'test-data';
            const signature = crypto.sign('sha384', Buffer.from(testData), privateKey);
            
            // Extract public key from certificate for verification
            const cert = new crypto.X509Certificate(publicCert);
            const publicKey = cert.publicKey;
            
            return crypto.verify('sha384', Buffer.from(testData), publicKey, signature);
        } catch (error) {
            console.error('Key pair verification failed:', error.message);
            return false;
        }
    }

    getPublicKeyFingerprint() {
        try {
            // Read the X.509 certificate and create X509Certificate object
            const certData = fs.readFileSync(this.publicKeyPath);
            const x509 = new crypto.X509Certificate(certData);
            
            // Calculate fingerprint from the raw certificate data
            const fingerprint = crypto
                .createHash('sha1')
                .update(x509.raw)
                .digest('hex')
                .toUpperCase();
            
            console.log('\nJWT Signing Key Fingerprint:', fingerprint);
            console.log('Formatted fingerprint:', fingerprint.match(/.{2}/g).join(':'));
            
            return fingerprint;
        } catch (error) {
            console.error('Error calculating certificate fingerprint:', error.message);
            return null;
        }
    }

    getBase64Certificate() {
        try {
            // Read the X.509 certificate
            const cert = fs.readFileSync('publickey509.pem');
            // Convert PEM to DER by removing headers and base64 decoding
            const pemContent = cert.toString();
            const base64Cert = pemContent
                .replace('-----BEGIN CERTIFICATE-----', '')
                .replace('-----END CERTIFICATE-----', '')
                .replace(/[\r\n]/g, '');
            // Save to file
            fs.writeFileSync('publickey509.b64', base64Cert);
            console.log('Base64 certificate saved to: publickey509.b64');
            return base64Cert;
        } catch (error) {
            console.error('Error creating base64 certificate:', error.message);
            return null;
        }
    }

    getX509Fingerprint() {
        try {
            const cert = fs.readFileSync(this.x509CertPath);
            const fingerprint = crypto
                .createHash('sha1')
                .update(cert)
                .digest('hex')
                .toUpperCase();
            console.log('\nX.509 Certificate Fingerprint:', fingerprint);
            return fingerprint;
        } catch (error) {
            console.error('Error calculating X.509 certificate fingerprint:', error.message);
            return null;
        }
    }
}

module.exports = KeyManager; 