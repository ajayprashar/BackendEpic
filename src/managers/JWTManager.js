/**
 * JWT Manager Class
 * ===============
 * Handles JWT creation and signing for Epic FHIR API authentication.
 * 
 * Features:
 * - JWT generation with required claims
 * - RSA signing using private key
 * - Token expiration management
 * - Robust error handling for missing keys
 * - JTI uniqueness tracking
 * 
 * Example Usage:
 * ```javascript
 * const jwtManager = new JWTManager(config, keyManager);
 * const jwt = await jwtManager.generateJWT();
 * ```
 * 
 * Epic JWT Requirements:
 * https://fhir.epic.com/Documentation?docId=jwt
 */

const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');

class JWTManager {
    constructor(config, keyManager) {
        this.config = config;
        this.keyManager = keyManager;
        this.algorithm = config.jwt_settings.jwt_algorithm;
        this.expiryMinutes = parseInt(config.jwt_settings.jwt_expiry_minutes);
        // Keep track of used JTIs with timestamps for cleanup
        this.usedJtis = new Map();
        // Cleanup interval in milliseconds (e.g., every hour)
        this.cleanupInterval = 60 * 60 * 1000;
        this.startJtiCleanup();
    }

    generateUniqueJti() {
        let jti;
        do {
            jti = uuidv4();
        } while (this.usedJtis.has(jti));
        
        // Store the JTI with current timestamp
        this.usedJtis.set(jti, Date.now());
        return jti;
    }

    startJtiCleanup() {
        setInterval(() => {
            const now = Date.now();
            // Remove JTIs older than twice the token expiry time
            const expiryMs = this.expiryMinutes * 60 * 1000 * 2;
            
            for (const [jti, timestamp] of this.usedJtis.entries()) {
                if (now - timestamp > expiryMs) {
                    this.usedJtis.delete(jti);
                }
            }
        }, this.cleanupInterval);
    }

    async generateJWT() {
        console.log('Generating JWT...');
        try {
            // Log token request destinations
            console.log('\nToken Request Destinations:');
            console.log('Issuer (iss):', this.config.oauth_settings.client_id);
            console.log('Subject (sub):', this.config.oauth_settings.client_id);
            console.log('Audience (aud):', this.config.oauth_settings.token_endpoint);
            
            // Ensure keys exist and are valid
            let keys;
            try {
                keys = await this.keyManager.ensureKeys();
                console.log('Successfully loaded RSA keys');
            } catch (keyError) {
                console.error('Failed to load or generate RSA keys:', keyError.message);
                throw new Error(`JWT generation failed: Unable to access RSA keys - ${keyError.message}`);
            }
            
            if (!keys || !keys.privateKey || !keys.publicKey) {
                throw new Error('JWT generation failed: Invalid or missing RSA keys');
            }

            console.log('\nPrivate Key (Signing Key) Status: Present');
            console.log('Public Key Status: Present');
            console.log('Base64 Public Key Status: Present');
            
            // Only log key contents if explicitly requested for debugging
            if (process.env.DEBUG_JWT === 'true') {
                console.log('\nPrivate Key (Signing Key):\n', keys.privateKey);
                console.log('\nPublic Key:\n', keys.publicKey);
                console.log('\nBase64 Public Key:\n', keys.base64PublicKey);
            }
            
            const now = Math.floor(Date.now() / 1000);
            const exp = now + (this.expiryMinutes * 60);
            
            const claims = {
                iss: this.config.oauth_settings.client_id,
                sub: this.config.oauth_settings.client_id,
                aud: this.config.oauth_settings.token_endpoint,
                jti: this.generateUniqueJti(),
                iat: now,
                exp: exp
            };

            console.log('\nJWT Claims:\n', claims);

            const token = jwt.sign(claims, keys.privateKey, {
                algorithm: this.algorithm
            });

            return token;
        } catch (error) {
            console.error('Error in JWT generation process:', error.message);
            throw error;
        }
    }

    verifyJWT(token) {
        try {
            let keys;
            try {
                keys = this.keyManager.loadKeys();
                console.log('Successfully loaded keys for JWT verification');
            } catch (keyError) {
                console.error('Failed to load keys for JWT verification:', keyError.message);
                throw new Error(`JWT verification failed: Unable to access RSA keys - ${keyError.message}`);
            }

            if (!keys || !keys.publicKey) {
                throw new Error('JWT verification failed: Missing public key');
            }

            const decoded = jwt.verify(token, keys.publicKey, {
                algorithms: [this.algorithm]
            });
            return decoded;
        } catch (error) {
            console.error('Error in JWT verification process:', error.message);
            throw error;
        }
    }
}

module.exports = JWTManager; 