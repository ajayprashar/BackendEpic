const fs = require('fs');
const crypto = require('crypto');
const { v4: uuidv4 } = require('uuid');
const jwt = require('jsonwebtoken');
const axios = require('axios');
const Logger = require('./src/utils/Logger');

class JWTManager {
    constructor(config) {
        if (!config.paths || !config.oauth_settings) {
            throw new Error('Configuration missing required paths or oauth_settings section');
        }

        this.config = config;
        this.privateKey = fs.readFileSync(config.paths.private_key, 'utf8');
        this.clientId = config.oauth_settings.client_id;
        this.tokenEndpoint = config.oauth_settings.token_endpoint;
        this.algorithm = config.jwt_settings.jwt_algorithm || 'RS384';
        this.expiryMinutes = parseInt(config.jwt_settings.jwt_expiry_minutes) || 5;
        this.logger = Logger.getInstance(config);
    }

    async getAccessToken() {
        try {
            const logger = Logger.getInstance(this.config);
            
            logger.writeLog('INFO', [
                '',
                'JWT CREATION',
                '------------',
                '• Creating JWT for OAuth 2.0 token request'
            ]);
            
            // Generate JWT with claims
            const currentTime = Math.floor(Date.now() / 1000);
            const expiryTime = currentTime + (this.expiryMinutes * 60);
            
            logger.writeLog('INFO', [
                '',
                'JWT Timestamps:',
                '--------------',
                `• Current Time (iat): ${new Date(currentTime * 1000).toISOString()}`,
                `• Not Before (nbf) : ${new Date(currentTime * 1000).toISOString()}`,
                `• Expiry Time (exp): ${new Date(expiryTime * 1000).toISOString()}`,
                `• Token Validity  : ${this.expiryMinutes} minutes`
            ]);
            
            const claims = {
                iss: this.clientId,
                sub: this.clientId,
                aud: this.tokenEndpoint,
                jti: uuidv4(),
                exp: expiryTime,
                nbf: currentTime,
                iat: currentTime
            };

            logger.writeLog('INFO', [
                '',
                'JWT Claims:',
                '-----------',
                ...Object.entries(claims).map(([key, value]) => 
                    `• ${key}: ${value}`
                )
            ]);

            // Generate JWT
            const publicKey = fs.readFileSync(this.config.paths.public_key, 'utf8');
            const publicKeyId = crypto.createHash('sha1')
                .update(Buffer.from(publicKey.replace(/-----BEGIN (?:PUBLIC KEY|CERTIFICATE)-----|\n|-----END (?:PUBLIC KEY|CERTIFICATE)-----/g, ''), 'base64'))
                .digest('hex')
                .toUpperCase();
            
            const header = {
                alg: this.algorithm,
                typ: 'JWT',
                kid: publicKeyId
            };

            const token = jwt.sign(claims, this.privateKey, {
                algorithm: this.algorithm,
                header: header
            });
            
            logger.writeLog('INFO', [
                '',
                'TOKEN REQUEST',
                '-------------',
                '• Endpoint:',
                `  ${this.tokenEndpoint}`,
                '',
                '• Request Parameters:',
                '  - grant_type: client_credentials',
                '  - client_assertion_type: urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
                '  - client_assertion: [JWT Token]'
            ]);
            
            const response = await axios.post(this.tokenEndpoint, 
                new URLSearchParams({
                    grant_type: this.config.oauth_settings.grant_type,
                    client_assertion_type: this.config.oauth_settings.client_assertion_type,
                    client_assertion: token
                }), 
                {
                    headers: {
                        'Content-Type': 'application/x-www-form-urlencoded'
                    }
                }
            );

            if (!response.data.access_token) {
                throw new Error('No access token received in response');
            }

            logger.writeLog('INFO', [
                '',
                'TOKEN RESPONSE',
                '--------------',
                '• Status Code:',
                `  ${response.status} ${response.statusText}`,
                '',
                '• Response Headers:',
                ...Object.entries(response.headers).map(([key, value]) => 
                    `  ${key}: ${value}`
                ),
                '',
                '• Response Body:',
                ...Object.entries(response.data)
                    .filter(([key]) => key !== 'access_token') // Don't log the actual token
                    .map(([key, value]) => `  ${key}: ${value}`),
                '  access_token: [TOKEN]'
            ]);

            return response.data.access_token;
        } catch (error) {
            const logger = Logger.getInstance(this.config);
            logger.writeLog('ERROR', [
                '',
                'TOKEN REQUEST FAILED',
                '------------------',
                '• Error Message:',
                `  ${error.message}`,
                '',
                '• Request URL:',
                `  ${this.tokenEndpoint}`,
                '',
                '• Response Status:',
                `  ${error.response?.status || 'Unknown'} ${error.response?.statusText || ''}`,
                '',
                '• Response Headers:',
                ...(error.response?.headers ? 
                    Object.entries(error.response.headers).map(([key, value]) => 
                        `  ${key}: ${value}`
                    ) : ['  No headers available']),
                '',
                '• Response Data:',
                error.response?.data ? 
                    JSON.stringify(error.response.data, null, 2)
                        .split('\n')
                        .map(line => `  ${line}`)
                        .join('\n') : 
                    '  No response data'
            ]);
            throw error;
        }
    }
}

module.exports = { JWTManager }; 