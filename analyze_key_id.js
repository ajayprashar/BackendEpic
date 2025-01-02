const fs = require('fs');
const crypto = require('crypto');

function calculateThumbprints(certPath) {
    console.log('Analyzing certificate/key:', certPath);
    console.log('=====================================');

    try {
        // Read the file content
        const fileContent = fs.readFileSync(certPath, 'utf8');
        
        // Method 1: Raw file content SHA-1
        console.log('\nMethod 1: Raw file content SHA-1');
        const hash1 = crypto.createHash('sha1');
        hash1.update(fileContent);
        console.log('Result:', hash1.digest('hex').toUpperCase());

        // Method 2: Base64 decoded content SHA-1
        console.log('\nMethod 2: Base64 decoded content SHA-1');
        const cleanContent = fileContent
            .replace(/-----BEGIN CERTIFICATE-----/, '')
            .replace(/-----END CERTIFICATE-----/, '')
            .replace(/-----BEGIN PUBLIC KEY-----/, '')
            .replace(/-----END PUBLIC KEY-----/, '')
            .replace(/\n/g, '');
        const decodedContent = Buffer.from(cleanContent, 'base64');
        const hash2 = crypto.createHash('sha1');
        hash2.update(decodedContent);
        console.log('Result:', hash2.digest('hex').toUpperCase());

        // Method 3: DER encoded SHA-1 (Epic's likely method)
        console.log('\nMethod 3: DER encoded SHA-1');
        const derBuffer = Buffer.from(cleanContent, 'base64');
        const hash3 = crypto.createHash('sha1');
        hash3.update(derBuffer);
        console.log('Result:', hash3.digest('hex').toUpperCase());

    } catch (error) {
        console.error('Error analyzing file:', error.message);
    }
}

// Test with both files
console.log('\nAnalyzing public key files to find Epic\'s thumbprint calculation method...');
console.log('Target thumbprint: A9449062942DEBF66B8B48B131AC47C9189583F4\n');

calculateThumbprints('publickey509.pem');
calculateThumbprints('publickey509.b64'); 