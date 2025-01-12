const https = require('https');

class HttpClient {
    static async request(url, options = {}) {
        return new Promise((resolve, reject) => {
            const urlObj = new URL(url);
            
            // Add query parameters if they exist
            if (options.params) {
                Object.entries(options.params).forEach(([key, value]) => {
                    urlObj.searchParams.append(key, value);
                });
            }

            const requestOptions = {
                method: options.method || 'GET',
                headers: options.headers || {},
                ...options
            };

            // Remove params from options as it's already been processed
            delete requestOptions.params;

            const req = https.request(urlObj, requestOptions, (res) => {
                let data = '';
                res.on('data', (chunk) => data += chunk);
                res.on('end', () => {
                    const response = {
                        status: res.statusCode,
                        headers: res.headers,
                        data: data
                    };

                    if (data && data.length > 0) {
                        try {
                            response.data = JSON.parse(data);
                        } catch (e) {
                            // If it's not JSON, keep the raw data
                        }
                    }

                    if (res.statusCode >= 200 && res.statusCode < 300) {
                        resolve(response);
                    } else {
                        reject(new Error(`Request failed with status ${res.statusCode}`));
                    }
                });
            });

            req.on('error', reject);

            if (options.data) {
                req.write(typeof options.data === 'string' ? options.data : JSON.stringify(options.data));
            }

            req.end();
        });
    }

    static async get(url, options = {}) {
        return this.request(url, { ...options, method: 'GET' });
    }

    static async post(url, data, options = {}) {
        return this.request(url, { ...options, method: 'POST', data });
    }
}

module.exports = HttpClient; 