const fs = require('fs');
const path = require('path');
const axios = require('axios');
const { promisify } = require('util');
const sleep = promisify(setTimeout);

// Define standard reference ranges
const VITAL_SIGNS_RANGES = {
    'BP': {
        systolic: { min: 90, max: 140 },
        diastolic: { min: 60, max: 90 },
        unit: 'mmHg'
    },
    'Temp': { 
        min: 36.5, 
        max: 37.5,
        unit: '°C'
    },
    'Pulse': { 
        min: 60, 
        max: 100,
        unit: 'bpm'
    }
};

// LOINC code mapping for vital signs
const VITAL_SIGNS_CODE_MAP = {
    '55284-4': { type: 'BP', description: 'Blood pressure systolic and diastolic' },
    '85354-9': { type: 'BP', description: 'Blood pressure panel' },
    '8480-6':  { type: 'BP', description: 'Systolic blood pressure' },
    '8462-4':  { type: 'BP', description: 'Diastolic blood pressure' },
    '8310-5':  { type: 'Temp', description: 'Body temperature' },
    '8867-4':  { type: 'Pulse', description: 'Heart rate' }
};

class FHIRQueryClient {
    constructor(config, logger) {
        this.config = config;
        this.logger = logger;
        this.exportDir = path.join(this.config.paths.epic_data_export_folder);
        if (!fs.existsSync(this.exportDir)) {
            fs.mkdirSync(this.exportDir, { recursive: true });
        }
    }

    getObservationType(observation) {
        // Try to identify type from code.text
        if (observation.code?.text && ['BP', 'Temp', 'Pulse'].includes(observation.code.text)) {
            return observation.code.text;
        }

        // Search coding for known codes
        const codingArray = observation.code?.coding || [];
        for (const coding of codingArray) {
            const mappedCode = VITAL_SIGNS_CODE_MAP[coding.code];
            if (mappedCode) {
                return mappedCode.type;
            }
        }

        return observation.code?.coding?.[0]?.display || 'Unknown Type';
    }

    getObservationDate(observation) {
        const dateFields = [
            'effectiveDateTime',
            'effectivePeriod.start',
            'effectiveInstant',
            'issued',
            'meta.lastUpdated',
            'date'
        ];

        for (const field of dateFields) {
            const value = field.split('.').reduce((obj, key) => obj?.[key], observation);
            if (value) {
                try {
                    const date = new Date(value);
                    if (!isNaN(date)) {
                        return date.toISOString().split('T')[0];
                    }
                } catch (error) {
                    continue;
                }
            }
        }

        return 'No date';
    }

    async analyzeObservations(observations) {
        const patientStats = {};

        for (const obs of observations) {
            try {
                if (obs.resourceType !== 'Observation') continue;

                const patientId = obs.subject?.reference?.split('/')[1];
                const patientName = obs.subject?.display || 'Unknown Patient';
                
                if (!patientId) continue;

                // Initialize patient stats
                if (!patientStats[patientId]) {
                    patientStats[patientId] = {
                        name: patientName,
                        normalCount: 0,
                        abnormalCount: 0,
                        normalObservations: [],
                        abnormalReadings: []
                    };
                }

                const observationType = this.getObservationType(obs);
                const formattedDate = this.getObservationDate(obs);

                // Handle BP observations
                if (observationType === 'BP') {
                    const systolicComponent = obs.component?.find(comp =>
                        comp.code?.coding?.some(coding => coding.code === '8480-6')
                    );
                    const diastolicComponent = obs.component?.find(comp =>
                        comp.code?.coding?.some(coding => coding.code === '8462-4')
                    );

                    if (systolicComponent?.valueQuantity?.value && diastolicComponent?.valueQuantity?.value) {
                        const systolic = systolicComponent.valueQuantity.value;
                        const diastolic = diastolicComponent.valueQuantity.value;
                        const ranges = VITAL_SIGNS_RANGES.BP;
                        
                        const isAbnormal = 
                            systolic < ranges.systolic.min || 
                            systolic > ranges.systolic.max ||
                            diastolic < ranges.diastolic.min || 
                            diastolic > ranges.diastolic.max;

                        const record = {
                            id: obs.id,
                            type: 'Blood Pressure',
                            value: `${systolic}/${diastolic} ${ranges.unit}`,
                            referenceRange: `${ranges.systolic.min}-${ranges.systolic.max}/${ranges.diastolic.min}-${ranges.diastolic.max} ${ranges.unit}`,
                            status: isAbnormal ? 'ABNORMAL' : 'NORMAL',
                            date: formattedDate
                        };

                        if (isAbnormal) {
                            patientStats[patientId].abnormalCount++;
                            patientStats[patientId].abnormalReadings.push(record);
                        } else {
                            patientStats[patientId].normalCount++;
                            patientStats[patientId].normalObservations.push(record);
                        }
                    }
                    continue;
                }

                // Handle other vital signs
                if (obs.valueQuantity) {
                    const value = obs.valueQuantity.value;
                    const unit = obs.valueQuantity.unit;
                    const range = VITAL_SIGNS_RANGES[observationType];

                    if (range) {
                        const isAbnormal = value < range.min || value > range.max;
                        const record = {
                            id: obs.id,
                            type: observationType,
                            value: `${value} ${unit || range.unit}`,
                            referenceRange: `${range.min}-${range.max} ${range.unit}`,
                            status: isAbnormal ? 'ABNORMAL' : 'NORMAL',
                            date: formattedDate
                        };

                        if (isAbnormal) {
                            patientStats[patientId].abnormalCount++;
                            patientStats[patientId].abnormalReadings.push(record);
                        } else {
                            patientStats[patientId].normalCount++;
                            patientStats[patientId].normalObservations.push(record);
                        }
                    }
                }
            } catch (error) {
                this.logger.writeLog('ERROR', [
                    `Error analyzing observation ${obs?.id || 'unknown'}:`,
                    error.message
                ], console.error);
            }
        }

        return patientStats;
    }

    generateObservationReport(patientStats) {
        let report = '\n=== Observation Analysis Report ===\n\n';

        // Add reference ranges information
        report += 'Reference Ranges:\n';
        report += '-----------------\n';
        report += 'Blood Pressure (BP):\n';
        report += `• Normal Systolic: ${VITAL_SIGNS_RANGES.BP.systolic.min}-${VITAL_SIGNS_RANGES.BP.systolic.max} ${VITAL_SIGNS_RANGES.BP.unit}\n`;
        report += `• Normal Diastolic: ${VITAL_SIGNS_RANGES.BP.diastolic.min}-${VITAL_SIGNS_RANGES.BP.diastolic.max} ${VITAL_SIGNS_RANGES.BP.unit}\n\n`;

        // Calculate totals
        const totals = Object.values(patientStats).reduce(
            (acc, stats) => ({
                normal: acc.normal + stats.normalCount,
                abnormal: acc.abnormal + stats.abnormalCount
            }),
            { normal: 0, abnormal: 0 }
        );

        // Add summary
        report += 'Summary:\n';
        report += '--------\n';
        report += `Total Observations: ${totals.normal + totals.abnormal}\n`;
        report += `Normal Readings: ${totals.normal}\n`;
        report += `Abnormal Readings: ${totals.abnormal}\n\n`;

        // Add detailed observations
        report += 'Detailed Observations:\n';
        report += '---------------------\n';
        report += 'Date | Patient | Type | Value | Reference Range | Status\n';
        report += '-----|---------|------|-------|-----------------|--------\n';

        Object.entries(patientStats).forEach(([patientId, stats]) => {
            const allObservations = [
                ...stats.normalObservations,
                ...stats.abnormalReadings
            ].sort((a, b) => new Date(a.date) - new Date(b.date));

            allObservations.forEach(obs => {
                report += `${obs.date} | ${stats.name} | ${obs.type} | ${obs.value} | ${obs.referenceRange} | ${obs.status}\n`;
            });
        });

        return report;
    }

    async initiateGroupExport(accessToken, resourceTypes = []) {
        let url;
        try {
            const groupId = 'e3iabhmS8rsueyz7vaimuiaSmfGvi.QwjVXJANlPOgR83';
            url = `${this.config.epic_settings.epic_endpoint}Group/${groupId}/$export`;
            
            // Add _type parameter if resource types are specified
            if (resourceTypes.length > 0) {
                const typeParam = resourceTypes.join(',').toLowerCase();
                url += `?_type=${typeParam}`;
            }

            this.logger.writeLog('INFO', [
                'BULK EXPORT REQUEST DETAILS',
                '------------------------',
                '• Request URL:',
                `  ${url}`,
                '',
                '• Request Headers:',
                '  Authorization: Bearer [TOKEN]',
                '  Accept: application/fhir+json',
                '  Prefer: respond-async',
                '',
                '• Request Parameters:',
                `  _type: ${resourceTypes.length > 0 ? resourceTypes.join(',').toLowerCase() : 'Not specified (using default resources)'}`,
                '',
                '• Group ID:',
                `  ${groupId}`,
                '',
                '• Expected Response:',
                '  - Status Code: 202 Accepted',
                '  - Content-Location header with status URL'
            ]);
            
            const response = await axios.get(url, {
                headers: {
                    'Authorization': `Bearer ${accessToken}`,
                    'Accept': 'application/fhir+json',
                    'Prefer': 'respond-async'
                },
                maxRedirects: 0,
                validateStatus: status => status === 202
            });

            const statusUrl = response.headers['content-location'];
            if (!statusUrl) {
                throw new Error('No Content-Location header in response');
            }

            this.logger.writeLog('INFO', [
                '',
                'RESPONSE RECEIVED',
                '----------------',
                '• Status Code:',
                `  ${response.status} ${response.statusText}`,
                '',
                '• Response Headers:',
                ...Object.entries(response.headers).map(([key, value]) => 
                    `  ${key}: ${value}`
                ),
                '',
                '• Content-Location (Status URL):',
                `  ${statusUrl}`
            ]);

            return statusUrl;
        } catch (error) {
            this.logger.writeLog('ERROR', [
                '',
                'BULK EXPORT REQUEST FAILED',
                '----------------------',
                '• Error Message:',
                `  ${error.message}`,
                '',
                '• Request Details:',
                `  URL: ${url}`,
                '  Method: GET',
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

    async checkExportStatus(statusUrl, accessToken) {
        try {
            this.logger.writeLog('INFO', [
                'STATUS CHECK REQUEST',
                '------------------',
                '• URL:',
                `  ${statusUrl}`,
                '',
                '• Headers:',
                '  Authorization: Bearer [TOKEN]',
                '  Accept: application/json'
            ]);

            const response = await axios.get(statusUrl, {
                headers: {
                    'Authorization': `Bearer ${accessToken}`,
                    'Accept': 'application/json'
                }
            });

            this.logger.writeLog('INFO', [
                '',
                'STATUS CHECK RESPONSE',
                '-------------------',
                '• Status Code:',
                `  ${response.status} ${response.statusText}`,
                '',
                '• Response Headers:',
                ...Object.entries(response.headers).map(([key, value]) => 
                    `  ${key}: ${value}`
                ),
                '',
                '• Response Body:',
                ...JSON.stringify(response.data, null, 2)
                    .split('\n')
                    .map(line => `  ${line}`)
            ]);

            return response;
        } catch (error) {
            if (error.response?.status === 202) {
                this.logger.writeLog('INFO', [
                    '',
                    'STATUS: IN PROGRESS',
                    '-----------------',
                    '• Status Code: 202 Accepted',
                    '• Export still processing'
                ]);
                return { status: 202 };
            }
            
            this.logger.writeLog('ERROR', [
                '',
                'STATUS CHECK FAILED',
                '-----------------',
                '• Error Message:',
                `  ${error.message}`,
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

    async downloadFile(fileUrl, accessToken, outputPath) {
        try {
            this.logger.writeLog('INFO', [
                'FILE DOWNLOAD REQUEST',
                '-------------------',
                '• URL:',
                `  ${fileUrl}`,
                '',
                '• Headers:',
                '  Authorization: Bearer [TOKEN]',
                '  Accept: application/fhir+ndjson',
                '',
                '• Output Path:',
                `  ${outputPath}`
            ]);

            const response = await axios.get(fileUrl, {
                headers: {
                    'Authorization': `Bearer ${accessToken}`,
                    'Accept': 'application/fhir+ndjson'
                },
                responseType: 'stream'
            });

            this.logger.writeLog('INFO', [
                '',
                'DOWNLOAD RESPONSE',
                '----------------',
                '• Status Code:',
                `  ${response.status} ${response.statusText}`,
                '',
                '• Response Headers:',
                ...Object.entries(response.headers).map(([key, value]) => 
                    `  ${key}: ${value}`)
            ]);

            const writer = fs.createWriteStream(outputPath);
            response.data.pipe(writer);

            return new Promise((resolve, reject) => {
                writer.on('finish', () => {
                    const stats = fs.statSync(outputPath);
                    this.logger.writeLog('INFO', [
                        '',
                        'DOWNLOAD COMPLETE',
                        '----------------',
                        '• File Size:',
                        `  ${(stats.size / 1024 / 1024).toFixed(2)} MB`,
                        '• Location:',
                        `  ${outputPath}`
                    ]);
                    resolve();
                });
                writer.on('error', reject);
            });
        } catch (error) {
            this.logger.writeLog('ERROR', [
                '',
                'DOWNLOAD FAILED',
                '--------------',
                '• Error Message:',
                `  ${error.message}`,
                '',
                '• URL:',
                `  ${fileUrl}`,
                '',
                '• Response Status:',
                `  ${error.response?.status || 'Unknown'} ${error.response?.statusText || ''}`,
                '',
                '• Response Headers:',
                ...(error.response?.headers ? 
                    Object.entries(error.response.headers).map(([key, value]) => 
                        `  ${key}: ${value}`
                    ) : ['  No headers available'])
            ]);
            throw error;
        }
    }

    async processBulkExport(statusUrl, accessToken) {
        try {
            let complete = false;
            let attempts = 0;
            const pollInterval = 10000; // 10 seconds
            const maxAttempts = 30; // 5 minutes total

            this.logger.writeLog('INFO', [
                '',
                'EXPORT STATUS MONITORING',
                '----------------------',
                '• Poll Interval: 10 seconds',
                '• Maximum Duration: 5 minutes',
                '• Status URL:',
                `  ${statusUrl}`,
                '',
                'Beginning status checks...'
            ]);

            while (!complete && attempts < maxAttempts) {
                attempts++;
                this.logger.writeLog('INFO', [
                    `\nStatus Check #${attempts}`,
                    '----------------'
                ]);
                
                const response = await this.checkExportStatus(statusUrl, accessToken);
                
                if (response.status === 200) {
                    complete = true;
                    const { data: { output } } = response;
                    
                    this.logger.writeLog('INFO', [
                        '• Status: COMPLETE',
                        '• Available Resources:',
                        ...output.map(file => `  - ${file.type}: ${file.url}`)
                    ]);

                    for (const file of output) {
                        const fileName = `bulk_fhir_query_${file.type}_${new Date().toISOString().replace(/[:.]/g, '-')}.ndjson`;
                        const outputPath = path.join(this.exportDir, fileName);
                        
                        this.logger.writeLog('INFO', [
                            '',
                            `DOWNLOADING ${file.type.toUpperCase()} DATA`,
                            '-'.repeat(file.type.length + 20),
                            '• Source:',
                            `  ${file.url}`,
                            '• Destination:',
                            `  ${fileName}`
                        ]);
                        
                        await this.downloadFile(file.url, accessToken, outputPath);
                        
                        this.logger.writeLog('INFO', [
                            `• Successfully downloaded ${file.type} data`
                        ]);

                        if (file.type === 'Observation') {
                            this.logger.writeLog('INFO', [
                                '',
                                'ANALYZING OBSERVATIONS',
                                '--------------------'
                            ]);

                            const fileContent = await fs.promises.readFile(outputPath, 'utf8');
                            const observations = fileContent
                                .split('\n')
                                .filter(line => line.trim())
                                .map(line => JSON.parse(line));

                            this.logger.writeLog('INFO', [
                                `• Processing ${observations.length} observations`
                            ]);

                            const patientStats = await this.analyzeObservations(observations);
                            const report = this.generateObservationReport(patientStats);
                            
                            const reportPath = path.join(this.exportDir, `bulk_fhir_query_observation_report_${new Date().toISOString().replace(/[:.]/g, '-')}.txt`);
                            await fs.promises.writeFile(reportPath, report, 'utf8');
                            
                            this.logger.writeLog('INFO', [
                                '• Analysis complete',
                                '• Report generated:',
                                `  ${reportPath}`,
                                '',
                                'OBSERVATION REPORT',
                                '-----------------',
                                report
                            ]);
                        }
                    }
                } else {
                    this.logger.writeLog('INFO', [
                        '• Status: IN PROGRESS',
                        `• Waiting ${pollInterval/1000} seconds before next check...`
                    ]);
                    await sleep(pollInterval);
                }
            }

            if (!complete) {
                throw new Error('Export timed out');
            }

            this.logger.writeLog('INFO', [
                '',
                'CLEANUP',
                '-------',
                '• Deleting export request from server...'
            ]);

            // Clean up the export
            await axios.delete(statusUrl, {
                headers: {
                    'Authorization': `Bearer ${accessToken}`
                }
            });

            this.logger.writeLog('INFO', ['• Cleanup completed successfully']);

        } catch (error) {
            this.logger.writeLog('ERROR', [
                '',
                'BULK EXPORT PROCESSING FAILED',
                '-------------------------',
                '• Error Message:',
                `  ${error.message}`,
                '• Response Data:',
                error.response?.data ? JSON.stringify(error.response.data, null, 2) : 'No response data'
            ]);
            throw error;
        }
    }
}

module.exports = { FHIRQueryClient }; 