/**
 * Observation Analyzer Module
 * =========================
 * Handles analysis and reporting of FHIR Observation resources.
 */

const fs = require('fs');
const path = require('path');

// Define standard reference ranges
const REFERENCE_RANGES = {
    'BP': '90-140/60-90',
    'Temp': '36.5-37.5',
    'Pulse': '60-100',
    'Cholesterol [Mass/volume] in Serum or Plasma': '<=200'
};

function getLatestObservationFile(directory) {
    console.log('\n=== Getting Latest Observation File ===');
    const files = fs.readdirSync(directory);
    const observationFiles = files.filter(file => file.startsWith('Observation_data_'));
    
    console.log(`Found ${observationFiles.length} observation files:`);
    observationFiles.forEach(file => console.log(`- ${file}`));
    
    if (observationFiles.length === 0) {
        throw new Error('No Observation files found in the directory.');
    }

    observationFiles.sort((a, b) => {
        const extractTimestamp = (filename) => {
            const match = filename.match(/_(\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}\.\d{3}Z)/);
            if (!match) {
                console.warn(`Warning: No timestamp match found in filename: ${filename}`);
                return new Date(0);
            }
            const formattedTimestamp = match[1].replace(/(\d{4}-\d{2}-\d{2})T(\d{2})-(\d{2})-(\d{2}\.\d{3})Z/, '$1T$2:$3:$4Z');
            return new Date(formattedTimestamp);
        };
        
        return extractTimestamp(b) - extractTimestamp(a); // Sort descending
    });

    const selectedFile = path.join(directory, observationFiles[0]);
    console.log(`\nSelected latest file: ${selectedFile}`);
    
    return selectedFile;
}

function readNDJSON(filePath) {
    const data = fs.readFileSync(filePath, 'utf8');
    return data.split('\n')
        .filter(line => line.trim() !== '')
        .map(line => {
            try {
                // Remove wrapping quotes if present
                const cleanLine = line.replace(/^"|"$/g, '');
                
                // Parse XML to extract Observation resources
                const match = cleanLine.match(/<entry>.*?<resource><Observation>(.*?)<\/Observation><\/resource>.*?<\/entry>/g);
                if (!match) {
                    return null;
                }

                // Convert each Observation XML to a JSON object
                return match.map(entry => {
                    const obsMatch = entry.match(/<Observation>(.*?)<\/Observation>/);
                    if (!obsMatch) {
                        return null;
                    }

                    // Extract key fields from XML
                    const observation = {
                        resourceType: 'Observation',
                        id: extractValue(entry, 'id'),
                        subject: {
                            reference: extractValue(entry, 'subject/reference'),
                            display: extractValue(entry, 'subject/display')
                        },
                        code: {
                            coding: [{
                                system: extractValue(entry, 'code/coding/system'),
                                code: extractValue(entry, 'code/coding/code'),
                                display: extractValue(entry, 'code/coding/display')
                            }]
                        },
                        effectiveDateTime: extractValue(entry, 'effectiveDateTime'),
                        valueQuantity: {
                            value: extractValue(entry, 'valueQuantity/value'),
                            unit: extractValue(entry, 'valueQuantity/unit')
                        }
                    };

                    return observation;
                }).filter(obs => obs !== null);
            } catch (error) {
                console.warn(`Error parsing line: ${error.message}`);
                return null;
            }
        })
        .filter(obj => obj !== null)
        .flat();
}

function extractValue(xml, path) {
    const parts = path.split('/');
    let value = '';
    const regex = new RegExp(`<${parts[parts.length - 1]}.*?value="(.*?)".*?>`);
    const match = xml.match(regex);
    return match ? match[1] : '';
}

function analyzeObservations(observations) {
    const patientStats = {};

    observations.forEach(obs => {
        try {
            if (obs.resourceType !== 'Observation') {
                return;
            }

            const observationId = obs.id;
            const observationType = obs.code?.coding?.[0]?.display || 'Unknown Type';
            
            // Get patient info
            let patientId, patientName;
            if (obs.subject?.reference) {
                patientId = obs.subject.reference.split('/')[1];
                patientName = obs.subject.display || 'Unknown Patient';
            } else {
                return;
            }
            
            // Initialize patient stats if not exists
            if (!patientStats[patientId]) {
                patientStats[patientId] = {
                    name: patientName,
                    normalCount: 0,
                    abnormalCount: 0,
                    normalObservations: [],
                    abnormalReadings: []
                };
            }

            const observationDate = obs.effectiveDateTime || obs.issued || 'No date';
            const formattedDate = observationDate !== 'No date' 
                ? new Date(observationDate).toISOString().split('T')[0]
                : observationDate;

            if (observationType === 'BP') {
                analyzeBPObservation(obs, patientStats[patientId], observationId, formattedDate);
            } else {
                analyzeGeneralObservation(obs, patientStats[patientId], observationId, observationType, formattedDate);
            }

        } catch (error) {
            console.warn(`Error processing observation ${obs?.id || 'unknown'}: ${error.message}`);
        }
    });

    return patientStats;
}

function analyzeBPObservation(obs, patientStat, observationId, formattedDate) {
    const systolic = obs.component?.[0]?.valueQuantity?.value;
    const diastolic = obs.component?.[1]?.valueQuantity?.value;
    
    if (systolic && diastolic) {
        const value = `${systolic}/${diastolic}`;
        const unit = 'mmHg';
        const referenceText = '90-140/60-90';
        const isAbnormal = systolic > 140 || systolic < 90 || diastolic > 90 || diastolic < 60;
        const status = isAbnormal ? 'ABNORMAL' : 'NORMAL';
        
        const observationRecord = {
            observationId,
            type: 'BP',
            value: `${value} ${unit}`,
            referenceRange: referenceText,
            status,
            date: formattedDate
        };

        if (isAbnormal) {
            patientStat.abnormalCount++;
            patientStat.abnormalReadings.push(observationRecord);
        } else {
            patientStat.normalCount++;
            patientStat.normalObservations.push(observationRecord);
        }
    }
}

function analyzeGeneralObservation(obs, patientStat, observationId, observationType, formattedDate) {
    if (obs.valueQuantity) {
        const value = obs.valueQuantity.value;
        const unit = obs.valueQuantity.unit;
        let referenceText = '';

        if (obs.referenceRange && obs.referenceRange.length > 0) {
            referenceText = obs.referenceRange[0].text || '';
        }

        if (!referenceText && REFERENCE_RANGES[observationType]) {
            referenceText = REFERENCE_RANGES[observationType];
        }

        let status = determineObservationStatus(value, referenceText);

        const observationRecord = {
            observationId,
            type: observationType,
            value: `${value}${unit ? ' ' + unit : ''}`,
            referenceRange: referenceText || 'No range specified',
            status,
            date: formattedDate
        };

        if (status === 'NORMAL') {
            patientStat.normalCount++;
            patientStat.normalObservations.push(observationRecord);
        } else {
            patientStat.abnormalCount++;
            patientStat.abnormalReadings.push(observationRecord);
        }
    }
}

function determineObservationStatus(value, referenceText) {
    if (!referenceText) return 'NORMAL';

    if (referenceText.includes('<=')) {
        const highValue = parseFloat(referenceText.replace('<=', ''));
        return value > highValue ? 'ABNORMAL (High)' : 'NORMAL';
    } 
    
    if (referenceText.includes('-')) {
        const [low, high] = referenceText.split('-').map(Number);
        if (value < low) return 'ABNORMAL (Low)';
        if (value > high) return 'ABNORMAL (High)';
    }

    return 'NORMAL';
}

function generateReport(patientStats) {
    let reportString = '';
    
    // Calculate totals
    const totals = Object.values(patientStats).reduce((acc, stats) => {
        acc.normal += stats.normalCount;
        acc.abnormal += stats.abnormalCount;
        return acc;
    }, { normal: 0, abnormal: 0 });

    // Summary section
    reportString += `Summary:\n`;
    reportString += `---------\n`;
    reportString += `Total Observations: ${totals.normal + totals.abnormal}\n`;
    reportString += `Total Normal Readings: ${totals.normal}\n`;
    reportString += `Total Abnormal Readings: ${totals.abnormal}\n\n`;

    // Detailed observations header
    reportString += 'Detailed Observations:\n';
    reportString += '--------------------\n';
    reportString += 'Date | Patient Name | Patient ID | Observation Type | Value | Reference Range | Status\n';
    reportString += '-----|--------------|------------|------------------|--------|----------------|--------\n';

    // Patient-wise observations
    Object.entries(patientStats).forEach(([patientId, stats]) => {
        const allObservations = [...stats.normalObservations || [], ...stats.abnormalReadings || []];
        
        allObservations.forEach(obs => {
            reportString += [
                obs.date,
                stats.name,
                patientId,
                obs.type,
                obs.value,
                obs.referenceRange || 'N/A',
                obs.status || 'NORMAL'
            ].join(' | ') + '\n';
        });
    });

    return reportString;
}

module.exports = {
    getLatestObservationFile,
    readNDJSON,
    analyzeObservations,
    generateReport
}; 