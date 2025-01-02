const { VITAL_SIGNS_RANGES } = require('../constants/ReferenceRanges');

class VitalSignsAnalyzer {
    analyze(observation) {
        const codeTypeMap = {
            // BP codes
            '55284-4': 'BP',       // Blood pressure systolic and diastolic
            '85354-9': 'BP',       // Blood pressure panel
            '8480-6': 'BP',        // Systolic blood pressure
            '8462-4': 'BP',        // Diastolic blood pressure
            // Add any additional BP codes found in your observations

            // Temperature codes
            '8310-5': 'Temp',      // Body temperature
            // Add any additional Temp codes

            // Pulse codes
            '8867-4': 'Pulse',     // Heart rate
            // Add any additional Pulse codes
        };

        let type = null;

        // Attempt to identify the type from code.text
        if (['BP', 'Temp', 'Pulse'].includes(observation.code?.text)) {
            type = observation.code.text;
        }

        // If type is still null, search coding for known codes
        if (!type) {
            const codingArray = observation.code?.coding || [];
            for (const coding of codingArray) {
                const code = coding.code;
                const display = coding.display;
                if (codeTypeMap[code]) {
                    type = codeTypeMap[code];
                    break;
                } else if (codeTypeMap[display]) {
                    type = codeTypeMap[display];
                    break;
                }
            }
        }

        // If type is still not determined, log for debugging
        if (!type) {
            console.log('Unknown observation type:', JSON.stringify(observation.code, null, 2));
            return null;
        }

        // Debug observation type
        console.log(`Observation classified as type: ${type}`);

        switch(type) {
            case 'BP':
                return this.analyzeBP(observation);
            case 'Temp':
                return this.analyzeTemperature(observation);
            case 'Pulse':
                return this.analyzePulse(observation);
            default:
                console.log('Unhandled observation type:', type);
                return null;
        }
    }

    analyzeBP(observation) {
        // Log the full BP observation for debugging
        console.log('Full BP Observation:', JSON.stringify(observation, null, 2));

        // Find systolic and diastolic components by their codes
        const systolicComponent = observation.component?.find(comp =>
            comp.code?.coding?.some(coding => coding.code === '8480-6')
        );
        const diastolicComponent = observation.component?.find(comp =>
            comp.code?.coding?.some(coding => coding.code === '8462-4')
        );

        const systolic = systolicComponent?.valueQuantity?.value;
        const diastolic = diastolicComponent?.valueQuantity?.value;

        if (!systolic || !diastolic) {
            console.log('Could not find systolic or diastolic values');
            return null;
        }

        // Extract the date from available fields
        const dateField =
            observation.effectiveDateTime ||
            observation.effectivePeriod?.start ||
            observation.effectiveInstant ||
            observation.issued ||
            observation.meta?.lastUpdated ||
            observation.date ||
            observation.performedDateTime ||
            observation.performedPeriod?.start ||
            observation.recordedDate;

        console.log('Date Field:', dateField);

        let date;
        if (dateField) {
            try {
                const parsedDate = new Date(dateField);
                if (!isNaN(parsedDate)) {
                    date = parsedDate.toISOString().split('T')[0];
                } else {
                    console.log('Invalid date format:', dateField);
                    date = 'No date';
                }
            } catch (error) {
                console.log('Error parsing date:', dateField, error);
                date = 'No date';
            }
        } else {
            console.log('No date fields available in observation');
            date = 'No date';
        }

        console.log('Extracted BP Date:', date);

        // Determine if the BP readings are abnormal
        const ranges = VITAL_SIGNS_RANGES.BP;
        const isAbnormal =
            systolic > ranges.systolic.max ||
            systolic < ranges.systolic.min ||
            diastolic > ranges.diastolic.max ||
            diastolic < ranges.diastolic.min;

        const result = {
            date,
            type: 'BP',
            value: `${systolic}/${diastolic} mmHg`,
            referenceRange: '90-140/60-90',
            status: isAbnormal ? 'ABNORMAL' : 'NORMAL',
            patientId: observation.subject?.reference?.split('/')?.[1],
            patientName: observation.subject?.display,
        };

        // Debug the final result
        console.log('BP Analysis Result:', result);

        return result;
    }

    analyzeTemperature(observation) {
        const temp = observation.valueQuantity?.value;
        // Temperature analysis logic...
    }

    analyzePulse(observation) {
        const pulse = observation.valueQuantity?.value;
        // Pulse analysis logic...
    }
}

module.exports = VitalSignsAnalyzer; 