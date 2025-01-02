const VitalSignsAnalyzer = require('./analyzers/VitalSignsAnalyzer');
const LabResultsAnalyzer = require('./analyzers/LabResultsAnalyzer');

class ObservationAnalyzer {
    constructor() {
        this.vitalSignsAnalyzer = new VitalSignsAnalyzer();
        this.labResultsAnalyzer = new LabResultsAnalyzer();
    }

    analyzeObservations(observations) {
        const patientStats = {};
        
        observations.forEach(obs => {
            try {
                const result = this.analyzeObservation(obs);
                if (result) {
                    this.updatePatientStats(patientStats, result);
                }
            } catch (error) {
                console.warn(`Error analyzing observation: ${error.message}`);
            }
        });

        return patientStats;
    }

    analyzeObservation(obs) {
        if (obs.resourceType !== 'Observation') return null;

        // Route to appropriate analyzer based on observation type
        if (this.isVitalSign(obs)) {
            return this.vitalSignsAnalyzer.analyze(obs);
        } else if (this.isLabResult(obs)) {
            return this.labResultsAnalyzer.analyze(obs);
        }
        
        return null;
    }
}

module.exports = ObservationAnalyzer; 