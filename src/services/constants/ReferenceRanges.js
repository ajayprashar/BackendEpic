exports.VITAL_SIGNS_RANGES = {
    'BP': {
        systolic: { min: 90, max: 140 },
        diastolic: { min: 60, max: 90 }
    },
    'Temp': { min: 36.5, max: 37.5 },
    'Pulse': { min: 60, max: 100 }
};

exports.LAB_REFERENCE_RANGES = {
    'Cholesterol [Mass/volume] in Serum or Plasma': {
        type: 'max',
        value: 200,
        unit: 'mg/dL'
    }
    // Add other lab reference ranges...
}; 