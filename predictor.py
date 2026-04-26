import pickle
import pandas as pd
import numpy as np
import logging
import warnings
from sklearn.preprocessing import StandardScaler
from sklearn.exceptions import InconsistentVersionWarning

LOGGER = logging.getLogger(__name__)


def _load_pickle_with_version_notice(file_path):
    """Load a pickle and emit one clean warning if sklearn versions differ."""
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always", InconsistentVersionWarning)
        with open(file_path, "rb") as f:
            loaded_object = pickle.load(f)

    for warning_item in caught:
        if isinstance(warning_item.message, InconsistentVersionWarning):
            LOGGER.warning(
                "Model compatibility warning for %s: %s. "
                "Recommended fix: install scikit-learn==1.4.2 to match training artifacts.",
                file_path,
                warning_item.message,
            )
            break

    return loaded_object

class FlowPredictor:
    def __init__(self, model_path='EModel.pkl', scaler_path='EScaler.pkl'):
       
        self.model = _load_pickle_with_version_notice(model_path)
       
        self.scaler = _load_pickle_with_version_notice(scaler_path)
       
        
        self.selected_features = [
            'Flow Duration', 'Tot Fwd Pkts', 'Tot Bwd Pkts', 'TotLen Fwd Pkts', 'TotLen Bwd Pkts',
    'Fwd Pkt Len Max', 'Fwd Pkt Len Min', 'Fwd Pkt Len Mean', 'Fwd Pkt Len Std', 'Bwd Pkt Len Max',
    'Bwd Pkt Len Min', 'Bwd Pkt Len Mean', 'Bwd Pkt Len Std', 'Flow Byts/s', 'Flow Pkts/s',
    'Flow IAT Mean', 'Flow IAT Std', 'Flow IAT Max', 'Flow IAT Min', 'Fwd IAT Tot', 'Fwd IAT Mean',
    'Fwd IAT Std', 'Fwd IAT Max', 'Fwd IAT Min', 'Bwd IAT Tot', 'Bwd IAT Mean', 'Bwd IAT Std',
    'Bwd IAT Max', 'Bwd IAT Min', 'Fwd PSH Flags', 'Bwd PSH Flags', 'Fwd URG Flags', 'Bwd URG Flags',
    'Fwd Header Len', 'Bwd Header Len', 'Fwd Pkts/s', 'Bwd Pkts/s', 'Pkt Len Min', 'Pkt Len Max',
    'Pkt Len Mean', 'Pkt Len Std', 'Pkt Len Var', 'FIN Flag Cnt', 'SYN Flag Cnt', 'RST Flag Cnt',
    'PSH Flag Cnt', 'ACK Flag Cnt', 'URG Flag Cnt', 'CWE Flag Count', 'ECE Flag Cnt', 'Down/Up Ratio',
    'Pkt Size Avg', 'Fwd Seg Size Avg', 'Bwd Seg Size Avg', 'Fwd Byts/b Avg', 'Fwd Pkts/b Avg',
    'Fwd Blk Rate Avg', 'Bwd Byts/b Avg', 'Bwd Pkts/b Avg', 'Bwd Blk Rate Avg', 'Subflow Fwd Pkts',
    'Subflow Fwd Byts', 'Subflow Bwd Pkts', 'Subflow Bwd Byts', 'Init Fwd Win Byts', 'Init Bwd Win Byts',
    'Fwd Act Data Pkts', 'Fwd Seg Size Min', 'Active Mean', 'Active Std', 'Active Max', 'Active Min',
    'Idle Mean', 'Idle Std', 'Idle Max', 'Idle Min'
        ]
   
    def predict(self, features):
        # Extract relevant features with default 0 for missing features
        feature_values = [features.get(feature, 0) for feature in self.selected_features]
       
        # Convert to DataFrame
        X = pd.DataFrame([feature_values], columns=self.selected_features)
       
        # Scale features
        X_scaled = self.scaler.transform(X)
       
        # Make prediction
        prediction = self.model.predict(X_scaled)
       
        return 'Attack' if prediction[0] == 1 else 'Benign'
