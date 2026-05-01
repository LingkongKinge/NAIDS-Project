import joblib
import numpy as np
import pandas as pd

# ─── Load Both AI Models ──────────────────────────────────────
print("Loading dual AI engines...")

RF_MODEL_PATH = '/home/lingkong/NAIDS_Project/model/naids_model.pkl'
IF_MODEL_PATH = '/home/lingkong/NAIDS_Project/model/isolation_forest.pkl'
LE_PATH       = '/home/lingkong/NAIDS_Project/model/label_encoder.pkl'

rf_model       = joblib.load(RF_MODEL_PATH)
if_model       = joblib.load(IF_MODEL_PATH)
label_encoder  = joblib.load(LE_PATH)

print("✅ Random Forest loaded")
print("✅ Isolation Forest loaded")

# ─── Feature Columns ─────────────────────────────────────────
FEATURE_COLUMNS = [
    'Destination Port', 'Flow Duration', 'Total Fwd Packets',
    'Total Length of Fwd Packets', 'Fwd Packet Length Max',
    'Fwd Packet Length Min', 'Fwd Packet Length Mean',
    'Fwd Packet Length Std', 'Bwd Packet Length Max',
    'Bwd Packet Length Min', 'Bwd Packet Length Mean',
    'Bwd Packet Length Std', 'Flow Bytes/s', 'Flow Packets/s',
    'Flow IAT Mean', 'Flow IAT Std', 'Flow IAT Max', 'Flow IAT Min',
    'Fwd IAT Total', 'Fwd IAT Mean', 'Fwd IAT Std', 'Fwd IAT Max',
    'Fwd IAT Min', 'Bwd IAT Total', 'Bwd IAT Mean', 'Bwd IAT Std',
    'Bwd IAT Max', 'Bwd IAT Min', 'Fwd Header Length',
    'Bwd Header Length', 'Fwd Packets/s', 'Bwd Packets/s',
    'Min Packet Length', 'Max Packet Length', 'Packet Length Mean',
    'Packet Length Std', 'Packet Length Variance', 'FIN Flag Count',
    'PSH Flag Count', 'ACK Flag Count', 'Average Packet Size',
    'Subflow Fwd Bytes', 'Init_Win_bytes_forward',
    'Init_Win_bytes_backward', 'act_data_pkt_fwd',
    'min_seg_size_forward', 'Active Mean', 'Active Max',
    'Active Min', 'Idle Mean', 'Idle Max', 'Idle Min'
]

def get_severity(confidence):
    """Convert confidence percentage to severity level"""
    if confidence >= 95:
        return 'Critical'
    elif confidence >= 90:
        return 'High'
    elif confidence >= 70:
        return 'Medium'
    else:
        return 'Low'

def get_recommendation(rf_result, if_result, confidence):
    """
    Generate plain English recommendation for admin
    Based on both engine results
    """
    attack_type = rf_result['attack_type']
    is_anomaly  = if_result['is_anomaly']
    anomaly_score = if_result['anomaly_score']

    # Both engines agree — confirmed threat
    if attack_type != 'Normal Traffic' and is_anomaly:
        return {
            'action': 'BLOCK_IMMEDIATELY',
            'message': f'Confirmed {attack_type} detected by both AI engines. '
                       f'Immediate blocking is strongly recommended.',
            'engines': 'RF + IF'
        }

    # Only Random Forest detected — known attack
    elif attack_type != 'Normal Traffic' and not is_anomaly:
        if confidence >= 95:
            return {
                'action': 'BLOCK_RECOMMENDED',
                'message': f'Known {attack_type} pattern detected with '
                           f'{confidence:.1f}% confidence. Blocking recommended.',
                'engines': 'RF'
            }
        else:
            return {
                'action': 'INVESTIGATE',
                'message': f'Possible {attack_type} detected with '
                           f'{confidence:.1f}% confidence. '
                           f'Please investigate before blocking.',
                'engines': 'RF'
            }

    # Only Isolation Forest detected — unknown/zero-day
    elif attack_type == 'Normal Traffic' and is_anomaly:
        if anomaly_score < -0.1:
            return {
                'action': 'INVESTIGATE',
                'message': f'Unknown traffic pattern detected (Zero-Day risk). '
                           f'Anomaly score: {anomaly_score:.3f}. '
                           f'Investigate this source IP before taking action.',
                'engines': 'IF'
            }
        else:
            return {
                'action': 'MONITOR',
                'message': f'Slightly unusual traffic pattern detected. '
                           f'Monitoring recommended.',
                'engines': 'IF'
            }

    # Both engines say normal
    else:
        return {
            'action': 'NORMAL',
            'message': 'Traffic appears normal.',
            'engines': 'RF + IF'
        }

def analyse_flow(features_dict):
    """
    Main function — runs both AI engines on a network flow
    Returns unified result with recommendation

    Input:  features_dict — dictionary of 52 network flow features
    Output: complete analysis result
    """
    try:
        # Build dataframe with correct column order
        df = pd.DataFrame([features_dict])[FEATURE_COLUMNS]

        # ── ENGINE 1: Random Forest ──────────────────────────
        rf_pred_encoded  = rf_model.predict(df)[0]
        rf_probabilities = rf_model.predict_proba(df)[0]
        rf_confidence    = max(rf_probabilities) * 100
        rf_attack_type   = label_encoder.inverse_transform(
                               [rf_pred_encoded])[0]

        rf_result = {
            'attack_type': rf_attack_type,
            'confidence': round(rf_confidence, 1),
            'is_attack': rf_attack_type != 'Normal Traffic'
        }

        # ── ENGINE 2: Isolation Forest ───────────────────────
        if_pred        = if_model.predict(df)[0]
        if_score       = if_model.decision_function(df)[0]
        if_is_anomaly  = if_pred == -1

        if_result = {
            'is_anomaly': if_is_anomaly,
            'anomaly_score': round(float(if_score), 4),
            'risk_level': 'HIGH' if if_score < -0.1 else
                          'MEDIUM' if if_score < 0 else 'LOW'
        }

        # ── UNIFIED RECOMMENDATION ───────────────────────────
        recommendation = get_recommendation(
            rf_result, if_result, rf_confidence
        )

        # ── FINAL COMBINED RESULT ─────────────────────────────
        is_threat = (rf_result['is_attack'] or
                     if_result['is_anomaly'])

        result = {
            'is_threat': is_threat,
            'attack_type': rf_attack_type if rf_result['is_attack']
                           else ('Zero-Day Anomaly'
                                 if if_is_anomaly else 'Normal Traffic'),
            'confidence': rf_confidence,
            'severity': get_severity(rf_confidence)
                        if rf_result['is_attack']
                        else if_result['risk_level'],
            'rf_engine': rf_result,
            'if_engine': if_result,
            'recommendation': recommendation
        }

        return result

    except Exception as e:
        return {
            'is_threat': False,
            'attack_type': 'Analysis Error',
            'confidence': 0,
            'severity': 'Low',
            'error': str(e)
        }