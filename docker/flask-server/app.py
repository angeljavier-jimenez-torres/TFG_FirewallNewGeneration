from flask import Flask, request, render_template, jsonify
from flask_socketio import SocketIO, emit
from flask_cors import CORS
import pandas as pd
import numpy as np
import joblib
from sklearn.metrics import classification_report, confusion_matrix

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret!'
socketio = SocketIO(app, cors_allowed_origins="*")
CORS(app)


# Cargar el modelo y las características seleccionadas
model_path = 'model/random_forest_model.pkl'
features_path = 'model/selected_features.csv'
rf_model = joblib.load(model_path)
selected_features = pd.read_csv(features_path)['feature']

#' Source Port', 
columns = [
    'Flow ID', ' Source IP', ' Source Port', ' Destination IP', ' Destination Port', ' Protocol', ' Timestamp', ' Flow Duration', ' Total Fwd Packets', 
    ' Total Backward Packets', 'Total Length of Fwd Packets', ' Total Length of Bwd Packets', ' Fwd Packet Length Max', ' Fwd Packet Length Min', ' Fwd Packet Length Mean', 
    ' Fwd Packet Length Std', 'Bwd Packet Length Max', ' Bwd Packet Length Min', ' Bwd Packet Length Mean', ' Bwd Packet Length Std', 'Flow Bytes/s', 
    ' Flow Packets/s', ' Flow IAT Mean', ' Flow IAT Std', ' Flow IAT Max', ' Flow IAT Min', 'Fwd IAT Total', ' Fwd IAT Mean', ' Fwd IAT Std', ' Fwd IAT Max', 
    ' Fwd IAT Min', 'Bwd IAT Total', ' Bwd IAT Mean', ' Bwd IAT Std', ' Bwd IAT Max', ' Bwd IAT Min', 'Fwd PSH Flags', ' Bwd PSH Flags', ' Fwd URG Flags', ' Bwd URG Flags', 
    ' Fwd Header Length', ' Bwd Header Length', 'Fwd Packets/s', ' Bwd Packets/s', ' Min Packet Length', ' Max Packet Length', ' Packet Length Mean', ' Packet Length Std', 
    ' Packet Length Variance', 'FIN Flag Count', ' SYN Flag Count', ' RST Flag Count', ' PSH Flag Count', ' ACK Flag Count', ' URG Flag Count', ' CWE Flag Count', ' ECE Flag Count', 
    ' Down/Up Ratio', ' Average Packet Size', ' Avg Fwd Segment Size', ' Avg Bwd Segment Size', 'Fwd Avg Bytes/Bulk', ' Fwd Avg Packets/Bulk', 
    ' Fwd Avg Bulk Rate', ' Bwd Avg Bytes/Bulk', ' Bwd Avg Packets/Bulk', 'Bwd Avg Bulk Rate', 'Subflow Fwd Packets', ' Subflow Fwd Bytes', ' Subflow Bwd Packets', ' Subflow Bwd Bytes', 
    'Init_Win_bytes_forward', ' Init_Win_bytes_backward', ' act_data_pkt_fwd', ' min_seg_size_forward', 'Active Mean', ' Active Std', ' Active Max', ' Active Min', 'Idle Mean', ' Idle Std', 
    ' Idle Max', ' Idle Min', ' Label'
    ]
def preprocess_flow_data(df):
    df = df.drop(columns=[
    'Flow ID', ' Source IP', ' Destination IP', ' Timestamp', ' Bwd PSH Flags', ' Fwd URG Flags', ' Bwd URG Flags', 
    'FIN Flag Count', ' PSH Flag Count', ' ECE Flag Count', 'Fwd Avg Bytes/Bulk', ' Fwd Avg Packets/Bulk', ' Fwd Avg Bulk Rate', ' Bwd Avg Bytes/Bulk', 
    ' Bwd Avg Packets/Bulk', 'Bwd Avg Bulk Rate', ' Label'
    ])

    #' Source Port': 'int64',
    # Convert column types to maintain data consistency
    df = df.astype({' Source Port': 'int64', ' Destination Port': 'int64', ' Protocol': 'int64', ' Flow Duration': 'int64', ' Total Fwd Packets': 'int64', ' Total Backward Packets': 'int64', 'Fwd PSH Flags': 'int64', ' Fwd Header Length': 'int64', ' Bwd Header Length': 'int64', ' SYN Flag Count': 'int64', ' RST Flag Count': 'int64', ' ACK Flag Count': 'int64', ' URG Flag Count': 'int64', ' CWE Flag Count': 'int64', 'Subflow Fwd Packets': 'int64', ' Subflow Fwd Bytes': 'int64', ' Subflow Bwd Packets': 'int64', ' Subflow Bwd Bytes': 'int64', 'Init_Win_bytes_forward': 'int64', ' Init_Win_bytes_backward': 'int64', ' act_data_pkt_fwd': 'int64', ' min_seg_size_forward': 'int64'})#, ' Inbound': 'int64'
    df = df.astype({'Total Length of Fwd Packets': 'float64', ' Total Length of Bwd Packets': 'float64', ' Fwd Packet Length Max': 'float64', ' Fwd Packet Length Min': 'float64', ' Fwd Packet Length Mean': 'float64', ' Fwd Packet Length Std': 'float64', 'Bwd Packet Length Max': 'float64', ' Bwd Packet Length Min': 'float64', ' Bwd Packet Length Mean': 'float64', ' Bwd Packet Length Std': 'float64', 'Flow Bytes/s': 'float64', ' Flow Packets/s': 'float64', ' Flow IAT Mean': 'float64', ' Flow IAT Std': 'float64', ' Flow IAT Max': 'float64', ' Flow IAT Min': 'float64', 'Fwd IAT Total': 'float64', ' Fwd IAT Mean': 'float64', ' Fwd IAT Std': 'float64', ' Fwd IAT Max': 'float64', ' Fwd IAT Min': 'float64', 'Bwd IAT Total': 'float64', ' Bwd IAT Mean': 'float64', ' Bwd IAT Std': 'float64', ' Bwd IAT Max': 'float64', ' Bwd IAT Min': 'float64', 'Fwd Packets/s': 'float64', ' Bwd Packets/s': 'float64', ' Min Packet Length': 'float64', ' Max Packet Length': 'float64', ' Packet Length Mean': 'float64', ' Packet Length Std': 'float64', ' Packet Length Variance': 'float64', ' Down/Up Ratio': 'float64', ' Average Packet Size': 'float64', ' Avg Fwd Segment Size': 'float64', ' Avg Bwd Segment Size': 'float64', 'Active Mean': 'float64', ' Active Std': 'float64', ' Active Max': 'float64', ' Active Min': 'float64', 'Idle Mean': 'float64', ' Idle Std': 'float64', ' Idle Max': 'float64', ' Idle Min': 'float64'})
  
    # Replace missing values with the median of each column
    df = df.fillna(df.median())

    # Replace infinite values with the maximum finite value of each column
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    for col in df.select_dtypes(include=[np.float64, np.int64]).columns:
        max_finite_value = df[col].max()
        df[col] = df[col].fillna(max_finite_value)

    return df

@app.route('/')
def get_data():
    return render_template('index.html')

@app.route('/receive_flow', methods=['POST'])
def receive_flow():
    try:
        request_data = request.get_json()
        flow_data = request_data['flowData']

        # Convertir el flujo de datos a un DataFrame
        flow_data = [flow_data.split(',')]
        flow_data = pd.DataFrame(flow_data, columns=columns)
        
        df = preprocess_flow_data(flow_data)
        X_new = df[selected_features]
        
        prediction = rf_model.predict(X_new)
        prediction_proba = rf_model.predict_proba(X_new)

        # Emitir los datos, la predicción y la probabilidad a través de WebSocket
        socketio.emit('new_data', {
            'source_ip': flow_data[' Source IP'][0],
            'destination_ip': flow_data[' Destination IP'][0],
            'timestamp': flow_data[' Timestamp'][0],
            'prediction': int(prediction[0]), 
            'probability_0': float(prediction_proba[0][0]),
            'probability_1': float(prediction_proba[0][1]),
            'X_new': X_new.to_dict(orient='records')[0]
        })
        
        return '', 200
    except Exception as e:
        print("Error al recibir el flujo:", str(e))
        return '', 500

        
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
