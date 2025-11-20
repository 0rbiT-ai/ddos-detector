import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import accuracy_score
import pickle
import numpy as np
import os
import glob
import sys
import shutil


CIC_DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'CIC-DDoS2019-CSVs') 

LOCAL_BENIGN_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'backend', 'local_benign_traffic.csv')

RAW_FEATURE_COLS = [
    'Flow Duration',         
    'Total Fwd Packets',     
    'SYN Flag Count',        
    'Protocol',              
    'Label'                  
]

FINAL_FEATURES = ['pps', 'syn_count', 'udp_count', 'icmp_count']
TARGET_COL = 'Label'

BACKEND_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'backend')
INTERMEDIATE_FILE = os.path.join(BACKEND_DIR, 'intermediate_features.csv')

def process_single_df(df, is_local_data=False):
    """Cleans, engineers features, and drops unusable data for a single DataFrame chunk."""
    
    if is_local_data:
        
        df.columns = df.columns.str.strip()
        df = df.replace([np.inf, -np.inf], np.nan).dropna()
        df_out = df[FINAL_FEATURES + [TARGET_COL]]
        return df_out

    
    
    
    df.columns = df.columns.str.strip() 
    df = df[RAW_FEATURE_COLS]
    
    
    df = df.replace([np.inf, -np.inf], np.nan).dropna()
    
   
    if TARGET_COL in df.columns:
        
        df[TARGET_COL] = df[TARGET_COL].astype(str).str.strip().str.upper().apply(
            lambda x: 0 if x == 'BENIGN' else 1
        )
    
    
    df['Flow Duration'] = df['Flow Duration'].replace(0, 1e-6) 
    df['pps'] = df['Total Fwd Packets'] / df['Flow Duration']
    
    
    df['udp_count'] = df['Protocol'].apply(lambda x: 1 if x == 17 else 0)
    df['icmp_count'] = df['Protocol'].apply(lambda x: 1 if x == 1 else 0)
    df['syn_count'] = df['SYN Flag Count'] 

    
    df_out = df[FINAL_FEATURES + [TARGET_COL]]
    
    return df_out


def load_and_process_all_data():
    """Locates and processes both CIC and local benign files in a memory-safe way."""
    
    
    cic_files = glob.glob(os.path.join(CIC_DATA_DIR, '**', '*.csv'), recursive=True)
    all_files = cic_files
    
    
    is_local_present = False
    if os.path.exists(LOCAL_BENIGN_FILE):
        all_files.append(LOCAL_BENIGN_FILE)
        is_local_present = True
    else:
        print(f"WARNING: Local benign file not found at {LOCAL_BENIGN_FILE}. Training without local fine-tuning.")
        
    if not all_files:
        print(f"Error: No training files found in {CIC_DATA_DIR}.", file=sys.stderr)
        sys.exit(1)
        
    print(f"Found {len(all_files)} training files. Starting memory-safe feature extraction...")
    
    
    if not os.path.exists(BACKEND_DIR):
        os.makedirs(BACKEND_DIR)
        
    if os.path.exists(INTERMEDIATE_FILE):
        os.remove(INTERMEDIATE_FILE)

    total_rows = 0
    
    
    for i, filename in enumerate(all_files):
        is_local_file = (filename == LOCAL_BENIGN_FILE)
        print(f"[{i+1}/{len(all_files)}] Processing {os.path.basename(filename)} (Local: {is_local_file})...")
        
        try:
            
            chunk_size = 100000 
            reader = pd.read_csv(filename, chunksize=chunk_size, low_memory=False, encoding='latin-1')
            
            for chunk in reader:
                
                df_out = process_single_df(chunk, is_local_data=is_local_file)
                
                
                header = not os.path.exists(INTERMEDIATE_FILE) 
                df_out.to_csv(INTERMEDIATE_FILE, mode='a', header=header, index=False)
                
                total_rows += len(df_out)

            
            del reader, chunk, df_out 
            
        except Exception as e:
            print(f"--- FAILED: Skipping {os.path.basename(filename)}. Error: {e}")
            continue

    return total_rows


def train_from_intermediate(total_rows):
    """Loads the processed features and trains the ML model."""
    if total_rows == 0 or not os.path.exists(INTERMEDIATE_FILE):
        print("CRITICAL: No features were processed. Cannot train model.")
        sys.exit(1)
        
    print("-" * 50)
    print(f"Feature processing complete. Total usable rows: {total_rows}")
    print("Loading final features into memory for training...")
    
    
    df_final = pd.read_csv(INTERMEDIATE_FILE, low_memory=False) 
    
    X = df_final[FINAL_FEATURES]
    y = df_final[TARGET_COL]
    
    
    y = y.astype(str).str.strip().str.upper().apply(
        lambda x: 0 if x == 'BENIGN' else x
    )
    
    
    y = y.astype(int) 
    
    
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    X_train, X_test, y_train, y_test = train_test_split(X_scaled, y, test_size=0.2, random_state=42)

    
    print(f"Starting Random Forest Training on {len(X_train)} samples...")
    model = RandomForestClassifier(n_estimators=50, random_state=42, n_jobs=-1)
    model.fit(X_train, y_train)

    
    y_pred = model.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)
    print(f"Model Training Complete. Accuracy on Test Set: {accuracy:.4f}")
    
    
    with open(os.path.join(BACKEND_DIR, 'ddos_detector.pkl'), 'wb') as f:
        pickle.dump(model, f)
    with open(os.path.join(BACKEND_DIR, 'scaler.pkl'), 'wb') as f:
        pickle.dump(scaler, f)
    
    
    os.remove(INTERMEDIATE_FILE)

    print("-" * 50)
    print("SUCCESS: ddos_detector.pkl and scaler.pkl created.")
    print("Your model is now fine-tuned and ready to run 'npm start' as Administrator.")
    print("-" * 50)


if __name__ == "__main__":
    total_processed_rows = load_and_process_all_data()
    if total_processed_rows > 0:
        train_from_intermediate(total_processed_rows)
    else:
        print("\nTraining aborted due to file loading errors.")
