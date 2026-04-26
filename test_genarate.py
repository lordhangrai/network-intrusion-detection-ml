import pandas as pd
import numpy as np

# Function to generate benign flow
def create_benign_flow(flow_id):
    return {
        'Flow Duration': np.random.uniform(5, 60),
        'Tot Fwd Pkts': np.random.randint(5, 50),
        'Tot Bwd Pkts': np.random.randint(3, 40),
        'TotLen Fwd Pkts': np.random.randint(500, 5000),
        'TotLen Bwd Pkts': np.random.randint(500, 5000),
        'SYN Flag Cnt': np.random.randint(0, 5),
        'FIN Flag Cnt': np.random.randint(0, 3),
        'ACK Flag Cnt': np.random.randint(10, 100),
        # Add remaining 63 features...
    }

# Function to generate attack flow (SYN Flood)
def create_syn_flood_attack():
    return {
        'Flow Duration': np.random.uniform(1, 10),
        'Tot Fwd Pkts': np.random.randint(200, 500),  # Excessive packets
        'Tot Bwd Pkts': np.random.randint(1, 5),      # Few reverse packets
        'TotLen Fwd Pkts': np.random.randint(10000, 50000),  # High volume
        'TotLen Bwd Pkts': np.random.randint(50, 500),
        'SYN Flag Cnt': np.random.randint(150, 500),  # Abnormally high
        'FIN Flag Cnt': 0,
        'ACK Flag Cnt': np.random.randint(0, 10),
        # Add remaining features...
    }

# Generate mixed dataset
flows = []
for i in range(50):
    flows.append(create_benign_flow(i))
for i in range(30):
    flows.append(create_syn_flood_attack())

df = pd.DataFrame(flows)
df.to_csv('test_dataset.csv', index=False)

print(f"✓ Created {len(df)} flows for testing")
print(f"  - 50 benign flows")
print(f"  - 30 attack flows (SYN Flood)")