import asyncio
import time
import numpy as np
import os
import pickle
import ipaddress
import tensorflow as tf
from keras.models import load_model
from pathlib import Path

class MLNetworkAnalyzer:
    def __init__(self):
        # Initialize packet processing
        self.packet_history = []  # Store recent packets for analysis
        self.history_limit = 1000  # Maximum number of packets to keep in history
        self.batch_size = 64  # Batch size for model inference
        
        # Feature extraction settings
        self.feature_count = 15  # Number of features for ML models
        
        # Alert thresholds
        self.anomaly_threshold = 0.85  # Threshold for anomaly score (higher = more anomalous)
        self.probability_threshold = 0.75  # Threshold for attack probability
        
        # Common attack mappings
        self.attack_types = {
            0: "Normal Traffic",
            1: "Port Scan",
            2: "DoS Attack",
            3: "Brute Force",
            4: "Data Exfiltration",
            5: "Command and Control"
        }
        
        # Load models
        self.models = self._load_models()
        
        # Track IPs and their behavior
        self.ip_behavior = {}  # {ip: {'packets': count, 'last_seen': timestamp, 'scores': []}}
        
    def _load_models(self):
        """Load trained ML models from files"""
        models = {
            'keras': {},
            'tensorflow': {}
        }
        
        # Get base directory for models
        base_dir = Path(__file__).parent / "models"
        
        # Load Keras models
        keras_dir = base_dir / "keras"
        if keras_dir.exists():
            for model_file in keras_dir.glob("*.keras"):
                model_name = model_file.stem
                try:
                    print(f"Loading Keras model: {model_name}")
                    models['keras'][model_name] = load_model(str(model_file))
                except Exception as e:
                    print(f"Error loading Keras model {model_name}: {str(e)}")
        
        # Load TensorFlow/sklearn models (pickle format)
        tf_dir = base_dir / "tensorflow"
        if tf_dir.exists():
            for model_file in tf_dir.glob("*.pkl"):
                model_name = model_file.stem
                try:
                    print(f"Loading TensorFlow/sklearn model: {model_name}")
                    with open(model_file, 'rb') as f:
                        models['tensorflow'][model_name] = pickle.load(f)
                except Exception as e:
                    print(f"Error loading TensorFlow/sklearn model {model_name}: {str(e)}")
        
        return models
    
    async def analyze(self, network_data):
        """Analyze network traffic using ML models"""
        if not network_data:
            return []
            
        alerts = []
        current_time = time.time()
        
        # Add new packets to history
        self.packet_history.extend(network_data)
        
        # Limit history size
        if len(self.packet_history) > self.history_limit:
            self.packet_history = self.packet_history[-self.history_limit:]
        
        # Update IP behavior tracking
        for packet in network_data:
            src_ip = packet.get('src', '')
            if src_ip:
                if src_ip not in self.ip_behavior:
                    self.ip_behavior[src_ip] = {
                        'packets': 0,
                        'last_seen': 0,
                        'scores': []
                    }
                
                self.ip_behavior[src_ip]['packets'] += 1
                self.ip_behavior[src_ip]['last_seen'] = current_time
        
        # Process batches for ML analysis to improve performance
        if len(network_data) >= self.batch_size:
            # Extract features for ML models
            features = self._extract_features(network_data)
            
            # Run detection models
            ml_alerts = self._run_ml_detection(features, network_data)
            alerts.extend(ml_alerts)
        
        # Analyze flows and sessions
        flow_alerts = await self._analyze_flows(network_data, current_time)
        alerts.extend(flow_alerts)
        
        # Clean up old IP behavior data
        self._cleanup_old_data(current_time - 3600)  # Remove data older than 1 hour
        
        return alerts
    
    def _extract_features(self, packets):
        """Extract features from network packets for ML models"""
        features = []
        
        for packet in packets:
            # Extract basic features
            src_ip = packet.get('src', '0.0.0.0')
            dst_ip = packet.get('dst', '0.0.0.0')
            src_port = packet.get('sport', 0)
            dst_port = packet.get('dport', 0)
            proto = packet.get('proto', '')
            size = packet.get('size', 0)
            flags = packet.get('flags', '')
            
            # Convert protocol to numeric
            proto_num = 0
            if proto.lower() == 'tcp':
                proto_num = 1
            elif proto.lower() == 'udp':
                proto_num = 2
            elif proto.lower() == 'icmp':
                proto_num = 3
            
            # Process IP addresses
            src_is_private = int(self._is_internal_ip(src_ip))
            dst_is_private = int(self._is_internal_ip(dst_ip))
            
            # Process flags (for TCP)
            flag_features = [0, 0, 0, 0]  # SYN, ACK, FIN, RST
            if 'S' in flags:
                flag_features[0] = 1
            if 'A' in flags:
                flag_features[1] = 1
            if 'F' in flags:
                flag_features[2] = 1
            if 'R' in flags:
                flag_features[3] = 1
            
            # Process ports
            is_well_known_port = 1 if (dst_port < 1024 or src_port < 1024) else 0
            is_high_port = 1 if (dst_port > 49000 or src_port > 49000) else 0
            
            # Combine features
            packet_features = [
                src_port / 65535,  # Normalize port numbers
                dst_port / 65535,
                proto_num / 3,  # Normalize protocol
                size / 1500,  # Normalize packet size (assuming MTU)
                src_is_private,
                dst_is_private,
                is_well_known_port,
                is_high_port
            ]
            packet_features.extend(flag_features)
            
            # Add contextual features (recent packet counts, etc.)
            if src_ip in self.ip_behavior:
                recent_packets = min(self.ip_behavior[src_ip]['packets'] / 1000, 1.0)
            else:
                recent_packets = 0
                
            packet_features.append(recent_packets)
            
            # Ensure we have the right number of features
            while len(packet_features) < self.feature_count:
                packet_features.append(0)
                
            # Trim if too many features
            packet_features = packet_features[:self.feature_count]
            
            features.append(packet_features)
        
        return np.array(features, dtype=np.float32)
    
    def _run_ml_detection(self, features, packets):
        """Run ML models for attack detection"""
        alerts = []
        current_time = time.time()
        
        if len(features) == 0:
            return alerts
            
        try:
            # Run CNN model if available
            if 'cnn_model' in self.models['keras']:
                # Get the expected shape from the model
                input_shape = self.models['keras']['cnn_model'].input_shape
                
                # Determine if we need to reshape based on model's expected dimensions
                if len(input_shape) == 3:  # 3D input (batch_size, time, features)
                    # Check dimensions and reshape if needed
                    if input_shape[1] is not None and features.shape[1] != input_shape[1]:
                        # Handle different feature dimensions by ensuring dimensions match
                        if features.shape[1] < input_shape[1]:
                            # Pad features if we have fewer features than expected
                            padding = ((0, 0), (0, input_shape[1] - features.shape[1]))
                            features_for_cnn = np.pad(features, padding, mode='constant')
                        else:
                            # Truncate if we have more features than expected
                            features_for_cnn = features[:, :input_shape[1]]
                    else:
                        features_for_cnn = features
                    
                    # Make prediction with properly shaped input
                    try:
                        cnn_preds = self.models['keras']['cnn_model'].predict(features_for_cnn, verbose=0)
                    except ValueError as e:
                        # Additional reshaping if needed
                        if "not compatible with" in str(e):
                            # Try to reshape to match expected dimensions
                            expected_shape = tuple(dim if dim is not None else features_for_cnn.shape[i] 
                                                for i, dim in enumerate(input_shape))
                            features_for_cnn = features_for_cnn.reshape(expected_shape[1:])
                            features_for_cnn = np.expand_dims(features_for_cnn, axis=0)  # Add batch dimension
                            cnn_preds = self.models['keras']['cnn_model'].predict(features_for_cnn, verbose=0)
                        else:
                            raise
                
                elif len(input_shape) == 4:  # 4D input for Conv2D
                    # Reshape to (batch_size, height, width, channels)
                    # Assuming features is (batch_size, features)
                    # We'll reshape to match the model's expected dimensions
                    
                    # Calculate the appropriate reshape dimensions
                    if input_shape[1] is not None and input_shape[2] is not None:
                        height = input_shape[1]
                        width = input_shape[2]
                        channels = input_shape[3] if input_shape[3] is not None else 1
                        
                        # Make sure we have enough data
                        if features.shape[1] < height * width * channels:
                            # Pad with zeros if not enough features
                            padding_needed = height * width * channels - features.shape[1]
                            padded_features = np.pad(features, 
                                                   ((0, 0), (0, padding_needed)), 
                                                   mode='constant')
                            reshaped_features = padded_features.reshape((features.shape[0], height, width, channels))
                        else:
                            # Truncate if too many features
                            flat_features = features[:, :height * width * channels]
                            reshaped_features = flat_features.reshape((features.shape[0], height, width, channels))
                    else:
                        # If dimensions are None, make a best guess
                        feature_count = features.shape[1]
                        if feature_count >= 9:  # minimum 3x3
                            # Try to make it square-ish
                            dim = int(np.sqrt(feature_count))
                            reshaped_features = features.reshape((features.shape[0], dim, feature_count // dim, 1))
                        else:
                            # Fall back to simple reshape
                            reshaped_features = features.reshape((features.shape[0], 1, feature_count, 1))
                    
                    try:
                        cnn_preds = self.models['keras']['cnn_model'].predict(reshaped_features, verbose=0)
                    except ValueError as e:
                        # If that fails, try auto-detecting the right shape
                        print(f"Shape error: {e}. Trying to auto-detect correct shape.")
                        # Get expected total elements
                        total_elements = np.prod([d for d in input_shape[1:] if d is not None])
                        if total_elements == 0:  # If all are None
                            total_elements = features.shape[1]
                        
                        # Create best-guess shape
                        if features.shape[1] < total_elements:
                            # Pad data if not enough
                            padding_needed = total_elements - features.shape[1]
                            padded_features = np.pad(features, 
                                                  ((0, 0), (0, padding_needed)), 
                                                  mode='constant')
                            flattened = padded_features
                        else:
                            # Truncate if too much data
                            flattened = features[:, :total_elements]
                        
                        # Try to reshape to match model's expected input
                        new_shape = tuple([features.shape[0]] + 
                                        [input_shape[i] if input_shape[i] is not None else 1 
                                         for i in range(1, len(input_shape))])
                        reshaped_features = flattened.reshape(new_shape)
                        cnn_preds = self.models['keras']['cnn_model'].predict(reshaped_features, verbose=0)
                else:
                    # 2D input or other unexpected shape
                    # Just use features directly
                    cnn_preds = self.models['keras']['cnn_model'].predict(features, verbose=0)
                
                # Process predictions
                for i, pred in enumerate(cnn_preds):
                    packet = packets[i] if i < len(packets) else packets[-1]
                    attack_type_idx = np.argmax(pred)
                    attack_confidence = pred[attack_type_idx]
                    
                    if attack_type_idx > 0 and attack_confidence > self.probability_threshold:
                        alerts.append({
                            'timestamp': current_time,
                            'type': f'ML Detected: {self.attack_types.get(attack_type_idx, "Unknown Attack")}',
                            'severity': 'high' if attack_confidence > 0.9 else 'medium',
                            'source': 'ml_network_analyzer',
                            'description': (f"ML detected {self.attack_types.get(attack_type_idx, 'anomalous traffic')} "
                                        f"from IP {packet.get('src', 'unknown')} to {packet.get('dst', 'unknown')} "
                                        f"(confidence: {attack_confidence:.2f})")
                        })
                        
                        # Update IP behavior with this score
                        src_ip = packet.get('src', '')
                        if src_ip in self.ip_behavior:
                            self.ip_behavior[src_ip]['scores'].append(attack_confidence)
                            
                            # Keep the last 10 scores
                            if len(self.ip_behavior[src_ip]['scores']) > 10:
                                self.ip_behavior[src_ip]['scores'] = self.ip_behavior[src_ip]['scores'][-10:]
            
            # Run SVM model if available
            if 'svm_model' in self.models['tensorflow']:
                try:
                    # Check if we need to reshape for SVM
                    # Most SVMs expect 2D input (samples, features)
                    if len(features.shape) != 2:
                        # Flatten to 2D
                        svm_features = features.reshape(features.shape[0], -1)
                    else:
                        svm_features = features
                    
                    svm_preds = self.models['tensorflow']['svm_model'].predict(svm_features)
                    
                    for i, pred in enumerate(svm_preds):
                        packet = packets[i] if i < len(packets) else packets[-1]
                        if pred > 0:  # Assuming binary classification (0=normal, 1=attack)
                            alerts.append({
                                'timestamp': current_time,
                                'type': 'ML Detected: Suspicious Traffic Pattern',
                                'severity': 'medium',
                                'source': 'ml_network_analyzer',
                                'description': (f"SVM model detected suspicious traffic pattern "
                                            f"from IP {packet.get('src', 'unknown')} to {packet.get('dst', 'unknown')}")
                            })
                except Exception as e:
                    print(f"Error in SVM prediction: {str(e)}")
        
        except Exception as e:
            print(f"Error in ML detection: {str(e)}")
            import traceback
            traceback.print_exc()
        
        return alerts
    
    async def _analyze_flows(self, network_data, current_time):
        """Analyze network flows for suspicious patterns"""
        alerts = []
        
        # Group packets by source IP and destination
        flows = {}
        for packet in network_data:
            src_ip = packet.get('src', '')
            dst_ip = packet.get('dst', '')
            dst_port = packet.get('dport', 0)
            
            flow_key = f"{src_ip}:{dst_ip}:{dst_port}"
            if flow_key not in flows:
                flows[flow_key] = []
            
            flows[flow_key].append(packet)
        
        # Analyze each flow
        for flow_key, packets in flows.items():
            src_ip, dst_ip, dst_port = flow_key.split(':')
            dst_port = int(dst_port)
            
            # Check for anomalous behavior based on known patterns
            
            # 1. Excessive connection attempts to a single port
            if len(packets) > 10 and dst_port in [22, 23, 3389, 445]:
                alerts.append({
                    'timestamp': current_time,
                    'type': 'Potential Brute Force',
                    'severity': 'high',
                    'source': 'ml_network_analyzer',
                    'description': f"Excessive connection attempts from {src_ip} to {dst_ip}:{dst_port}"
                })
            
            # 2. Check for data exfiltration (large outbound data)
            if not self._is_internal_ip(dst_ip) and sum(p.get('size', 0) for p in packets) > 100000:
                alerts.append({
                    'timestamp': current_time,
                    'type': 'Large Data Transfer',
                    'severity': 'medium',
                    'source': 'ml_network_analyzer',
                    'description': f"Large data transfer from {src_ip} to external IP {dst_ip}"
                })
            
            # 3. Check for anomaly scores from ML models
            if src_ip in self.ip_behavior and len(self.ip_behavior[src_ip]['scores']) > 0:
                avg_score = sum(self.ip_behavior[src_ip]['scores']) / len(self.ip_behavior[src_ip]['scores'])
                if avg_score > self.anomaly_threshold:
                    alerts.append({
                        'timestamp': current_time,
                        'type': 'Persistent Anomalous Behavior',
                        'severity': 'high',
                        'source': 'ml_network_analyzer',
                        'description': f"IP {src_ip} shows persistent anomalous behavior (score: {avg_score:.2f})"
                    })
        
        return alerts
    
    def _cleanup_old_data(self, cutoff_time):
        """Remove old entries from tracking dictionaries"""
        for ip in list(self.ip_behavior.keys()):
            if self.ip_behavior[ip]['last_seen'] < cutoff_time:
                del self.ip_behavior[ip]
                
    def _is_internal_ip(self, ip):
        """Check if IP is in private ranges"""
        try:
            ip_obj = ipaddress.ip_address(ip)
            return ip_obj.is_private
        except ValueError:
            return False