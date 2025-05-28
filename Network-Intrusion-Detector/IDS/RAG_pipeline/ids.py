import ollama
import pandas as pd
import numpy as np
import pickle
from typing import Dict, Any, Optional
import logging
from datetime import datetime
from pathlib import Path

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class NetworkAnalyzer:
    def __init__(self, model_path: str = 'LDA_model.pkl'):
        """Initialize both intrusion detection and LLM components."""
        self.model_path = model_path
        self.model = self._load_model()
        self.default_values = {
            'count': 0.77,  # High number of connections
    'srv_serror_rate': 0.25,  # High service error rate
    'serror_rate': 0.1,  # Elevated general error rate
    'dst_host_serror_rate': 0.5,  # High destination host service error rate
    'dst_host_same_srv_rate': 0.15,  # Low same service rate
    'dst_host_srv_serror_rate': 0.4,  # High rate of service errors on the host
    'dst_host_srv_count': 300,  # Many different services accessed
    'protocol_type_tcp': 1,  # TCP heavily utilized
    'service_http': 1,  # HTTP traffic is being utilized
    'service_ftp': 0,  # Not commonly targeted in DoS
    'service_smtp': 0,  # Not commonly targeted in DoS
    'service_ssh': 1,  # High SSH attempts may indicate brute force
    'service_telnet': 0,  # Rarely used in DoS attacks
    'flag_SF': 0.5,  # Percentage of successful connections drops
    'flag_REJ': 0.5,  # High percentage of rejected connections
        }

    def _load_model(self) -> Any:
        """Load the intrusion detection model."""
        try:
            if not Path(self.model_path).exists():
                raise FileNotFoundError(f"Model file not found: {self.model_path}")

            with open(self.model_path, 'rb') as f:
                model = pickle.load(f)
            logger.info("Model loaded successfully")
            return model
        except Exception as e:
            logger.error(f"Error loading model: {str(e)}")
            raise

    def get_llm_analysis(self, prediction_results: Dict[str, Any], input_data: Dict[str, float]) -> str:
        """Get detailed analysis from LLama model."""
        # Prepare context for LLM
        context = {
            "prediction": "Intrusion Detected" if prediction_results['prediction'] == 1 else "Normal Traffic",
            "confidence": f"{prediction_results['confidence']:.2%}",
            "key_metrics": {
                "error_rates": {
                    "srv_error_rate": input_data.get('srv_serror_rate', self.default_values['srv_serror_rate']),
                    "general_error_rate": input_data.get('serror_rate', self.default_values['serror_rate'])
                },
                "connection_patterns": {
                    "connection_count": input_data.get('count', self.default_values['count']),
                    "same_service_rate": input_data.get('dst_host_same_srv_rate',
                                                        self.default_values['dst_host_same_srv_rate'])
                },
                "services": {
                    "http": input_data.get('service_http', self.default_values['service_http']),
                    "ftp": input_data.get('service_ftp', self.default_values['service_ftp']),
                    "smtp": input_data.get('service_smtp', self.default_values['service_smtp']),
                    "ssh": input_data.get('service_ssh', self.default_values['service_ssh'])
                }
            }
        }

        # Create prompt for LLM
        prompt = f"""
        As a network security expert, analyze the following network traffic patterns and provide a detailed assessment:

        Prediction: {context['prediction']}
        Confidence: {context['confidence']}

        Key Metrics:
        1. Error Rates:
           - Service Error Rate: {context['key_metrics']['error_rates']['srv_error_rate']:.3f}
           - General Error Rate: {context['key_metrics']['error_rates']['general_error_rate']:.3f}

        2. Connection Patterns:
           - Connection Count (normalized): {context['key_metrics']['connection_patterns']['connection_count']:.3f}
           - Same Service Rate: {context['key_metrics']['connection_patterns']['same_service_rate']:.3f}

        3. Active Services:
           - HTTP: {'Yes' if context['key_metrics']['services']['http'] else 'No'}
           - FTP: {'Yes' if context['key_metrics']['services']['ftp'] else 'No'}
           - SMTP: {'Yes' if context['key_metrics']['services']['smtp'] else 'No'}
           - SSH: {'Yes' if context['key_metrics']['services']['ssh'] else 'No'}

        Please provide:
        1. A detailed analysis of these patterns
        2. Potential security implications
        3. Recommended actions
        4. Risk level assessment
        """

        try:
            response = ollama.chat(model='llama3.2', messages=[
                {
                    'role': 'system',
                    'content': 'You are an expert network security analyst providing detailed analysis of network traffic patterns.'
                },
                {
                    'role': 'user',
                    'content': prompt
                }
            ])
            return response['message']['content']
        except Exception as e:
            logger.error(f"Error getting LLM analysis: {str(e)}")
            return "Error: Unable to get detailed analysis"

    def analyze_traffic(self, input_data: Optional[Dict[str, float]] = None) -> Dict[str, Any]:
        """Analyze traffic patterns using both ML model and LLM."""
        if input_data is None:
            input_data = self.default_values

        try:
            # Prepare data for prediction
            input_df = pd.DataFrame([input_data])

            # Make prediction
            prediction = self.model.predict(input_df)
            prediction_proba = self.model.predict_proba(input_df)

            # Get basic results
            results = {
                'prediction': prediction[0],
                'confidence': float(np.max(prediction_proba)),
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'features_used': input_data
            }

            # Get detailed LLM analysis
            results['detailed_analysis'] = self.get_llm_analysis(results, input_data)

            return results

        except Exception as e:
            logger.error(f"Error in analysis: {str(e)}")
            raise

    def check_risky_values(self, input_data: Dict[str, float], risky_thresholds: Dict[str, float]) -> str:
        """Check for risky values in the input data against custom thresholds."""
        risky_reports = []
        for key, threshold in risky_thresholds.items():
            if input_data.get(key, self.default_values[key]) > threshold:
                risky_reports.append(f"{key} exceeds risky threshold: {input_data[key]:.3f} > {threshold:.3f}")

        if risky_reports:
            return "Risky Values Detected:\n" + "\n".join(risky_reports)
        return "No risky values detected."


def interactive_session():
    """Run an interactive analysis session."""
    analyzer = NetworkAnalyzer()

    print("=== Network Security Analysis System ===")
    print("Using ML model for detection and LLM for detailed analysis")

    while True:
        try:
            print("\nOptions:")
            print("1. Analyze with custom values of your network traffic patterns")
            print("2. Analyze with default values of this network traffic patterns")
            print("3. Analyze risky custom values based on the network traffic pattern")
            print("4. Get information about different parameters in the network and working of the model")
            print("5. Exit")

            choice = input("\nEnter your choice (1-5): ")

            if choice == '5':
                break

            if choice == '4':
                print("Hii")
                continue

            if choice == '1':
                print("\nEnter values (press Enter for default):")
                input_data = {}
                for key in analyzer.default_values.keys():
                    value = input(f"{key} [{analyzer.default_values[key]}]: ").strip()
                    if value:
                        input_data[key] = float(value)
                    else:
                        input_data[key] = analyzer.default_values[key]
            elif choice == '2':
                input_data = analyzer.default_values.copy()
            elif choice == '3':
                print("\nEnter risky thresholds:")
                risky_thresholds = {}
                for key in analyzer.default_values.keys():
                    value = input(f"{key} [{analyzer.default_values[key]}]: ").strip()
                    if value:
                        risky_thresholds[key] = float(value)
                    else:
                        risky_thresholds[key] = analyzer.default_values[key]

                print("\nEnter custom values to analyze:")
                input_data = {}
                for key in analyzer.default_values.keys():
                    value = input(f"{key} [{analyzer.default_values[key]}]: ").strip()
                    if value:
                        input_data[key] = float(value)
                    else:
                        input_data[key] = analyzer.default_values[key]

                risky_report = analyzer.check_risky_values(input_data, risky_thresholds)
                print("\n=== Risky Value Analysis ===")
                print(risky_report)
                continue
            else:
                print("Invalid choice. Please try again.")
                continue

            # Get analysis
            results = analyzer.analyze_traffic(input_data)

            # Display results
            print("\n=== Analysis Results ===")
            print(f"Timestamp: {results['timestamp']}")
            print(f"Prediction: {'Intrusion Detected!' if results['prediction'] == 1 else 'Normal Traffic'}")
            print(f"Confidence: {results['confidence']:.2%}")
            print(f"Detailed Analysis:\n{results['detailed_analysis']}")

        except ValueError:
            print("Invalid input. Please enter numeric values.")
        except Exception as e:
            print(f"Error: {e}")


if __name__ == "__main__":
    interactive_session()
