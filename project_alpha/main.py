import argparse
import sys
import os
import yaml
# Fix imports when running directly
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
sys.path.append(parent_dir)

from project_alpha.logging_config import setup_logging
from project_alpha.src.detector import AnomalyDetector
from project_alpha.src.cli_rich import print_banner

def load_config(path="project_alpha/config.yaml"):
    with open(path, "r") as f:
        return yaml.safe_load(f)

def main():
    setup_logging()
    print_banner()
    print("\n[bold cyan]======================================================[/bold cyan]")
    print("[bold cyan]        ARGUS - The All-Seeing Eye[/bold cyan]")
    print("[bold cyan]======================================================[/bold cyan]")
    
    parser = argparse.ArgumentParser(description="Project Alpha: Network Anomaly Detector")
    parser.add_argument("--train", action="store_true", help="Run in training mode to build baseline.")
    parser.add_argument("--detect", action="store_true", help="Run in detection mode.")
    parser.add_argument("--interface", type=str, help="Override network interface from config.")
    parser.add_argument("--pcap", type=str, help="Path to PCAP file for offline training/detection.")
    
    args = parser.parse_args()
    
    config = load_config()
    interface = args.interface if args.interface else config['network']['interface']
    model_path = config['model']['save_path']
    
    detector = AnomalyDetector(interface=interface, model_path=model_path, pcap_path=args.pcap)
    
    if args.train:
        count = config['network']['train_packet_count']
        detector.train_mode(packet_count=count)
    elif args.detect:
        detector.detect_mode()
    else:
        parser.print_help()
        sys.exit(1)

if __name__ == "__main__":
    main()
