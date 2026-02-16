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
from scapy.all import get_if_list

def load_config(path="project_alpha/config.yaml"):
    with open(path, "r") as f:
        return yaml.safe_load(f)

def main():
    setup_logging()
    print_banner()
    print("\n[bold cyan]======================================================[/bold cyan]")
    print("[bold cyan]        ARGUS - The All-Seeing Eye[/bold cyan]")
    print("[bold cyan]======================================================[/bold cyan]")
    
    print("[bold cyan]======================================================[/bold cyan]")
    
    epilog_text = """
[bold]Step-by-Step Guide:[/bold]
1. [yellow]Train[/yellow]:   python3 project_alpha/main.py --train
2. [yellow]Detect[/yellow]:  python3 project_alpha/main.py --detect
3. [yellow]Visuals[/yellow]: streamlit run dashboard.py (or ./run_dashboard.bat on Windows)
4. [yellow]Report[/yellow]:  python3 -m project_alpha.src.reporting
"""
    parser = argparse.ArgumentParser(
        description="Project Alpha: Network Anomaly Detector",
        epilog=epilog_text,
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("--train", action="store_true", help="Start Training Mode to learn normal network behavior.")
    parser.add_argument("--detect", action="store_true", help="Start Detection Mode to identify anomalies in real-time.")
    parser.add_argument("--interface", type=str, help="Specify network interface (e.g., eth0, wlan0). Overrides config.yaml.")
    parser.add_argument("--pcap", type=str, help="Analyze an offline PCAP file instead of live traffic.")
    parser.add_argument("--list-interfaces", action="store_true", help="Show all available network interfaces on this machine.")
    
    args = parser.parse_args()

    if args.list_interfaces:
        print("[bold]Available Network Interfaces:[/bold]")
        for iface in get_if_list():
            print(f" - {iface}")
        sys.exit(0)
    
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
