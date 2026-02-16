
import numpy as np
import logging
import json
import time
import yaml
import os
from scapy.all import wrpcap, IP
from .features import FeatureExtractor
from .sniffer import PacketSniffer
from .autoencoder import AutoEncoder
from .cli_rich import print_alert
from project_alpha.src.database import ForensicDB
from project_alpha.src.geoip import GeoEnricher
import re

logger = logging.getLogger(__name__)

class AnomalyDetector:
    def __init__(self, interface, model_path=None, pcap_path=None):
        self.interface = interface
        self.model_path = model_path
        self.pcap_path = pcap_path
        self.db = ForensicDB()
        self.geo = GeoEnricher()
        self.sniffer = None
        self.feature_extractor = FeatureExtractor()
        self.model = AutoEncoder()
        self.whitelist = []
        self.blacklist = []
        self._load_lists()
        
        # Load model if exists, else we need to train
        try:
            self.model.load(model_path)
        except:
            logger.warning(f"Model {model_path} not found. You must train first.")

    def _load_lists(self):
        try:
            with open("whitelist.yaml", "r") as f:
                data = yaml.safe_load(f)
                self.whitelist = data.get('whitelist', [])
                self.blacklist = data.get('blacklist', [])
        except FileNotFoundError:
            logger.warning("whitelist.yaml not found. Proceeding without filters.")

    def train_mode(self, packet_count=1000):
        """
        Capture packets, extract features, and train the model.
        """
        source = f"file {self.pcap_path}" if self.pcap_path else f"interface {self.interface}"
        logger.info(f"Starting Training Mode from {source}. Capturing {packet_count} packets...")
        
        captured_data = []
        
        def train_callback(packet):
            vec = self.feature_extractor.extract(packet)
            captured_data.append(vec)
            if len(captured_data) % 100 == 0:
                logger.info(f"Collected {len(captured_data)}/{packet_count} packets")

        sniffer = PacketSniffer(self.interface, callback=train_callback, pcap_path=self.pcap_path)
        sniffer.start()
        
        # Wait until we have enough packets OR pcap finishes
        try:
            while len(captured_data) < packet_count:
                if self.pcap_path and not sniffer.thread.is_alive():
                    # PCAP finished
                    break
                time.sleep(0.1)
        except KeyboardInterrupt:
            logger.info("Training interrupted by user.")
            
        sniffer.stop()
        
        if len(captured_data) > 0:
            logger.info("Processing data for training...")
            data_matrix = np.vstack(captured_data)
            self.model.train(data_matrix)
            self.model.save(self.model_path)
            logger.info("Model training complete and saved.")
        else:
            logger.error("No data collected. Training aborted.")

    def detect_mode(self):
        """
        Real-time detection loop.
        """
        if self.model.model is None:
            logger.error("Model not loaded. Please train first.")
            return

        if self.pcap_path:
             logger.info(f"Starting Detection Mode on file {self.pcap_path}...")
        else:
             logger.info(f"Starting Detection Mode on {self.interface}...")
             
        logger.info(f"Anomaly Threshold: {self.model.threshold}")
        
        packet_count = 0
        
        def detect_callback(packet):
            nonlocal packet_count
            packet_count += 1
            
            vec = self.feature_extractor.extract(packet)
            loss = self.model.predict(vec)
            
            if loss[0] > self.model.threshold:
                self._alert(packet, loss[0])
            
            if packet_count % 10 == 0:
                print(f"[+] Analyzed {packet_count} packets...", end="\r")

        sniffer = PacketSniffer(self.interface, callback=detect_callback, pcap_path=self.pcap_path)
        sniffer.start()
        
        print(f"\n[+] ARGUS is now watching {self.interface} for anomalies...")
        print("[+] Press Ctrl+C to stop.\n")
        
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            logger.info("Detection stopped.")
            sniffer.stop()

    def _is_whitelisted(self, packet):
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            if src_ip in self.whitelist or dst_ip in self.whitelist:
                return True
        return False

    def _alert(self, packet, loss):
        """
        Trigger an alert for an anomalous packet.
        """
        # Check Whitelist
        if self._is_whitelisted(packet):
            return

        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        src_ip = "Unknown"
        dst_ip = "Unknown"
        
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            
        location = self.geo.lookup(src_ip)
        
        # Console Output
        try:
            print_alert(timestamp, src_ip, dst_ip, loss, location)
        except:
            pass
        
        # Save to Database
        self.db.log_anomaly(timestamp, src_ip, dst_ip, float(loss), str(location))
        
        # EVIDENCE LOCKER: Save the malicious packet
        self._save_evidence(packet, src_ip, timestamp)

    def _save_evidence(self, packet, ip, timestamp):
        try:
            # Sanitize filename
            safe_time = timestamp.replace(":", "-").replace(" ", "_")
            evidence_dir = "evidence"
            if not os.path.exists(evidence_dir):
                os.makedirs(evidence_dir)
            filename = os.path.join(evidence_dir, f"alert_{safe_time}_{ip}.pcap")
            wrpcap(filename, packet)
        except Exception as e:
            logger.error(f"Failed to save evidence: {e}")
