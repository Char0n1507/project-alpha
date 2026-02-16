import threading
from scapy.all import sniff, conf
import logging

# Suppress verbose Scapy output
conf.verb = 0

logger = logging.getLogger(__name__)

class PacketSniffer:
    """
    threaded Packet Sniffer wrapper around Scapy.
    """
    def __init__(self, interface, callback=None, pcap_path=None):
        self.interface = interface
        self.callback = callback
        self.pcap_path = pcap_path
        self.stop_event = threading.Event()
        self.thread = None

    def start(self):
        """Start sniffing in a background thread."""
        if self.pcap_path:
            logger.info(f"Reading packets from file: {self.pcap_path}...")
        else:
            logger.info(f"Starting capturing on interface {self.interface}...")
            
        self.thread = threading.Thread(target=self._sniff_loop)
        self.thread.daemon = True
        self.thread.start()

    def _sniff_loop(self):
        try:
            if self.pcap_path:
                # Offline mode
                sniff(
                    offline=self.pcap_path,
                    prn=self.callback,
                    store=False
                )
                logger.info("PCAP processing complete.")
            else:
                # Live mode
                try:
                    sniff(
                        iface=self.interface,
                        prn=self.callback,
                        store=False,
                        stop_filter=lambda x: self.stop_event.is_set()
                    )
                except OSError:
                    # Fallback: Try default interface if specified one fails
                    logger.warning(f"Interface '{self.interface}' not found. Falling back to default...")
                    sniff(
                        iface=None, # Scapy defaults to system default
                        prn=self.callback,
                        store=False,
                        stop_filter=lambda x: self.stop_event.is_set()
                    )
        except Exception as e:
            logger.error(f"Sniffing failed: {e}")

    def stop(self):
        """Stop the sniffer thread."""
        logger.info("Stopping capture...")
        self.stop_event.set()
        if self.thread:
            self.thread.join(timeout=2.0)
