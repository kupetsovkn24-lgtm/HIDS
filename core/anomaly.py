import datetime
from dataclasses import dataclass, field
from typing import Dict, Any

@dataclass
class AnomalyEvent:
    """
    Data structure describing a single anomaly.
    """
    severity: int                  # Threat level (1-10)
    category: str                  # Category (Process, Network, Registry)
    description: str               # What happened
    details: Dict[str, Any] = field(default_factory=dict)  # Details (PID, IP, path, etc.)

    # Auto-set timestamp on creation
    timestamp: datetime.datetime = field(default_factory=datetime.datetime.now)

    def __str__(self):
        return f"[{self.timestamp.strftime('%H:%M:%S')}][{self.category}][Sev: {self.severity}] {self.description}"