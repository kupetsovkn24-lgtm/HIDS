from abc import ABC, abstractmethod
from typing import List
from core.anomaly import AnomalyEvent

class BaseSensor(ABC):
    """
    Abstract base class for all sensors.
    Ensures every subclass implements a scan() method.
    """

    @abstractmethod
    def scan(self) -> List[AnomalyEvent]:
        """
        Main scan method. Must be implemented by each sensor.

        Returns:
            List[AnomalyEvent]: List of detected anomalies.
        """
        pass