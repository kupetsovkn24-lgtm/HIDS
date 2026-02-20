from .process import ProcessSensor
from .network import NetworkSensor
from .registry import RegistrySensor
from .file import FileSensor
from .task import TaskSensor

# Expose all sensors for convenient single-line imports
__all__ = [
    'ProcessSensor', 
    'NetworkSensor', 
    'RegistrySensor', 
    'FileSensor', 
    'TaskSensor'
]