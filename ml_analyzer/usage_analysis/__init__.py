from enum import Enum, auto


class ModelUsage(Enum):
    IMAGE = auto()
    TEXT = auto()
    AUDIO = auto()
    OTHER = auto()
