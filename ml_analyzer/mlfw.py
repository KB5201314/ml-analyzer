from enum import Enum, auto


class MLFrameworkType(Enum):
    TENSORFLOW = auto() # also called as tensorflow-android
    TF_LITE = auto()    # tensorflow-lite
    CAFFE = auto()
    CAFFE2 = auto()
    MXNET = auto()
    DEEP_LEARNING = auto()
    NCNN = auto()
    OPENCV = auto()
    FEATHER_CNN = auto()
    PADDLE_MOBILE = auto()
    PADDLE_LITE = auto()
    XNN = auto()
    SUPERID = auto()
    PARROTS = auto()
    MACE = auto()
    SNPE = auto()
    CNNDROID = auto()
    CORE_ML = auto()
