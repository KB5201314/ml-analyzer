from enum import Enum, auto


class MLFrameworkType(Enum):
    TENSORFLOW = auto() # also called as tensorflow-android
    TF_LITE = auto()    # tensorflow-lite
    PADDLE_MOBILE = auto()
    PADDLE_LITE = auto()
    CAFFE = auto()
    CAFFE2 = auto()
    PYTORCH = auto()
    MXNET = auto()
    DEEP_LEARNING = auto()
    NCNN = auto()
    OPENCV = auto()
    FEATHER_CNN = auto()
    XNN = auto()
    SUPERID = auto()
    PARROTS = auto()
    MACE = auto()
    SNPE = auto()
    CNNDROID = auto()
    CORE_ML = auto()
