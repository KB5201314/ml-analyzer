#!/bin/bash

if ! command -v protoc &> /dev/null; then
    echo "protoc could not be found, please install it first"
    exit
fi

# https://stackoverflow.com/a/49329125
curl -L https://github.com/BVLC/caffe/raw/828dd100445137409dd40694b4ea14570f43e599/src/caffe/proto/caffe.proto -o ml_analyzer/misc/caffe.proto
protoc --python_out=. ml_analyzer/misc/caffe.proto

# test
echo "Testing generated .py files..."
python -c 'import ml_analyzer.misc.caffe_pb2'
