#!/bin/bash

# This file is used to build python source distrubute file (res/ncnn.tar.gz) from ncnn github source code

ncnn_path=/tmp/ncnn

echo "cloning source code of ncnn to /tmp/ncnn"
git clone git@github.com:Tencent/ncnn.git $ncnn_path
pushd $ncnn_path
git submodule init && git submodule update

echo "build"
mkdir build
pushd build
cmake -DNCNN_PYTHON=ON ..
make -j

echo "build sdist"
pushd $ncnn_path/python/
python setup.py sdist

popd
popd
popd

echo "copy to res/"
cp $ncnn_path/python/dist/ncnn-*.tar.gz ./res/ncnn.tar.gz

echo "cleaning"
rm -rf $ncnn_path
