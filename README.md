# ml-analyzer

The goal of this project is to implement a ML model analysis framework. To extract the model in the APK and perform some simple attack experiments.


# How to start
## Before starting

We are using [`pipenv`](https://github.com/pypa/pipenv) to manage python dependencies, so you may need to install `pipenv` first:
```shell
pip install pipenv
```
Once you have done that, you can install all the dependencies by the following command:
```shell
pipenv sync
```
This will also create a standalone python virtual environment with all packages installed.

## Run

Before running, we need to spawn a `pipenv` shell environment first:
```shell
pipenv shell
``` 


Now you can get help message of `ml-analyzer` tool by:
```sh
python main.py --help
```

```text
usage: ml-analyzer [-h] [--adb-serial ADB_SERIAL] {detect,extract,run} ...

A ML model analysis framework.

positional arguments:
  {detect,extract,run}  sub-command help

optional arguments:
  -h, --help            show this help message and exit
  --adb-serial ADB_SERIAL
                        A serial number which can be used to identify a
                        connected android device. can be found in `adb device
                        -l`.

```

### detect ML framework

```sh
python main.py detect --apk ./tests/apks/tflite_example_image_classification.apk
```

### extract ML framework

```sh
python main.py extract --apk ./tests/apks/tflite_example_image_classification.apk
```

## Test

We write test code and use `pytest` to execute these tests. You do not need to install `pytest` manually, which is already included in the virtual environment. 

Just enter the `pipenv` shell and run:

```shell
pytest --log-cli-level DEBUG
```

## Scripts

There are some tools that can be used in the process in the `scripts` directory
