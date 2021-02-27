# ml-analyzer

The goal of this project is to implement an ML model analysis framework. Extract the model in the apk and attack the experiment.


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
Now, let's run `ml-analyzer` by: 
```
python ./ml_analyzer/main.py
```

## Test

We write test code and use `pytest` to execute these tests. You do not need to install `pytest` manually, which is already included in the virtual environment. 

Just enter the `pipenv` shell and run:

```shell
pytest --log-cli-level DEBUG
```

