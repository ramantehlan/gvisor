FROM tensorflow/tensorflow:1.13.2

RUN apt-get update \
    && apt-get install -y git
RUN git clone --depth 1 https://github.com/aymericdamien/TensorFlow-Examples.git
RUN python -m pip install --no-cache-dir -U pip setuptools
RUN python -m pip install --no-cache-dir matplotlib

WORKDIR /TensorFlow-Examples/examples

ENV PYTHONPATH="$PYTHONPATH:/TensorFlow-Examples/examples"

ENV workload "3_NeuralNetworks/convolutional_network.py"
CMD python ${workload}
