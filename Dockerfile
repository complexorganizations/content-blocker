FROM ubuntu:latest
RUN sudo apt-get update && \
    sudo apt-get install software-properties-common git -y && \
    sudo add-apt-repository ppa:longsleep/golang-backports -y && \
    sudo apt-get install golang-go -y && \
    git clone https://github.com/complexorganizations/content-blocker
