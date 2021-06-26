FROM ubuntu:latest
RUN apt-get update && \
    apt-get install software-properties-common git -y && \
    add-apt-repository ppa:longsleep/golang-backports -y && \
    apt-get install golang-go -y
