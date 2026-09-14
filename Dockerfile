FROM ubuntu:latest
LABEL authors="felipe.torquato"

ENTRYPOINT ["top", "-b"]