FROM debian:stable-slim
RUN apt-get update && apt-get install -y mosquitto
RUN echo "listener 9138" > /etc/mosquitto.conf
RUN echo "allow_anonymous true" >> /etc/mosquitto.conf
CMD mosquitto -c /etc/mosquitto.conf
