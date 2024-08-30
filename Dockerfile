FROM ubuntu
LABEL version="1.0"
LABEL description="Mikrotik DHCP DNS Updater"

ENV container docker
ENV LC_ALL C

RUN apt-get update -y; apt-get install -y python3-flask python3-dnspython bind9-utils ; apt-get clean -y

ADD mikrotik.py /mikrotik.py
RUN chmod 755 /mikrotik.py

EXPOSE 5000

CMD ["/mikrotik.py"]

HEALTHCHECK --interval=5m --timeout=3s CMD curl localhost:5000 | grep Mikrotik || exit 1

