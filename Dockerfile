# DARK CRACKER OPS Generation 2 — Docker Container
# Build: docker build -t darkcracker .
# Run:   docker run --privileged --net=host -e DISPLAY=$DISPLAY -v /tmp/.X11-unix:/tmp/.X11-unix darkcracker

FROM kalilinux/kali-rolling

LABEL maintainer="DARK SEA TEAM" version="2.0.0"

ENV DEBIAN_FRONTEND=noninteractive
ENV ANTHROPIC_API_KEY=""

RUN apt-get update -qq && apt-get install -y \
    python3-pip python3-pyqt5 aircrack-ng hcxdumptool hcxtools hashcat nmap \
    arp-scan reaver iw wireless-tools net-tools network-manager hostapd dnsmasq \
    iptables sshpass bluez bluetooth nikto gobuster tcpdump tshark curl wget git \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt /opt/darkcracker/requirements.txt
RUN pip3 install -r /opt/darkcracker/requirements.txt --break-system-packages -q 2>/dev/null || \
    pip3 install -r /opt/darkcracker/requirements.txt -q
RUN pip3 install reportlab anthropic --break-system-packages -q 2>/dev/null || true

COPY . /opt/darkcracker/
WORKDIR /opt/darkcracker

RUN mkdir -p /root/.darkcracker/{captures,reports,sessions,wordlists}
RUN chmod +x run.sh install.sh

ENV DISPLAY=:0
ENTRYPOINT ["python3", "/opt/darkcracker/main.py"]
