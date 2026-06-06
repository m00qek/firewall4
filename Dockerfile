FROM openwrt/rootfs:x86-64-openwrt-25.12

RUN mkdir -p /var/lock && \
    wget -qO /tmp/utest.apk \
        https://github.com/m00qek/utest/releases/download/v1.1.0/ucode-utest-1.1.0.c439f238-r1.apk && \
    apk add --allow-untrusted /tmp/utest.apk && \
    rm /tmp/utest.apk

WORKDIR /app
