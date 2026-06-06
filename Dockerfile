FROM openwrt/rootfs:x86-64-openwrt-25.12

RUN mkdir -p /var/lock && \
    wget -qO /tmp/utest.apk \
        https://github.com/m00qek/utest/releases/download/v1.2.0/ucode-utest-1.2.0.43488a7a-r1.apk && \
    apk add --allow-untrusted /tmp/utest.apk && \
    rm /tmp/utest.apk

WORKDIR /app
