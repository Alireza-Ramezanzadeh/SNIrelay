#!/bin/sh
# docker-entrypoint.sh
# Mirrors the zhpjy/sniproxy-proxychains behaviour:
#   -e PROXY="socks5 127.0.0.1 10808"
# The PROXY env var is passed directly as --proxy to the binary.

set -e

# Docker CMD used to pass the binary name; ignore it if present.
case "$1" in
    snirelay|/usr/local/bin/snirelay) shift ;;
esac

CONFIG_FILE="${CONFIG_FILE:-/etc/sniproxy/config.yaml}"
LOG_LEVEL="${LOG_LEVEL:-info}"
LOG_FILE="${LOG_FILE:-}"

# Default route gateway from /proc/net/route.
docker_host_gateway() {
    awk '$2 == "00000000" {
        g = $3
        if (length(g) == 8) {
            printf "%d.%d.%d.%d\n",
                ("0x" substr(g, 7, 2)) + 0,
                ("0x" substr(g, 5, 2)) + 0,
                ("0x" substr(g, 3, 2)) + 0,
                ("0x" substr(g, 1, 2)) + 0
        }
        exit
    }' /proc/net/route 2>/dev/null
}

# Docker bridge gateways (remap 127.0.0.1 → 172.17.0.1). Public/ISP gateways are host-network.
is_docker_bridge_gateway() {
    case "$1" in
        172.17.*|172.18.*|172.19.*|172.20.*|172.21.*|172.22.*|192.168.65.*) return 0 ;;
        *) return 1 ;;
    esac
}

# 127.0.0.1 in PROXY is the container loopback unless the default route is docker0.
remap_proxy_loopback() {
    [ -z "${PROXY}" ] && return 0
    [ ! -f /.dockerenv ] && return 0
    case "${HOST_PROXY_GATEWAY:-}" in
        off|OFF) return 0 ;;
    esac
    case " ${PROXY} " in
        *" 127.0.0.1 "*|*" localhost "*) ;;
        *) return 0 ;;
    esac

    gw="${HOST_PROXY_GATEWAY:-}"
    [ -z "${gw}" ] && gw=$(docker_host_gateway)
    [ -z "${gw}" ] && return 0

    if ! is_docker_bridge_gateway "${gw}"; then
        echo "[entrypoint] Docker host network (gateway ${gw}): keeping 127.0.0.1 in PROXY"
        return 0
    fi

    PROXY=$(echo "${PROXY}" | sed -e "s/127\\.0\\.0\\.1/${gw}/g" -e "s/localhost/${gw}/g")
    export PROXY
    echo "[entrypoint] Docker bridge: remapped loopback in PROXY → ${gw}"
    echo "[entrypoint]           xray/SOCKS must listen on 0.0.0.0:10808 (allow LAN), or use: docker run --network host"
}

remap_proxy_loopback

# Per-process open files (sysctl fs.file-max alone is not enough).
if [ -n "${NOFILE_LIMIT:-}" ]; then
    ulimit -n "${NOFILE_LIMIT}" 2>/dev/null || \
        echo "[entrypoint] warning: could not set ulimit -n ${NOFILE_LIMIT}"
elif ulimit -n 1048576 2>/dev/null; then
    :
else
    ulimit -n 65535 2>/dev/null || true
fi

log_file_args() {
    if [ -n "${LOG_FILE}" ]; then
        echo "--log-file" "${LOG_FILE}"
    fi
}

if [ -n "${PROXY}" ]; then
    echo "[entrypoint] Using upstream proxy: ${PROXY}"
    echo "[entrypoint] Starting: snirelay --config ${CONFIG_FILE} --log-level ${LOG_LEVEL} --proxy ${PROXY}"
    # shellcheck disable=SC2046
    exec snirelay --config "${CONFIG_FILE}" --log-level "${LOG_LEVEL}" --proxy "${PROXY}" $(log_file_args) "$@"
fi

echo "[entrypoint] Starting: snirelay --config ${CONFIG_FILE} --log-level ${LOG_LEVEL}"
# shellcheck disable=SC2046
exec snirelay --config "${CONFIG_FILE}" --log-level "${LOG_LEVEL}" $(log_file_args) "$@"
