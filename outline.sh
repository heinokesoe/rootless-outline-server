#!/bin/bash

setup_log="$(mktemp -t setup_logXXX)"
red="\033[1;31m"
green="\033[1;32m"
cyan="\033[0;36m"
normal="\033[0m"

spin() {
    local i=0
    local sp="/-\|"
    local n=${#sp}
    printf " "
    sleep 0.2
    while true; do
        printf "\b${cyan}%s${normal}" "${sp:i++%n:1}"
        sleep 0.2
    done
}

log() {
    exec 3>&1 4>&2
    trap 'exec 2>&4 1>&3' 0 1 2 3
    exec 1>>"$setup_log" 2>&1
    echo -e "\n$1\n"
}

run_step() {
    local msg="$1"
    local func=$2
    local pos
    IFS='[;' read -p $'\e[6n' -d R -a pos -rs
    local current_row=${pos[1]}
    local current_col=${pos[2]}
    printf "${cyan}$msg${normal}\033[$current_row;50H"
    spin &
    spinpid=$!
    trap 'kill $spinpid' SIGTERM SIGKILL
    $func "$msg" &>/dev/null
    if [[ $? -eq 0 ]]; then
        kill $spinpid
        printf "\b \t\t${cyan}[OK]${normal}\n"
    else
        kill $spinpid
        printf "\b \t\t${red}[Failed]${normal}\n"
        printf "\n${red}Sorry! $msg went wrong. See full log at $setup_log ${normal}\n\n"
        exit 1
    fi
}

display_usage() {
    cat <<EOF

Usage: install.sh [--hostname <hostname>] [--api-port <port>] [--keys-port <port>]
       install.sh [--remove]

  --hostname   The hostname to be used to access the management API and access keys
  --api-port   The port number for the management API
  --keys-port  The port number for the access keys
  --remove     Remove and clean up

EOF
}

check_command() {
    check_command_result=()
    for i in $@; do
        if ! command -v $i &>/dev/null; then
            check_command_result+=("$i")
        fi
    done
}

fetch() {
    curl --silent --show-error --fail "$@"
}

get_random_port() {
    local -i num=0
    until (( 1024 <= num && num < 65536)); do
        num=$(( RANDOM + (RANDOM % 2) * 32768 ));
    done;
    echo "${num}";
}

create_outline_dir() {
    log "$1"
    mkdir -p "${SHADOWBOX_DIR}"
    chmod u+s,ug+rwx,o-rwx "${SHADOWBOX_DIR}"
}

set_api_port() {
    log "$1"
    API_PORT="${FLAGS_API_PORT}"
    if (( API_PORT == 0 )); then
        API_PORT=${SB_API_PORT:-$(get_random_port)}
    fi
    readonly API_PORT
}

create_persisted_state_dir() {
    log "$1"
    readonly STATE_DIR="${SHADOWBOX_DIR}/persisted-state"
    mkdir -p "${STATE_DIR}"
    chmod ug+rwx,g+s,o-rwx "${STATE_DIR}"
}

safe_base64() {
    local url_safe
    url_safe="$(base64 -w 0 - | tr '/+' '_-')"
    echo -n "${url_safe%%=*}"
}

generate_secret_key() {
    log "$1"
    SB_API_PREFIX="$(head -c 16 /dev/urandom | safe_base64)"
    readonly SB_API_PREFIX
}

generate_certificate() {
    log "$1"
    local -r CERTIFICATE_NAME="${STATE_DIR}/shadowbox-selfsigned"
    readonly SB_CERTIFICATE_FILE="${CERTIFICATE_NAME}.crt"
    readonly SB_PRIVATE_KEY_FILE="${CERTIFICATE_NAME}.key"
    declare -a openssl_req_flags=(
        -x509 -nodes -days 36500 -newkey rsa:4096
        -subj "/CN=${PUBLIC_HOSTNAME}"
        -keyout "${SB_PRIVATE_KEY_FILE}" -out "${SB_CERTIFICATE_FILE}"
    )
    openssl req "${openssl_req_flags[@]}" >&2
}

generate_certificate_fingerprint() {
    log "$1"
    local CERT_OPENSSL_FINGERPRINT
    CERT_OPENSSL_FINGERPRINT="$(openssl x509 -in "${SB_CERTIFICATE_FILE}" -noout -sha256 -fingerprint)"
    local CERT_HEX_FINGERPRINT
    CERT_HEX_FINGERPRINT="$(echo "${CERT_OPENSSL_FINGERPRINT#*=}" | tr -d :)"
    output_config "certSha256:${CERT_HEX_FINGERPRINT}"
}

join() {
    local IFS="$1"
    shift
    echo "$*"
}

write_config() {
    log "$1"
    local -a config=()
    if (( FLAGS_KEYS_PORT != 0 )); then
        config+=("\"portForNewAccessKeys\": ${FLAGS_KEYS_PORT}")
    fi
    config+=("$(printf '"hostname": "%q"' "${PUBLIC_HOSTNAME}")")
    echo "{$(join , "${config[@]}")}" > "${STATE_DIR}/shadowbox_server_config.json"
}

pull_image() {
    log "$1"
    podman pull ${SB_IMAGE}
}

start_shadowbox() {
    log "$1"
    local -ar podman_shadowbox_flags=(
        --name "${CONTAINER_NAME}" --replace --net host
        -v "${STATE_DIR}:${STATE_DIR}"
        -e "SB_STATE_DIR=${STATE_DIR}"
        -e "SB_API_PORT=${API_PORT}"
        -e "SB_API_PREFIX=${SB_API_PREFIX}"
        -e "SB_CERTIFICATE_FILE=${SB_CERTIFICATE_FILE}"
        -e "SB_PRIVATE_KEY_FILE=${SB_PRIVATE_KEY_FILE}"
        -e "SB_METRICS_URL=${SB_METRICS_URL:-}"
        -e "SB_DEFAULT_SERVER_NAME=${SB_DEFAULT_SERVER_NAME:-}"
        --label "io.containers.autoupdate=registry"
    )
    podman run -d "${podman_shadowbox_flags[@]}" "${SB_IMAGE}" 2>&1 >/dev/null
}

wait_shadowbox() {
    log "$1"
    until fetch --insecure "${LOCAL_API_URL}/access-keys" >/dev/null; do sleep 1; done
}

create_first_user() {
    log "$1"
    fetch --insecure --request POST "${LOCAL_API_URL}/access-keys" >&2
}

output_config() {
    echo "$@" >> "${ACCESS_CONFIG}"
}

add_api_url_to_config() {
    log "$1"
    output_config "apiUrl:${PUBLIC_API_URL}"
}

check_access_key_port() {
    log "$1"
    ACCESS_KEY_PORT=$(fetch --insecure "${LOCAL_API_URL}/access-keys" |
        podman exec -i "${CONTAINER_NAME}" node -e '
            const fs = require("fs");
            const accessKeys = JSON.parse(fs.readFileSync(0, {encoding: "utf-8"}));
            console.log(accessKeys["accessKeys"][0]["port"]);
        ')
    readonly ACCESS_KEY_PORT
}

create_systemd_file() {
    log "$1"
    mkdir -p $HOME/.config/systemd/user
    podman generate systemd --new --name ${CONTAINER_NAME} --restart-policy always > $HOME/.config/systemd/user/${CONTAINER_NAME}.service
    systemctl --user enable ${CONTAINER_NAME}.service
    loginctl enable-linger $USER
}

set_hostname() {
    log "$1"
    local -ar urls=(
        'https://domains.google.com/checkip'
        'https://ipinfo.io/ip'
    )
    for url in "${urls[@]}"; do
        PUBLIC_HOSTNAME="$(fetch --ipv4 "${url}")" && return
    done
    echo "Failed to determine the server's IP address.  Try using --hostname <server IP>." >&2
    return 1
}

is_valid_port() {
    (( 0 < "$1" && "$1" <= 65535 ))
}

remove() {
    {
        systemctl --user disable ${CONTAINER_NAME}.service
        rm $HOME/.config/systemd/user/${CONTAINER_NAME}.service
        systemctl --user daemon-reload
        podman rm -f -t 0 $CONTAINER_NAME
        rm -r $SHADOWBOX_DIR
    } &> /dev/null
    echo -e "\n${green}Outline Vpn Server has been successfully removed.${normal}\n"
    exit 0
}

parse_flags() {
    [[ $# -eq 1 && "$1" == "--remove" ]] && remove
    while [[ $# -gt 0 ]]; do
        case $1 in
            --hostname)
                FLAGS_HOSTNAME="$2"
                shift
                shift
                ;;
            --api-port)
                FLAGS_API_PORT="$2"
                if ! is_valid_port "${FLAGS_API_PORT}"; then
                    echo -e "\n${red}Invalid value for ${1#--*}: ${FLAGS_API_PORT}${normal}\n" >&2
                    exit 1
                fi
                shift
                shift
                ;;
            --keys-port)
                FLAGS_KEYS_PORT="$2"
                if ! is_valid_port "${FLAGS_KEYS_PORT}"; then
                    echo -e "\n${red}Invalid value for ${1#--*}: ${FLAGS_KEYS_PORT}${normal}\n" >&2
                    exit 1
                fi
                shift
                shift
                ;;
            *|-*|--*)
                echo -e "\n${red}Unsupported flag${normal}" >&2
                display_usage >&2
                exit 1
                ;;
        esac
    done
    if (( FLAGS_API_PORT != 0 && FLAGS_API_PORT == FLAGS_KEYS_PORT )); then
        echo -e "${red}--api-port must be different from --keys-port${normal}\n" >&2
        exit 1
    fi
}

main() {
    CONTAINER_NAME="shadowbox"
    SHADOWBOX_DIR="${SHADOWBOX_DIR:-$HOME/outline}"
    MACHINE_TYPE="$(uname -m)"
    if [[ "${MACHINE_TYPE}" != "x86_64" ]]; then
        echo -e "\n\n${red}Unsupported machine type: ${MACHINE_TYPE}. Please run this script on a x86_64 machine${normal}\n\n" >&2
        exit 1
    fi
    check_command curl openssl podman
    if [[ ${#check_command_result[@]} -ne 0 ]]; then
        echo -e "\n\n${red}${check_command_result[@]} need to be installed first.${normal}\n\n"
        exit 1
    fi
    declare FLAGS_HOSTNAME=""
    declare -i FLAGS_API_PORT=0
    declare -i FLAGS_KEYS_PORT=0
    parse_flags "$@"
    umask 0007
    run_step "Creating Outline directory" "create_outline_dir"
    run_step "Setting API port" "set_api_port"
    readonly ACCESS_CONFIG="${ACCESS_CONFIG:-${SHADOWBOX_DIR}/access.txt}"
    if [[ -s "${ACCESS_CONFIG}" ]]; then
        cp "${ACCESS_CONFIG}" "${ACCESS_CONFIG}.bak" && true > "${ACCESS_CONFIG}"
    fi
    readonly SB_IMAGE="${SB_IMAGE:-quay.io/outline/shadowbox:stable}"
    PUBLIC_HOSTNAME="${FLAGS_HOSTNAME:-${SB_PUBLIC_IP:-}}"
    if [[ -z "${PUBLIC_HOSTNAME}" ]]; then
        run_step "Setting PUBLIC_HOSTNAME to external IP" "set_hostname"
    fi
    readonly PUBLIC_HOSTNAME
    run_step "Creating persistent state dir" "create_persisted_state_dir"
    run_step "Generating secret key" "generate_secret_key"
    run_step "Generating TLS certificate" "generate_certificate"
    run_step "Generating SHA-256 certificate fingerprint" "generate_certificate_fingerprint"
    run_step "Writing config" "write_config"
    run_step "Pulling Shadowbox image" "pull_image"
    run_step "Starting Shadowbox" "start_shadowbox"
    readonly PUBLIC_API_URL="https://${PUBLIC_HOSTNAME}:${API_PORT}/${SB_API_PREFIX}"
    readonly LOCAL_API_URL="https://localhost:${API_PORT}/${SB_API_PREFIX}"
    run_step "Waiting for Outline server to be healthy" "wait_shadowbox"
    run_step "Creating first user" "create_first_user"
    run_step "Adding API URL to config" "add_api_url_to_config"
    run_step "Checking Access key port" "check_access_key_port"
    run_step "Creating systemd configuration file" "create_systemd_file"
    get_field_value() {
        grep "$1" "${ACCESS_CONFIG}" | sed "s/$1://"
    }

    cat <<END_OF_SERVER_OUTPUT

CONGRATULATIONS! Your Outline server is up and running.

To manage your Outline server, please copy the following line (including curly brackets) into Step 2 of the Outline Manager interface:

$(echo -e "${green}{\"apiUrl\":\"$(get_field_value apiUrl)\",\"certSha256\":\"$(get_field_value certSha256)\"}${normal}")

Make sure to open the following ports on your firewall, router or cloud provider:
- Management port ${API_PORT}, for TCP
- Access key port ${ACCESS_KEY_PORT}, for TCP and UDP"

END_OF_SERVER_OUTPUT
    exit 0
}

main "$@"
