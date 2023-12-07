#!/bin/bash

#colors
red='\033[0;31m'
green='\033[0;32m'
yellow='\033[0;33m'
blue='\033[0;34m'
purple='\033[0;35m'
cyan='\033[0;36m'
white='\033[0;37m'
rest='\033[0m'

#progress bar
display_progress() {
    local duration=$1
    local sleep_interval=0.1
    local progress=0
    local bar_length=40
    local colors=("[41m" "[42m" "[43m" "[44m" "[45m" "[46m" "[47m")

    while [ $progress -lt $duration ]; do
        echo -ne "\r${colors[$((progress % 7))]}"
        for ((i = 0; i < bar_length; i++)); do
            if [ $i -lt $((progress * bar_length / duration)) ]; then
                echo -ne "█"
            else
                echo -ne "░"
            fi
        done
        echo -ne "[0m ${progress}%"
        progress=$((progress + 1))
        sleep $sleep_interval
    done
    echo -ne "\r${colors[0]}"
    for ((i = 0; i < bar_length; i++)); do
        echo -ne " "
    done
    echo -ne "[0m 100%"
    echo
}

#detect_distribution
detect_distribution() {
    local supported_distributions=("ubuntu" "debian" "centos" "fedora")

    if [ -f /etc/os-release ]; then
        source /etc/os-release
        if [[ "${ID}" == "ubuntu" || "${ID}" == "debian" || "${ID}" == "centos" || "${ID}" == "fedora" ]]; then
            pm="apt"
            [ "${ID}" == "centos" ] && pm="yum"
            [ "${ID}" == "fedora" ] && pm="dnf"
            "$pm" update -y
        else
            echo "Unsupported distribution!"
            exit 1
        fi
    else
        echo "Unsupported distribution!"
        exit 1
    fi
}

#realip
realip(){
    ip=$(curl -s4m8 ip.sb -k) || ip=$(curl -s6m8 ip.sb -k)
}

#check_and_close_port
check_and_close_port() {
    local port=80
    
    if lsof -Pi :$port -sTCP:LISTEN -t >/dev/null ; then
        echo "Port $port is in use. Closing the port..."
        fuser -k $port/tcp
    fi
}

ip=$(hostname -I | awk '{print $1}')

#check_dependencies
check_dependencies() {
    detect_distribution

    local dependencies=("curl" "wget" "openssl" "socat" "coreutils" "jq" "lsof" "qrencode")

    for dep in "${dependencies[@]}"; do
        if ! command -v "${dep}" &> /dev/null; then
            echo "${dep} is not installed. Installing..."
            sudo "${pm}" install "${dep}" -y
        fi
    done
}

download_cf() {
    # Check if the file already exists
    if [ -x /etc/s-box/cloudflared ]; then
        echo "cf is already installed."
        return 0
    fi
     [ ! -d "/etc/s-box" ] && mkdir /etc/s-box
    [ ! -d "/root/peyman/configs" ] && mkdir -p /root/peyman/configs
    # Check the operating system type
    if [[ "$(uname -m)" == "x86_64" ]]; then
        download_url="https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64"
    elif [[ "$(uname -m)" == "aarch64" ]]; then
        download_url="https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-arm64"
    elif [[ "$(uname -m)" == "armv7l" ]]; then
        download_url="https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-arm"
    elif [[ "$(uname -m)" == "i686" ]]; then
        download_url="https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-386"
    else
        echo "Unsupported operating system."
        return 1
    fi
    
    # Download and install if the file doesn't exist
    sudo wget -O /etc/s-box/cloudflared $download_url >/dev/null 2>&1
    sudo chmod +x /etc/s-box/cloudflared
}

#install certificates
install_certs(){
    echo ""
    echo -e "${cyan}Methods of applying certificate :${rest}"
    echo -e "${green}1.${rest}Bing self-signed certificate ${yellow} (default) ${rest}"
    echo -e "${green}2.${rest}Acme (Domain Required)${rest}"
    echo ""
    read -rp "Please enter options [1-2]: " certInput
    if [[ $certInput == 2 ]]; then
        cert_path="/root/peyman/cert.crt"
        key_path="/root/peyman/private.key"
        tf="true"

        if [[ -f /root/peyman/cert.crt && -f /root/peyman/private.key ]] && [[ -s /root/peyman/cert.crt && -s /root/peyman/private.key ]] && [[ -f /root/peyman/ca.log ]]; then
            domain=$(cat /root/peyman/ca.log)
            echo -e "${green}The certificate of the original domain name: $domain was detected and is being applied${rest}"
            hy_domain=$domain
        else
            WARPv4Status=$(curl -s4m8 https://www.cloudflare.com/cdn-cgi/trace -k | grep warp | cut -d= -f2)
            WARPv6Status=$(curl -s6m8 https://www.cloudflare.com/cdn-cgi/trace -k | grep warp | cut -d= -f2)
            if [[ $WARPv4Status =~ on|plus ]] || [[ $WARPv6Status =~ on|plus ]]; then
                wg-quick down wgcf >/dev/null 2>&1
                systemctl stop warp-go >/dev/null 2>&1
                realip
                wg-quick up wgcf >/dev/null 2>&1
                systemctl start warp-go >/dev/null 2>&1
            else
                realip
            fi
            
            read -p "Please enter the domain name：" domain
            [[ -z $domain ]] && red "No domain name entered, unable to perform operation！" && exit 1
            echo -e "${green}Domain name entered: $domain${rest}" && sleep 1
            check_and_close_port
            domainIP=$(curl -sm8 ipget.net/?ip="${domain}")
            if [[ $domainIP == $ip ]]; then
                if [[ $ID == "CentOS" ]]; then
                    $pm install cronie -y
                    systemctl start crond
                    systemctl enable crond
                else
                    $pm install cron -y
                    systemctl start cron
                    systemctl enable cron
                fi
                curl https://get.acme.sh | sh -s email=$(date +%s%N | md5sum | cut -c 1-16)@gmail.com
                source ~/.bashrc
                bash ~/.acme.sh/acme.sh --upgrade --auto-upgrade
                bash ~/.acme.sh/acme.sh --set-default-ca --server letsencrypt
                if [[ -n $(echo $ip | grep ":") ]]; then
                    bash ~/.acme.sh/acme.sh --issue -d ${domain} --standalone -k ec-256 --listen-v6 --insecure
                else
                    bash ~/.acme.sh/acme.sh --issue -d ${domain} --standalone -k ec-256 --insecure
                fi
                bash ~/.acme.sh/acme.sh --install-cert -d ${domain} --key-file /root/peyman/private.key --fullchain-file /root/peyman/cert.crt --ecc
                if [[ -f /root/peyman/cert.crt && -f /root/peyman/private.key ]] && [[ -s /root/peyman/cert.crt && -s /root/peyman/private.key ]]; then
                    echo $domain > /root/peyman/ca.log
                    sed -i '/--cron/d' /etc/crontab >/dev/null 2>&1
                    echo "0 0 * * * root bash /root/.acme.sh/acme.sh --cron -f >/dev/null 2>&1" >> /etc/crontab
                    echo -e "${green}Successful! The certificate (cer.crt) and private key (private.key) saved in /root${rest}"
                    echo -e "${green}The certificate crt file path: /root/peyman/cert.crt${rest}"
                    echo -e "${green}The private key file path: /root/peyman/private.key${rest}"
                    chmod 777 /root/peyman/cert.crt
                    chmod 777 /root/peyman/private.key
                    chmod 777 /root/peyman/ca.log
                    hy_domain=$domain
                    read -rp "Do you want to use a subdomain with CDN [ON] for configs with TLS? Enter a subdomain or Press Enter to skip :" subdomain
                    if [[ -n $subdomain ]]; then
                      domain_cdn=$subdomain
                     echo -e "${green}Sub domain name entered: $domain_cdn${rest}" && sleep 1
                   else
                       domain_cdn=$domain
                    fi
                fi
            else
                echo -e "${red}The IP resolved by the current domain name does not match the real IP used by the current VPS${rest}"
                echo -e "${green}uggestions below :${rest}"
                echo -e "${yellow}1. Please make sure that CloudFlare is turned off (DNS only). The same applies to other domain name resolution or CDN website settings.${rest}"
                echo -e "${yellow}2. Please check whether the IP set by DNS resolution is the real IP of the VPS${rest}"
                exit 1
            fi
        fi
    else
        echo -e "${green}You selected Bing self-signed certificate.${rest}"
        cert_path="/root/peyman/cert.crt"
        key_path="/root/peyman/private.key"
        [ ! -d "/root/peyman/configs" ] && mkdir -p /root/peyman/configs
        openssl ecparam -genkey -name prime256v1 -out /root/peyman/private.key
        openssl req -new -x509 -days 36500 -key /root/peyman/private.key -out /root/peyman/cert.crt -subj "/CN=www.bing.com"
        chmod 777 /root/peyman/cert.crt
        chmod 777 /root/peyman/private.key
        hy_domain="www.bing.com"
        domain="$ip"
        tf="false"
    fi
}

#download sing-box
download-sb() {
    if [ "$ID" == "ubuntu" ]; then
        bash <(curl -fsSL https://sing-box.app/deb-install.sh)
    elif [ "$ID" == "debian" ]; then
        bash <(curl -fsSL https://sing-box.app/deb-install.sh)
    elif [ "$ID" == "centos" ] || [ "$ID" == "redhat" ]; then
        bash <(curl -fsSL https://sing-box.app/rpm-install.sh)
    elif [ "$ID" == "arch" ]; then
        bash <(curl -fsSL https://sing-box.app/arch-install.sh)
    else
        echo "Unsupported distribution!"
        exit 1
    fi
}

install() {
    if systemctl is-active --quiet s-box.service; then
        echo "sing-box is already installed."
        exit 1
    else
        echo "Installing..."
    fi
    
    check_dependencies
    download_cf
    download-sb
    install_certs
    uuid=$(sing-box generate uuid)
    keys=$(sing-box generate reality-keypair)
    private_key=$(echo $keys | awk -F " " '{print $2}')
    public_key=$(echo $keys | awk -F " " '{print $4}')
    short_id=$(openssl rand -hex 8)
    read -p "Do you want to use random Ports? [y/n]: " randomPort
    randomPort=${randomPort:-"y"}
    if [ "$randomPort" == "y" ]; then
        vlessport=$(shuf -i 2000-65535 -n 1)
        vlessgport=${vlessgport:-2083}
        vmessport=${vmessport:-2053}
        hyport=$(shuf -i 2000-65535 -n 1)
        tuicport=$(shuf -i 2000-65535 -n 1)
        
    else
        read -p "Enter VLESS port [default: 2087]: " vlessport
        vlessport=${vlessport:-2087}
        while lsof -Pi :$vlessport -sTCP:LISTEN -t >/dev/null ; do
            echo -e "${red}Error: Port $vlessport is already in use.${rest}"
            read -p "Enter a different VLESS port: " vlessport
            vlessport=${vlessport:-2087}
        done
        
        read -p "Enter VLESS_GRPC port [default: 2083]: " vlessgport
        vlessgport=${vlessgport:-2083}
        while lsof -Pi :$vlessgport -sTCP:LISTEN -t >/dev/null ; do
            echo -e "${red}Error: Port $vlessgport is already in use.${rest}"
            read -p "Enter a different VLESS port: " vlessgport
            vlessgport=${vlessgport:-2083}
        done

        read -p "Enter VMESS port [default: 2053]: " vmessport
        vmessport=${vmessport:-2053}
        while lsof -Pi :$vmessport -sTCP:LISTEN -t >/dev/null ; do
            echo -e "${red}Error: Port $vmessport is already in use.${rest}"
            read -p "Enter a different VMESS port: " vmessport
            vmessport=${vmessport:-2053}
        done

        read -p "Enter HYSTERIA port [default: 2096]: " hyport
        hyport=${hyport:-2096}
        while lsof -Pi :$hyport -sTCP:LISTEN -t >/dev/null ; do
            echo -e "${red}Error: Port $hyport is already in use.${rest}"
            read -p "Enter a different HYSTERIA port: " hyport
            hyport=${hyport:-2096}
        done

        read -p "Enter TUIC port [default: 8443]: " tuicport
        tuicport=${tuicport:-8443}
        while lsof -Pi :$tuicport -sTCP:LISTEN -t >/dev/null ; do
            echo -e "${red}Error: Port $tuicport is already in use.${rest}"
            read -p "Enter a different TUIC port: " tuicport
            tuicport=${tuicport:-8443}
        done
    fi
    server_config
    (crontab -l ; echo "0 1 * * * systemctl restart sing-box >/dev/null 2>&1") | sort - | uniq - | crontab -
    if [[ $certInput == 2 ]]; then
        config-sing-box
        config-nekobox
        telegram_tls
        setup_service
        config_tls
      else
        config-sing-boxx
        config-nekoboxx
        telegram_ip
        setup_service
        config_ip
    fi
}

server_config() {
    cat <<EOL > /etc/s-box/sb.json
{
"log": {
    "disabled": false,
    "level": "info",
    "timestamp": true
  },
  "inbounds": [
    {
      "type": "vless",
      "tag": "vless-tcp-reality",
      "sniff": true,
      "sniff_override_destination": true,      
      "listen": "::",
      "listen_port": $vlessport,
      "users": [
        {
          "uuid": "$uuid",
          "flow": "xtls-rprx-vision"
        }
      ],
      "tls": {
        "enabled": true,
        "server_name": "www.yahoo.com",
          "reality": {
          "enabled": true,
          "handshake": {
            "server": "www.yahoo.com",
            "server_port": 443
          },
          "private_key": "$private_key",
          "short_id": ["$short_id"]
        }
      }
    },
    {
        "type": "vmess",
        "tag": "vmess-sb",
        "sniff": true,
        "sniff_override_destination": true,
        "listen": "::",
        "listen_port": $vmessport,
        "users": [
            {
                "uuid": "$uuid",
                "alterId": 0
            }
        ],
        "transport": {
            "type": "ws",
            "path": "$uuid"
        },
        "tls":{
                "enabled": $tf,
                "server_name": "$domain_cdn",
                "min_version": "1.2",
                "max_version": "1.3",
                "certificate_path": "/root/peyman/cert.crt",
                "key_path": "/root/peyman/private.key"
            }
    },
{
            "type": "vless",
            "tag": "vless-grpc",
            "sniff": true,
            "sniff_override_destination": true,
            "listen": "::",
            "listen_port": $vlessgport,
            "users": [
                {
                    "uuid": "$uuid"
                }
            ],
            "transport": {
                "type": "grpc",
                "service_name": "$domain_cdn"
            },
            "tls":{
                "enabled": true,
                "server_name": "$domain_cdn",
                "min_version": "1.2",
                "max_version": "1.3",
                "certificate_path": "/root/peyman/cert.crt",
                "key_path": "/root/peyman/private.key"
            }
        },
    {
        "type": "hysteria2",
        "tag": "hy2-sb",
        "sniff": true,
        "sniff_override_destination": true,
        "listen": "::",
        "listen_port": $hyport,
        "users": [
            {
                "password": "$uuid"
            }
        ],
        "ignore_client_bandwidth":false,
        "tls": {
            "enabled": true,
            "alpn": [
                "h3"
            ],
            "min_version":"1.2",
            "max_version":"1.3",
            "certificate_path": "/root/peyman/cert.crt",
            "key_path": "/root/peyman/private.key"
        }
    },
        {
            "type":"tuic",
            "tag": "tuic5-sb",
            "sniff": true,
            "sniff_override_destination": true,
            "listen": "::",
            "listen_port": $tuicport,
            "users": [
                {
                    "uuid": "$uuid",
                    "password": "$uuid"
                }
            ],
            "congestion_control": "bbr",
            "tls":{
                "enabled": true,
                "alpn": [
                    "h3"
                ],
                "certificate_path": "/root/peyman/cert.crt",
                "key_path": "/root/peyman/private.key"
            }
        }
],
"outbounds": [
{
"type":"direct",
"tag":"direct",
"domain_strategy": "prefer_ipv4"
},
{
"type":"direct",
"tag": "vps-outbound-v4", 
"domain_strategy":"ipv4_only"
},
{
"type":"direct",
"tag": "vps-outbound-v6",
"domain_strategy":"ipv6_only"
},
{
"type": "socks",
"tag": "socks-out",
"server": "127.0.0.1",
"server_port": 40000,
"version": "5"
},
{
"type":"direct",
"tag":"socks-IPv4-out",
"detour":"socks-out",
"domain_strategy":"ipv4_only"
},
{
"type":"direct",
"tag":"socks-IPv6-out",
"detour":"socks-out",
"domain_strategy":"ipv6_only"
},
{
"type":"direct",
"tag":"warp-IPv4-out",
"detour":"wireguard-out",
"domain_strategy":"ipv4_only"
},
{
"type":"direct",
"tag":"warp-IPv6-out",
"detour":"wireguard-out",
"domain_strategy":"ipv6_only"
},
{
"type":"wireguard",
"tag":"wireguard-out",
"server":"162.159.193.10",
"server_port":1701,
"local_address":[
"172.16.0.2/32",
"2606:4700:110:891c:6ee2:7df4:5e99:b7cf/128"
],
"private_key":"aJkrp4MMgL/Oi2bO4Fww9J8aqAW1ojeOZ22RK0nXYWY=",
"peer_public_key":"bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=",
"reserved":[230,25,169]
},
{
"type": "block",
"tag": "block"
}
],
"route":{
"geoip":{
"download_url":"https://github.com/Ptechgithub/sing-box/blob/main/geo/geoip.db",
"download_detour":"direct"
},
"geosite":{
"download_url":"https://github.com/Ptechgithub/sing-box/blob/main/geo/geosite.db",
"download_detour":"direct"
},
"rules":[
{
"protocol": ["quic"],
"port": [ 443 ],
"outbound": "block"
},
{
"outbound": "direct",
"network": "udp,tcp"
}
]
}
}
EOL
}

setup_service() {
    cat <<EOL > "/etc/systemd/system/s-box.service"
[Unit]
After=network.target nss-lookup.target

[Service]
User=root
WorkingDirectory=/usr/bin
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
ExecStart=/usr/bin/sing-box run -c /etc/s-box/sb.json
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=10
LimitNOFILE=infinity

[Install]
WantedBy=multi-user.target
EOL

    sudo systemctl daemon-reload
    sudo systemctl start s-box.service
    sudo systemctl enable s-box.service
}

config_ip() {
    display_progress 10
    nohup /etc/s-box/cloudflared tunnel --url http://localhost:$(jq -r .inbounds[1].listen_port /etc/s-box/sb.json) --edge-ip-version auto --no-autoupdate --protocol http2 > /etc/s-box/argo.log 2>&1 &
    
    max_wait_seconds=10
    seconds_waited=0
    
    while [ $seconds_waited -lt $max_wait_seconds ]; do
        if [ -f /etc/s-box/argo.log ] && grep -q 'https://.*trycloudflare.com' /etc/s-box/argo.log; then
            break
        fi
        sleep 1
        ((seconds_waited++))
    done
    
    if [ $seconds_waited -ge $max_wait_seconds ]; then
        echo "Argo Can't run."
        echo ""
        echo -e "${purple}--------------------These are your configs.----------------------${rest}"
        echo ""
        tuic="tuic://$uuid:$uuid@$ip:$tuicport?congestion_control=bbr&udp_relay_mode=native&alpn=h3&sni=www.bing.com&allow_insecure=1#peyman-tuic5"
        echo "$tuic"
        echo ""
        echo -e "${purple}---------------------------------TUIC5-------------------------------${rest}"
        echo "$tuic" | qrencode -t ANSIUTF8
        echo "$tuic" > "/root/peyman/configs/tuic_config.txt"
        echo -e "${purple}----------------------------------------------------------------${rest}"
        
        hysteria2="hysteria2://$uuid@$ip:$hyport?insecure=1&mport=$hyport&sni=www.bing.com#peyman-hy2"
        echo "$hysteria2"
        echo ""
        echo -e "${purple}-------------------------------HYSTERIA2-----------------------------${rest}"
        echo "$hysteria2" | qrencode -t ANSIUTF8
        echo "$hysteria2" > "/root/peyman/configs/hysteria2_config.txt"
        echo -e "${purple}----------------------------------------------------------------${rest}"

        vless="vless://$uuid@$ip:$vlessport?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.yahoo.com&fp=chrome&pbk=$public_key&sid=$short_id&type=tcp&headerType=none#peyman-vless-reality"
        echo "$vless"
        echo ""
        echo -e "${purple}----------------------------VlESS-TCP-REALITY------------------------${rest}"
        echo "$vless" | qrencode -t ANSIUTF8
        echo "$vless" > "/root/peyman/configs/vless_config.txt"
        echo -e "${purple}----------------------------------------------------------------${rest}"

        vmess="{\"add\":\"$ip\",\"aid\":\"0\",\"host\":\"www.bing.com\",\"id\":\"$uuid\",\"net\":\"ws\",\"path\":\"$uuid\",\"port\":\"$vmessport\",\"ps\":\"peyman-ws\",\"tls\":\"\",\"type\":\"none\",\"v\":\"2\"}"
        encoded_vmess=$(echo -n "$vmess" | base64 -w 0)
        echo "vmess://$encoded_vmess"
        echo ""
        echo -e "${purple}--------------------------------VMESS-WS----------------------------${rest}"
        echo "$vmess://$encoded_vmess" | qrencode -t ANSIUTF8
        echo "vmess://$encoded_vmess" > "/root/peyman/configs/vmess_config.txt"
        echo -e "${purple}----------------------------------------------------------------${rest}"
    else
        link=$(grep -o 'https://.*trycloudflare.com' /etc/s-box/argo.log | sed 's/https:\/\///')
        echo ""
        echo -e "${purple}--------------------These are your configs.----------------------${rest}"
        echo ""
        tuic="tuic://$uuid:$uuid@$ip:$tuicport?congestion_control=bbr&udp_relay_mode=native&alpn=h3&sni=www.bing.com&allow_insecure=1#peyman-tuic5"
        echo "$tuic"
        echo ""
        echo -e "${purple}---------------------------------TUIC5-------------------------------${rest}"
        echo "$tuic" | qrencode -t ANSIUTF8
        echo "$tuic" > "/root/peyman/configs/tuic_config.txt"
        echo -e "${purple}----------------------------------------------------------------${rest}"
        
        hysteria2="hysteria2://$uuid@$ip:$hyport?insecure=1&mport=$hyport&sni=www.bing.com#peyman-hy2"
        echo "$hysteria2"
        echo ""
        echo -e "${purple}-------------------------------HYSTERIA2-----------------------------${rest}"
        echo "$hysteria2" | qrencode -t ANSIUTF8
        echo "$hysteria2" > "/root/peyman/configs/hysteria2_config.txt"
        echo -e "${purple}----------------------------------------------------------------${rest}"

        vless="vless://$uuid@$ip:$vlessport?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.yahoo.com&fp=chrome&pbk=$public_key&sid=$short_id&type=tcp&headerType=none#peyman-vless-reality"
        echo "$vless"
        echo ""
        echo -e "${purple}----------------------------VlESS-TCP-REALITY------------------------${rest}"
        echo "$vless" | qrencode -t ANSIUTF8
        echo "$vless" > "/root/peyman/configs/vless_config.txt"
        echo -e "${purple}----------------------------------------------------------------${rest}"

        vmess="{\"add\":\"$ip\",\"aid\":\"0\",\"host\":\"www.bing.com\",\"id\":\"$uuid\",\"net\":\"ws\",\"path\":\"$uuid\",\"port\":\"$vmessport\",\"ps\":\"peyman-ws\",\"tls\":\"\",\"type\":\"none\",\"v\":\"2\"}"
        encoded_vmess=$(echo -n "$vmess" | base64 -w 0)
        echo "vmess://$encoded_vmess"
        echo ""
        echo -e "${purple}----------------------------------VMESS-WS------------------------------${rest}"
        echo "$vmess://$encoded_vmess" | qrencode -t ANSIUTF8
        echo "vmess://$encoded_vmess" > "/root/peyman/configs/vmess_config.txt"
        echo -e "${purple}----------------------------------------------------------------${rest}"

        vmess="{\"add\":\"104.31.16.60\",\"aid\":\"0\",\"host\":\"$link\",\"id\":\"$uuid\",\"net\":\"ws\",\"path\":\"$uuid\",\"port\":\"443\",\"ps\":\"peyman-vmess-Argo\",\"tls\":\"tls\",\"sni\":\"$link\",\"type\":\"none\",\"v\":\"2\"}"
        encoded_vmess=$(echo -n "$vmess" | base64 -w 0)
        echo "vmess://$encoded_vmess"
        echo ""
        echo -e "${purple}-------------------------VMESS-WS-TLS+ARGO-TUNNEL------------------${rest}"
        echo "$vmess://$encoded_vmess" | qrencode -t ANSIUTF8
        echo "vmess://$encoded_vmess" > "/root/peyman/configs/vmess_Argo_config.txt"
        echo -e "${purple}----------------------------------------------------------------${rest}"
        
        (crontab -l 2>/dev/null | grep -q -F "@reboot /bin/bash -c \"/etc/s-box/cloudflared tunnel --url http://localhost:$(jq -r .inbounds[1].listen_port /etc/s-box/sb.json) --edge-ip-version auto --no-autoupdate --protocol http2 > /etc/s-box/argo.log 2>&1\"") || (crontab -l 2>/dev/null ; echo "@reboot /bin/bash -c \"/etc/s-box/cloudflared tunnel --url http://localhost:$(jq -r .inbounds[1].listen_port /etc/s-box/sb.json) --edge-ip-version auto --no-autoupdate --protocol http2 > /etc/s-box/argo.log 2>&1\"") | crontab - > /dev/null 2>&1
    fi
}

telegram_ip() {
    echo -e "${cyan}Do you want to receive the configs through Telegram bot? (y/n)${rest} \c"
    read configure_via_telegram

    if [[ "$configure_via_telegram" == "y" ]]; then
        echo -e "Enter your ${yellow}Telegram bot Token${rest} :\c"
        read token

        echo -e "Enter Your ${yellow}chat ID${rest}.${purple}(Get your Chat ID in: bot--> @userinfobot) ${rest}: \c"
        read chat_id
        display_progress 20
        echo "Please wait about 20s for connecting Argo tunnel..."
        

        message="🖐سلام، کانفیگ های شما با موفقیت ساخته شد.

1⃣
$(config_ip | grep -o 'tuic://.*#peyman-tuic5')

2⃣
$(config_ip | grep -o 'hysteria2://.*#peyman-hy2')

3⃣
$(config_ip | grep -o 'vless://.*#peyman-vless-reality')

4⃣
$(config_ip | grep -o 'vmess://.*' | head -n 1)

5️⃣
$(config_ip | grep -o 'vmess://.*' | tail -n 1)"
        
        response=$(curl -s "https://api.telegram.org/bot$token/sendMessage" \
            --data-urlencode "chat_id=$chat_id" \
            --data-urlencode "text=$message")
            
        json_file="/root/peyman/configs/config-nekobox.json"
        caption="📦 این فایل ترکیب کانفیگ با هم است. لطفا روی نرم افزار Nekobox اجرا شود."
        
        curl -s -X POST \
            https://api.telegram.org/bot$token/sendDocument \
            -F document=@$json_file \
            -F chat_id=$chat_id \
            -F caption="$caption" > /dev/null 
            
        json_files="/root/peyman/configs/config-sing-box.json"
        captions="📦 این فایل ترکیب کانفیگ با هم است. لطفا روی نرم افزار Sing-Box اجرا شود."
        
        curl -s -X POST \
            https://api.telegram.org/bot$token/sendDocument \
            -F document=@$json_files \
            -F chat_id=$chat_id \
            -F caption="$captions" > /dev/null 


        if [[ "$(echo "$response" | jq -r '.ok')" == "true" ]]; then
            echo -e "${green}Message sent to telegram successfully!${rest}"
        else
            echo -e "${red}Failed to send message. Check your bot token and chat ID.${rest}"
        fi
    else
        echo "Please Wait..."
        show_output=$(config_ip)
    fi
}

config_tls() {
    sleep 1
    echo ""
    echo -e "${purple}--------------------These are your configs.----------------------${rest}"
    echo ""
    echo -e "${purple}---------------------------------TUIC5-------------------------------${rest}"
    tuic="tuic://$uuid:$uuid@$domain:$tuicport?congestion_control=bbr&udp_relay_mode=native&alpn=h3&sni=$domain&allow_insecure=0#peyman-tuic5"
    echo "$tuic"
    echo ""
    echo "$tuic" | qrencode -t ANSIUTF8
    echo "$tuic" > "/root/peyman/configs/tuic_config.txt"
    echo -e "${purple}----------------------------------------------------------------${rest}"
    
    hysteria2="hysteria2://$uuid@$domain:$hyport?insecure=0&mport=$hyport&sni=$domain#peyman-hy2"
    echo "$hysteria2"
    echo ""
    echo -e "${purple}-------------------------------HYSTERIA2-----------------------------${rest}"
    echo "$hysteria2" | qrencode -t ANSIUTF8
    echo "$hysteria2" > "/root/peyman/configs/hysteria2_config.txt"
    echo -e "${purple}----------------------------------------------------------------${rest}"
    
    vless="vless://$uuid@$domain:$vlessport?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.yahoo.com&fp=chrome&pbk=$public_key&sid=$short_id&type=tcp&headerType=none#peyman-vless-reality"
    echo "$vless"
    echo ""
    echo -e "${purple}----------------------------VlESS-TCP-REALITY------------------------${rest}"
    echo "$vless" | qrencode -t ANSIUTF8
    echo "$vless" > "/root/peyman/configs/vless_config.txt"
    echo -e "${purple}----------------------------------------------------------------${rest}"

    vlessg="vless://$uuid@$domain_cdn:$vlessgport/?type=grpc&encryption=none&serviceName=$domain_cdn&security=tls&sni=$domain_cdn&alpn=h2&fp=chrome#peyman-Vless-GRPC-Tls"
    echo "$vlessg"
    echo ""
    echo -e "${purple}---------------------------------VLESS-GRPC-TLS-----------------------------${rest}"
    echo "$vlessg" | qrencode -t ANSIUTF8
    echo "$vlessg" > "/root/peyman/configs/vless_grpc_config.txt"
    echo -e "${purple}----------------------------------------------------------------${rest}"

    
    vmess='{"add":"'$domain_cdn'","aid":"0","host":"'$domain_cdn'","id":"'$uuid'","net":"ws","path":"'$uuid'","port":"'$vmessport'","ps":"peyman-ws-tls","tls":"tls","sni":"'$domain_cdn'","type":"none","v":"2"}'
    encoded_vmess=$(echo -n "$vmess" | base64 -w 0)
    echo "vmess://$encoded_vmess"
    echo ""
    echo -e "${purple}--------------------------------VMESS-WS-TLS----------------------------${rest}"
    echo "$vmess://$encoded_vmess" | qrencode -t ANSIUTF8
    echo "vmess://$encoded_vmess" > "/root/peyman/configs/vmess_config.txt"
    echo -e "${purple}----------------------------------------------------------------${rest}"
}

telegram_tls() {
    echo -e "${cyan}Do you want to receive the configs through Telegram bot? (y/n)${rest} \c"
    read configure_via_telegram

    if [[ "$configure_via_telegram" == "y" ]]; then
        echo -e "Enter your ${yellow}Telegram bot Token${rest} :\c"
        read token

        echo -e "Enter Your ${yellow}chat ID${rest}.${purple}(Get your Chat ID in: bot--> @userinfobot) ${rest}: \c"
        read chat_id
        display_progress 10
        sleep 1
        echo "Please Wait..."

        message="🖐سلام، کانفیگ های شما با موفقیت ساخته شد.
        
1⃣
$(config_tls | grep -o 'tuic://.*#peyman-tuic5')

2⃣
$(config_tls | grep -o 'hysteria2://.*#peyman-hy2')

3⃣
$(config_tls | grep -o 'vless://.*#peyman-vless-reality')

4⃣
$(config_tls | grep -o 'vmess://.*')

5️⃣
$(config_tls | grep -o 'vless://.*' | tail -n 1)"

        response=$(curl -s "https://api.telegram.org/bot$token/sendMessage" \
            --data-urlencode "chat_id=$chat_id" \
            --data-urlencode "text=$message")
            
        json_file="/root/peyman/configs/config-nekobox.json"
        caption="📦 این فایل ترکیب کانفیگ با هم است. لطفا روی نرم افزار Nekobox اجرا شود."
        
        curl -s -X POST \
            https://api.telegram.org/bot$token/sendDocument \
            -F document=@$json_file \
            -F chat_id=$chat_id \
            -F caption="$caption" > /dev/null 
            
        json_files="/root/peyman/configs/config-sing-box.json"
        captions="📦 این فایل ترکیب کانفیگ با هم است. لطفا روی نرم افزار Sing-Box اجرا شود."
        
        curl -s -X POST \
            https://api.telegram.org/bot$token/sendDocument \
            -F document=@$json_files \
            -F chat_id=$chat_id \
            -F caption="$captions" > /dev/null 


        if [[ "$(echo "$response" | jq -r '.ok')" == "true" ]]; then
            echo -e "${green}Message sent to telegram successfully!${rest}"
        else
            echo -e "${red}Failed to send message. Check your bot token and chat ID.${rest}"
        fi
    else
        show_output=$(config_tls)
    fi
}

uninstall() {
    # Check if the service is installed
    if [ ! -f "/etc/systemd/system/s-box.service" ]; then
        echo "The service is not installed."
        return
    fi

    # Stop and disable the service
    sudo systemctl stop s-box.service
    sudo systemctl disable s-box.service >/dev/null 2>&1

    # Remove service file
    sudo rm /etc/systemd/system/s-box.service >/dev/null 2>&1
    sudo rm -rf /etc/s-box
    sudo rm -rf /root/peyman
    sudo systemctl reset-failed
    echo "Uninstallation completed."
}

config-sing-box(){
    cat <<EOL> /root/peyman/configs/config-sing-box.json
{
  "log": {
    "disabled": false,
    "level": "info",
    "timestamp": true
  },
    "dns": {
        "servers": [
            {
                "tag": "remote",
                "address": "https://8.8.8.8/dns-query",             
                "detour": "select"
            },
            {
                "tag": "local",
                "address": "h3://223.5.5.5/dns-query",
                "detour": "direct"
            },
            {
                "address": "rcode://success",
                "tag": "block"
            },
            {
                "tag": "dns_fakeip",
                "address": "fakeip"
            }
        ],
        "rules": [
            {
                "outbound": "any",
                "server": "local",
                "disable_cache": true
            },
            {
                "clash_mode": "Global",
                "server": "remote"
            },
            {
                "clash_mode": "Direct",
                "server": "local"
            },
            {
                "geosite": "ir",
                "server": "local"
            },
            {
                "geosite": "geolocation-!ir",
                "server": "remote"
            },
             {
                "geosite": "geolocation-!ir",             
                "query_type": [
                    "A",
                    "AAAA"
                ],
                "server": "dns_fakeip"
            }
          ],
           "fakeip": {
           "enabled": true,
           "inet4_range": "198.18.0.0/15",
           "inet6_range": "fc00::/18"
         },
          "independent_cache": true,
          "final": "remote"
        },
      "inbounds": [
    {
      "type": "tun",
      "inet4_address": "172.19.0.1/30",
      //"inet6_address": "fdfe:dcba:9876::1/126",
      "auto_route": true,
      "strict_route": true,
      "stack": "mixed",
      "sniff": true
    }
  ],
  "experimental": {
    "clash_api": {
      "external_controller": "127.0.0.1:9090",
      "external_ui": "ui",
      "external_ui_download_url": "",
      "external_ui_download_detour": "",
      "secret": "",
      "default_mode": "Rule",
      "store_mode": true,
      "store_selected": true,
      "store_fakeip": true
    }
  },
  "outbounds": [
    {
      "tag": "select",
      "type": "selector",
      "default": "auto",
      "outbounds": [
        "auto",
        "vless-tcp-reality",
        "vless-grpc",
        "vmess-sb",
        "hy2-sb",
        "tuic5-sb"
      ]
    },
    {
      "type": "vless",
      "tag": "vless-tcp-reality",
      "server": "$domain",
      "server_port": $vlessport,
      "uuid": "$uuid",
      "flow": "xtls-rprx-vision",
      "tls": {
        "enabled": true,
        "server_name": "www.yahoo.com",
        "utls": {
          "enabled": true,
          "fingerprint": "chrome"
        },
      "reality": {
          "enabled": true,
          "public_key": "$public_key",
          "short_id": "$short_id"
        }
      }
    },
    {
    "type": "vless",
    "tag": "vless-grpc",
    "server": "$domain_cdn",
    "server_port": $vlessgport,
    "uuid": "$uuid",
    "tls": {
        "enabled": true,
        "server_name": "$domin_cdn",
        "utls": {
            "enabled": true,
            "fingerprint": "chrome"
        }
    },
    "packet_encoding": "xudp",
    "transport": {
        "type": "grpc",
        "service_name": "$domain_cdn"
    }
},
{
        "type": "vmess",
        "tag": "vmess-sb",
        "server": "$domain",
        "server_port": $vmessport,
        "tls": {
            "enabled": $tf,
            "server_name": "$domain_cdn",
            "insecure": $tf,
            "utls": {
                "enabled": true,
                "fingerprint": "chrome"
            }
        },
        "transport": {
            "headers": {
                "Host": [
                    "$domain_cdn"
                ]
            },
            "path": "$uuid",
            "type": "ws"
        },
        "security": "auto",
        "uuid": "$uuid"
    },
    {
        "type": "hysteria2",
        "tag": "hy2-sb",
        "server": "$domain",
        "server_port": $hyport,
        "password": "$uuid",
        "tls": {
            "enabled": true,
            "server_name": "www.bing.com",
            "insecure": true,
            "alpn": [
                "h3"
            ]
        }
    },
        {
            "type":"tuic",
            "tag": "tuic5-sb",
            "server": "$domain",
            "server_port": $tuicport,
            "uuid": "$uuid",
            "password": "$uuid",
            "congestion_control": "bbr",
            "udp_relay_mode": "native",
            "udp_over_stream": false,
            "zero_rtt_handshake": false,
            "heartbeat": "10s",
            "tls":{
                "enabled": true,
                "server_name": "www.bing.com",
                "insecure": true,
                "alpn": [
                    "h3"
                ]
            }
        },
    {
      "tag": "direct",
      "type": "direct"
    },
    {
      "tag": "block",
      "type": "block"
    },
    {
      "tag": "dns-out",
      "type": "dns"
    },
    {
      "tag": "auto",
      "type": "urltest",
      "outbounds": [
        "vless-tcp-reality",
        "vless-grpc",
        "vmess-sb",
        "hy2-sb",
        "tuic5-sb"
      ],
      "url": "https://cp.cloudflare.com/generate_204",
      "interval": "1m",
      "tolerance": 50,
      "interrupt_exist_connections": false
    }
  ],
  "route": {
      "geoip": {
      "download_url": "https://mirror.ghproxy.com/https://github.com/Ptechgithub/sing-box/blob/main/geo/geoip.db",
      "download_detour": "select"
    },
    "geosite": {
      "download_url": "https://mirror.ghproxy.com/https://github.com/Ptechgithub/sing-box/blob/main/geo/geosite.db",
      "download_detour": "select"
    },
    "auto_detect_interface": true,
    "final": "select",
    "rules": [
      {
        "outbound": "dns-out",
        "protocol": "dns"
      },
      {
        "clash_mode": "Direct",
        "outbound": "direct"
      },
      {
        "clash_mode": "Global",
        "outbound": "select"
      },
      {
        "geosite": "ir",
        "geoip": [
          "ir",
          "private"
        ],
        "outbound": "direct"
      },
      {
        "geosite": "geolocation-!ir",
        "outbound": "select"
      }
    ]
  },
    "ntp": {
    "enabled": true,
    "server": "time.apple.com",
    "server_port": 123,
    "interval": "30m",
    "detour": "direct"
  }
}
EOL
}

#config2
config-sing-boxx(){
    cat <<EOL> /root/peyman/configs/config-sing-box.json
{
  "log": {
    "disabled": false,
    "level": "info",
    "timestamp": true
  },
    "dns": {
        "servers": [
            {
                "tag": "remote",
                "address": "https://8.8.8.8/dns-query",             
                "detour": "select"
            },
            {
                "tag": "local",
                "address": "h3://223.5.5.5/dns-query",
                "detour": "direct"
            },
            {
                "address": "rcode://success",
                "tag": "block"
            },
            {
                "tag": "dns_fakeip",
                "address": "fakeip"
            }
        ],
        "rules": [
            {
                "outbound": "any",
                "server": "local",
                "disable_cache": true
            },
            {
                "clash_mode": "Global",
                "server": "remote"
            },
            {
                "clash_mode": "Direct",
                "server": "local"
            },
            {
                "geosite": "ir",
                "server": "local"
            },
            {
                "geosite": "geolocation-!ir",
                "server": "remote"
            },
             {
                "geosite": "geolocation-!ir",             
                "query_type": [
                    "A",
                    "AAAA"
                ],
                "server": "dns_fakeip"
            }
          ],
           "fakeip": {
           "enabled": true,
           "inet4_range": "198.18.0.0/15",
           "inet6_range": "fc00::/18"
         },
          "independent_cache": true,
          "final": "remote"
        },
      "inbounds": [
    {
      "type": "tun",
      "inet4_address": "172.19.0.1/30",
      //"inet6_address": "fdfe:dcba:9876::1/126",
      "auto_route": true,
      "strict_route": true,
      "stack": "mixed",
      "sniff": true
    }
  ],
  "experimental": {
    "clash_api": {
      "external_controller": "127.0.0.1:9090",
      "external_ui": "ui",
      "external_ui_download_url": "",
      "external_ui_download_detour": "",
      "secret": "",
      "default_mode": "Rule",
      "store_mode": true,
      "store_selected": true,
      "store_fakeip": true
    }
  },
  "outbounds": [
    {
      "tag": "select",
      "type": "selector",
      "default": "auto",
      "outbounds": [
        "auto",
        "vless-tcp-reality",
        "vmess-sb",
        "vmess-ws-+ARGO-Tunnel",
        "hy2-sb",
        "tuic5-sb"
      ]
    },
    {
      "type": "vless",
      "tag": "vless-tcp-reality",
      "server": "$domain",
      "server_port": $vlessport,
      "uuid": "$uuid",
      "flow": "xtls-rprx-vision",
      "tls": {
        "enabled": true,
        "server_name": "www.yahoo.com",
        "utls": {
          "enabled": true,
          "fingerprint": "chrome"
        },
      "reality": {
          "enabled": true,
          "public_key": "$public_key",
          "short_id": "$short_id"
        }
      }
    },
{
        "type": "vmess",
        "tag": "vmess-sb",
        "server": "$domain",
        "server_port": $vmessport,
        "tls": {
            "enabled": false,
            "server_name": "$domain",
            "insecure": true,
            "utls": {
                "enabled": true,
                "fingerprint": "chrome"
            }
        },
        "transport": {
            "headers": {
                "Host": [
                    "$domain"
                ]
            },
            "path": "$uuid",
            "type": "ws"
        },
        "security": "auto",
        "uuid": "$uuid"
    },
    {
        "type": "vmess",
        "tag": "vmess-ws-+ARGO-Tunnel",
        "server": "104.31.16.60",
        "server_port": 443,
        "tls": {
            "enabled": true,
            "server_name": "$link",
            "insecure": false,
            "utls": {
                "enabled": true,
                "fingerprint": "chrome"
            }
        },
        "transport": {
            "headers": {
                "Host": [
                    "$link"
                ]
            },
            "path": "$uuid",
            "type": "ws"
        },
        "security": "auto",
        "uuid": "$uuid"
    },
    {
        "type": "hysteria2",
        "tag": "hy2-sb",
        "server": "$domain",
        "server_port": $hyport,
        "password": "$uuid",
        "tls": {
            "enabled": true,
            "server_name": "www.bing.com",
            "insecure": true,
            "alpn": [
                "h3"
            ]
        }
    },
        {
            "type":"tuic",
            "tag": "tuic5-sb",
            "server": "$domain",
            "server_port": $tuicport,
            "uuid": "$uuid",
            "password": "$uuid",
            "congestion_control": "bbr",
            "udp_relay_mode": "native",
            "udp_over_stream": false,
            "zero_rtt_handshake": false,
            "heartbeat": "10s",
            "tls":{
                "enabled": true,
                "server_name": "www.bing.com",
                "insecure": true,
                "alpn": [
                    "h3"
                ]
            }
        },
    {
      "tag": "direct",
      "type": "direct"
    },
    {
      "tag": "block",
      "type": "block"
    },
    {
      "tag": "dns-out",
      "type": "dns"
    },
    {
      "tag": "auto",
      "type": "urltest",
      "outbounds": [
        "vless-tcp-reality",
        "vmess-sb",
        "vmess-ws-+ARGO-Tunnel",
        "hy2-sb",
        "tuic5-sb"
      ],
      "url": "https://cp.cloudflare.com/generate_204",
      "interval": "1m",
      "tolerance": 50,
      "interrupt_exist_connections": false
    }
  ],
  "route": {
      "geoip": {
      "download_url": "https://mirror.ghproxy.com/https://github.com/Ptechgithub/sing-box/blob/main/geo/geoip.db",
      "download_detour": "select"
    },
    "geosite": {
      "download_url": "https://mirror.ghproxy.com/https://github.com/Ptechgithub/sing-box/blob/main/geo/geosite.db",
      "download_detour": "select"
    },
    "auto_detect_interface": true,
    "final": "select",
    "rules": [
      {
        "outbound": "dns-out",
        "protocol": "dns"
      },
      {
        "clash_mode": "Direct",
        "outbound": "direct"
      },
      {
        "clash_mode": "Global",
        "outbound": "select"
      },
      {
        "geosite": "ir",
        "geoip": [
          "ir",
          "private"
        ],
        "outbound": "direct"
      },
      {
        "geosite": "geolocation-!ir",
        "outbound": "select"
      }
    ]
  },
    "ntp": {
    "enabled": true,
    "server": "time.apple.com",
    "server_port": 123,
    "interval": "30m",
    "detour": "direct"
  }
}
EOL
}

config-nekobox() {
    cat <<EOL> /root/peyman/configs/config-nekobox.json
{
  "dns": {
    "independent_cache": true,
    "rules": [
      {
        "domain": [
          "$domain"
        ],
        "server": "dns-direct"
      }
    ],
    "servers": [
      {
        "address": "https://1.1.1.1/dns-query",
        "address_resolver": "dns-direct",
        "strategy": "ipv4_only",
        "tag": "dns-remote"
      },
      {
        "address": "local",
        "address_resolver": "dns-local",
        "detour": "direct",
        "strategy": "ipv4_only",
        "tag": "dns-direct"
      },
      {
        "address": "local",
        "detour": "direct",
        "tag": "dns-local"
      },
      {
        "address": "rcode://success",
        "tag": "dns-block"
      }
    ]
  },
  "experimental": {
    "clash_api": {
      "cache_file": "../cache/clash.db",
      "external_controller": "127.0.0.1:9090",
      "external_ui": "../files/yacd"
    }
  },
  "inbounds": [
    {
      "listen": "127.0.0.1",
      "listen_port": 6450,
      "override_address": "8.8.8.8",
      "override_port": 53,
      "tag": "dns-in",
      "type": "direct"
    },
    {
      "domain_strategy": "",
      "endpoint_independent_nat": true,
      "inet4_address": [
        "172.19.0.1/28"
      ],
      "mtu": 9000,
      "sniff": true,
      "sniff_override_destination": false,
      "stack": "mixed",
      "tag": "tun-in",
      "type": "tun"
    },
    {
      "domain_strategy": "",
      "listen": "127.0.0.1",
      "listen_port": 2080,
      "sniff": true,
      "sniff_override_destination": false,
      "tag": "mixed-in",
      "type": "mixed"
    }
  ],
  "log": {
    "level": "panic"
  },
  "outbounds": [
    {
      "alter_id": 0,
      "packet_encoding": "",
      "security": "auto",
      "server": "$domain",
      "server_port": $vmessport,
      "tls": {
        "enabled": true,
        "insecure": false,
        "server_name": "$domain"
      },
      "transport": {
        "headers": {
          "Host": "$domain"
        },
        "path": "$uuid",
        "type": "ws"
      },
      "uuid": "$uuid",
      "type": "vmess",
      "domain_strategy": "",
      "tag": "vmess-ws-tls"
    },
    {
      "tag": "direct",
      "type": "direct"
    },
    {
      "flow": "xtls-rprx-vision",
      "packet_encoding": "",
      "server": "$domain",
      "server_port": $vlessport,
      "tls": {
        "enabled": true,
        "insecure": false,
        "reality": {
          "enabled": true,
          "public_key": "$public_key",
          "short_id": "$short_id"
        },
        "server_name": "www.yahoo.com",
        "utls": {
          "enabled": true,
          "fingerprint": "chrome"
        }
      },
      "uuid": "$uuid",
      "type": "vless",
      "domain_strategy": "",
      "tag": "Vless-reality"
    },
    {
      "packet_encoding": "",
      "server": "$domain_cdn",
      "server_port": $vlessgport,
      "tls": {
        "alpn": [
          "h2"
        ],
        "enabled": true,
        "insecure": false,
        "server_name": "$domain_cdn",
        "utls": {
          "enabled": true,
          "fingerprint": "chrome"
        }
      },
      "transport": {
        "service_name": "$domain_cdn",
        "type": "grpc"
      },
      "uuid": "$uuid",
      "type": "vless",
      "domain_strategy": "",
      "tag": "Vless-Grpc-tls"
    },
    {
      "congestion_control": "bbr",
      "password": "$uuid",
      "server": "$domain",
      "server_port": $tuicport,
      "tls": {
        "alpn": [
          "h3"
        ],
        "disable_sni": false,
        "enabled": true,
        "insecure": false,
        "server_name": "$domain"
      },
      "uuid": "$uuid",
      "zero_rtt_handshake": false,
      "type": "tuic",
      "domain_strategy": "",
      "tag": "TUIC5"
    },
    {
      "down_mbps": 0,
      "hop_interval": 10,
      "password": "$uuid",
      "server": "$domain",
      "server_port": $hyport,
      "tls": {
        "alpn": [
          "h3"
        ],
        "enabled": true,
        "insecure": false,
        "server_name": "$domain"
      },
      "up_mbps": 0,
      "type": "hysteria2",
      "domain_strategy": "",
      "tag": "HYSTERIA2"
    },
    {
      "tag": "💚Internet💚",
      "type": "selector",
      "outbounds":[
        "❤️Best Latency❤️",
        "Vless-reality",
        "TUIC5",
        "HYSTERIA2",
        "Vless-Grpc-tls",
        "vmess-ws-tls"
      ]
    },
    {
      "tag": "❤️Best Latency❤️",
      "type": "urltest",
      "outbounds":[
        "Vless-reality",
        "TUIC5",
        "HYSTERIA2",
        "Vless-Grpc-tls",
        "vmess-ws-tls"
      ],
      "url": "https://detectportal.firefox.com/success.txt",
      "interval": "60s",
      "tolerance": 0
    },
    {
      "tag": "bypass",
      "type": "direct"
    },
    {
      "tag": "block",
      "type": "block"
    },
    {
      "tag": "dns-out",
      "type": "dns"
    }
  ],
  "route": {
    "auto_detect_interface": true,
    "rules": [
      {
        "outbound": "dns-out",
        "port": [
          53
        ]
      },
      {
        "inbound": [
          "dns-in"
        ],
        "outbound": "dns-out"
      },
      {
        "ip_cidr": [
          "224.0.0.0/3",
          "ff00::/8"
        ],
        "outbound": "block",
        "source_ip_cidr": [
          "224.0.0.0/3",
          "ff00::/8"
        ]
      }
    ]
  }
}
EOL
}

config-nekoboxx() {
    cat <<EOL> /root/peyman/configs/config-nekobox.json
{
  "dns": {
    "independent_cache": true,
    "rules": [
      {
        "domain": [
          "dns.google"
        ],
        "server": "dns-direct"
      }
    ],
    "servers": [
      {
        "address": "https://dns.google/dns-query",
        "address_resolver": "dns-direct",
        "strategy": "ipv4_only",
        "tag": "dns-remote"
      },
      {
        "address": "local",
        "address_resolver": "dns-local",
        "detour": "direct",
        "strategy": "ipv4_only",
        "tag": "dns-direct"
      },
      {
        "address": "local",
        "detour": "direct",
        "tag": "dns-local"
      },
      {
        "address": "rcode://success",
        "tag": "dns-block"
      }
    ]
  },
  "experimental": {
    "clash_api": {
      "cache_file": "../cache/clash.db",
      "external_controller": "127.0.0.1:9090",
      "external_ui": "../files/yacd"
    }
  },
  "inbounds": [
    {
      "listen": "127.0.0.1",
      "listen_port": 6450,
      "override_address": "8.8.8.8",
      "override_port": 53,
      "tag": "dns-in",
      "type": "direct"
    },
    {
      "domain_strategy": "",
      "endpoint_independent_nat": true,
      "inet4_address": [
        "172.19.0.1/28"
      ],
      "mtu": 9000,
      "sniff": true,
      "sniff_override_destination": false,
      "stack": "mixed",
      "tag": "tun-in",
      "type": "tun"
    },
    {
      "domain_strategy": "",
      "listen": "127.0.0.1",
      "listen_port": 2080,
      "sniff": true,
      "sniff_override_destination": false,
      "tag": "mixed-in",
      "type": "mixed"
    }
  ],
  "log": {
    "level": "panic"
  },
  "outbounds": [
    {
      "flow": "xtls-rprx-vision",
      "packet_encoding": "",
      "server": "$domain",
      "server_port": $vlessport,
      "tls": {
        "enabled": true,
        "insecure": false,
        "reality": {
          "enabled": true,
          "public_key": "$public_key",
          "short_id": "$short_id"
        },
        "server_name": "www.yahoo.com",
        "utls": {
          "enabled": true,
          "fingerprint": "chrome"
        }
      },
      "uuid": "$uuid",
      "type": "vless",
      "domain_strategy": "",
      "tag": "Vless-reality"
    },
    {
      "congestion_control": "bbr",
      "password": "$uuid",
      "server": "$domain",
      "server_port": $tuicport,
      "tls": {
        "alpn": [
          "h3"
        ],
        "disable_sni": false,
        "enabled": true,
        "insecure": true,
        "server_name": "www.bing.com"
      },
      "uuid": "$uuid",
      "zero_rtt_handshake": false,
      "type": "tuic",
      "domain_strategy": "",
      "tag": "TUIC5"
    },
    {
      "down_mbps": 0,
      "hop_interval": 10,
      "password": "$uuid",
      "server": "$domain",
      "server_port": $hyport,
      "tls": {
        "alpn": [
          "h3"
        ],
        "enabled": true,
        "insecure": true,
        "server_name": "www.bing.com"
      },
      "up_mbps": 0,
      "type": "hysteria2",
      "domain_strategy": "",
      "tag": "HYSTERIA2"
    },
    {
      "alter_id": 0,
      "packet_encoding": "",
      "security": "auto",
      "server": "$domain",
      "server_port": $vmessport,
      "transport": {
        "headers": {
          "Host": "www.bing.com"
        },
        "path": "$uuid",
        "type": "ws"
      },
      "uuid": "$uuid",
      "type": "vmess",
      "domain_strategy": "",
      "tag": "vmess-ws"
    },
    {
      "alter_id": 0,
      "packet_encoding": "",
      "security": "auto",
      "server": "104.31.16.60",
      "server_port": 443,
      "tls": {
        "enabled": true,
        "insecure": false,
        "server_name": "$link"
      },
      "transport": {
        "headers": {
          "Host": "$link"
        },
        "path": "$uuid",
        "type": "ws"
      },
      "uuid": "$uuid",
      "type": "vmess",
      "domain_strategy": "",
      "tag": "vmess-ws-+ARGO-Tunnel"
    },
    {
      "tag": "💚Internet💚",
      "type": "selector",
      "outbounds":[
        "❤️Best Latency❤️",
        "Vless-reality",
        "TUIC5",
        "HYSTERIA2",
        "vmess-ws",
        "vmess-ws-+ARGO-Tunnel"
      ]
    },
    {
      "tag": "❤️Best Latency❤️",
      "type": "urltest",
      "outbounds":[
        "Vless-reality",
        "TUIC5",
        "HYSTERIA2",
        "vmess-ws",
        "vmess-ws-+ARGO-Tunnel"
      ],
      "url": "https://detectportal.firefox.com/success.txt",
      "interval": "60s",
      "tolerance": 0
    },
    {
      "tag": "direct",
      "type": "direct"
    },
    {
      "tag": "bypass",
      "type": "direct"
    },
    {
      "tag": "block",
      "type": "block"
    },
    {
      "tag": "dns-out",
      "type": "dns"
    }
  ],
  "route": {
    "auto_detect_interface": true,
    "rules": [
      {
        "outbound": "dns-out",
        "port": [
          53
        ]
      },
      {
        "inbound": [
          "dns-in"
        ],
        "outbound": "dns-out"
      },
      {
        "ip_cidr": [
          "224.0.0.0/3",
          "ff00::/8"
        ],
        "outbound": "block",
        "source_ip_cidr": [
          "224.0.0.0/3",
          "ff00::/8"
        ]
      }
    ]
  }
}
EOL
}

#check_status
check_status() {
    if sudo systemctl is-active --quiet s-box.service; then
        echo -e "${yellow}Sing-Box is:${green} [running ✔]${rest}"
    else
        echo -e "${yellow}Sing-Box is:${red} [Not running ✗ ]${rest}"
    fi
}

# Main menu
menu() {
    clear
    echo "-- VLESS --VMESS --TUIC-- HYSTERIA2-- ARGO--"
    echo "By --> Peyman * Github.com/Ptechgithub * "
    echo ""
    check_status
    echo -e "${green} --------${rest}#-${purple} Sing-Box ${rest}-#${green}--------${rest}"
    echo -e "${purple}1)${rest} Install"
    echo -e "${purple}2)${rest} Uninstall"
    echo -e "${purple}3)${rest} Options"
    echo -e "${red}0)${rest} Exit"
    echo -e "${cyan}Enter your choice${rest} : \c"
    read choice

    case $choice in
        1)
            install
            ;;
        2)
            uninstall
            ;;
        3)
            options
            ;;
        0)
            exit 0
            ;;
        *)
            echo "Invalid choice. Please select a valid option."
            ;;
    esac
}

show_files() {
  files=("/root/peyman/configs/vless_config.txt"
         "/root/peyman/configs/vmess_config.txt"
         "/root/peyman/configs/tuic_config.txt"
         "/root/peyman/configs/hysteria2_config.txt"
         "/root/peyman/configs/vmess_Argo_config.txt"
         "/root/peyman/configs/vless_grpc_config.txt")

  for file in "${files[@]}"; do
    if [ -e "$file" ]; then
      echo -e "${purple}~~~~~~~~~~~~~~~~~${rest}"
      cat "$file"
      echo -e "${purple}~~~~~~~~~~~~~~~~~${rest}"
    fi
  done
}

options() {
    clear
    
    echo""
    echo -e "${purple}1)${rest} Show Argo Host"
    echo -e "${purple}2)${rest} Show All Configs"
    echo -e "${purple}3)${rest} Change Vless SNI"
    echo -e "${red}0)${rest} Back to Menu"
    echo -e "${cyan}Enter your choice${rest} : \c"
    read choice
    
    case $choice in
        1)
            argo_host
            ;;
        2)
            show_files
            ;;
        3)
            update_vless_sni
            ;;
        0)
            menu
            ;;
        *)
            echo "Invalid choice. Returning to the menu."
            menu
            ;;
    esac
}

#change sni
update_vless_sni() {
    if [ -f "/etc/s-box/sb.json" ] && systemctl is-active --quiet s-box.service; then
        read -p "Enter the new SNI (use: www --> www.yahoo.com): " new_sni
        sed -i "/\"type\": \"vless\"/,/\"type\":/s/\"server\": \".*\"/\"server\": \"$new_sni\"/" /etc/s-box/sb.json
        sed -i "/\"type\": \"vless\"/,/\"type\":/s/\"server_name\": \".*\"/\"server_name\": \"$new_sni\"/" /etc/s-box/sb.json
        sed -i "s/sni=[^\&]*/sni=$new_sni/" /root/peyman/configs/vless_config.txt
        systemctl stop s-box.service
        systemctl start s-box.service
        echo "SNI updated successfully! to $new_sni"
    else
        echo -e "${red}Error:${rest}Service is not Installed"
    fi
}

#show new argo host after reboot server
argo_host() {
    if [ -f "/etc/s-box/argo.log" ] && systemctl is-active --quiet s-box.service; then
        echo -e "${purple}Change your Argo Host to below link: ${rest}"
        echo "---------------------------------------------"
        echo -e "${yellow}$(grep -o 'https://.*trycloudflare.com' /etc/s-box/argo.log | sed 's/https:\/\///')${rest}"
        echo "----------------------------------------------"
    else
        echo -e "${red}Error:${rest}The file '/etc/s-box/argo.log' doesn't exist or the service is not Installed"
    fi
}

menu