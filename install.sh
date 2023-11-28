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

    local dependencies=("curl" "wget" "openssl" "socat" "coreutils" "jq" "lsof")

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
                fi
            else
                red "The IP resolved by the current domain name does not match the real IP used by the current VPS"
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
        vmessport=${vmessport:-443}
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

        read -p "Enter VMESS port [default: 443]: " vmessport
        vmessport=${vmessport:-443}
        while lsof -Pi :$vmessport -sTCP:LISTEN -t >/dev/null ; do
            echo -e "${red}Error: Port $vmessport is already in use.${rest}"
            read -p "Enter a different VMESS port: " vmessport
            vmessport=${vmessport:-443}
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
    config-sing-box
    sed -i '/sing-box/d' /etc/crontab >/dev/null 2>&1
    echo "0 1 * * * systemctl restart sing-box >/dev/null 2>&1" >> /etc/crontab
    if [[ $certInput == 2 ]]; then
        telegram_tls
        setup_service
        config_tls
      else
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
      "tag": "vless-sb",
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
                "server_name": "$domain",
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
"download_url":"https://github.com/Chocolate4U/Iran-sing-box-rules/releases/download/202311250159/geoip.db",
"download_detour":"direct"
},
"geosite":{
"download_url":"https://github.com/Chocolate4U/Iran-sing-box-rules/releases/download/202311250159/geosite.db",
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
    display_progress 12
    nohup /etc/s-box/cloudflared tunnel --url http://localhost:$(jq -r .inbounds[1].listen_port /etc/s-box/sb.json) --edge-ip-version auto --no-autoupdate --protocol http2 > /etc/s-box/argo.log 2>&1 &
    
    max_wait_seconds=15
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
    else
        link=$(grep -o 'https://.*trycloudflare.com' /etc/s-box/argo.log | sed 's/https:\/\///')
        echo ""
        echo -e "${purple}--------------------These are your configs.----------------------${rest}"
        echo ""
        tuic="tuic://$uuid:$uuid@$ip:$tuicport?congestion_control=bbr&udp_relay_mode=native&alpn=h3&sni=www.bing.com&allow_insecure=1#peyman-tuic5"
        echo "$tuic"
        echo "$tuic" > "/root/peyman/configs/tuic_config.txt"
        echo -e "${purple}----------------------------------------------------------------${rest}"
        
        hysteria2="hysteria2://$uuid@$ip:$hyport?insecure=1&mport=$hyport&sni=www.bing.com#peyman-hy2"
        echo "$hysteria2"
        echo "$hysteria2" > "/root/peyman/configs/hysteria2_config.txt"
        echo -e "${purple}----------------------------------------------------------------${rest}"

        vless="vless://$uuid@$ip:$vlessport?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.yahoo.com&fp=chrome&pbk=$public_key&sid=$short_id&type=tcp&headerType=none#peyman-vless-reality"
        echo "$vless"
        echo "$vless" > "/root/peyman/configs/vless_config.txt"
        echo -e "${purple}----------------------------------------------------------------${rest}"

        vmess="{\"add\":\"$ip\",\"aid\":\"0\",\"host\":\"www.bing.com\",\"id\":\"$uuid\",\"net\":\"ws\",\"path\":\"$uuid\",\"port\":\"$vmessport\",\"ps\":\"peyman-ws\",\"tls\":\"\",\"type\":\"none\",\"v\":\"2\"}"
        encoded_vmess=$(echo -n "$vmess" | base64 -w 0)
        echo "vmess://$encoded_vmess"
        echo "vmess://$encoded_vmess" > "/root/peyman/configs/vmess_config.txt"
        echo -e "${purple}----------------------------------------------------------------${rest}"

        vmess="{\"add\":\"www.wto.org\",\"aid\":\"0\",\"host\":\"$link\",\"id\":\"$uuid\",\"net\":\"ws\",\"path\":\"$uuid\",\"port\":\"443\",\"ps\":\"peyman-vmess-Argo\",\"tls\":\"tls\",\"sni\":\"$link\",\"type\":\"none\",\"v\":\"2\"}"
        encoded_vmess=$(echo -n "$vmess" | base64 -w 0)
        echo "vmess://$encoded_vmess"
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
    display_progress 2
    sleep 1
    echo ""
    echo -e "${purple}--------------------These are your configs.----------------------${rest}"
    echo ""
    tuic="tuic://$uuid:$uuid@$domain:$tuicport?congestion_control=bbr&udp_relay_mode=native&alpn=h3&sni=$domain&allow_insecure=0#peyman-tuic5"
    echo "$tuic"
    echo "$tuic" > "/root/peyman/configs/tuic_config.txt"
    echo -e "${purple}----------------------------------------------------------------${rest}"
    
    hysteria2="hysteria2://$uuid@$domain:$hyport?insecure=0&mport=$hyport&sni=$domain#peyman-hy2"
    echo "$hysteria2"
    echo "$hysteria2" > "/root/peyman/configs/hysteria2_config.txt"
    echo -e "${purple}----------------------------------------------------------------${rest}"
    
    vless="vless://$uuid@$domain:$vlessport?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.yahoo.com&fp=chrome&pbk=$public_key&sid=$short_id&type=tcp&headerType=none#peyman-vless-reality"
    echo "$vless"
    echo "$vless" > "/root/peyman/configs/vless_config.txt"
    echo -e "${purple}----------------------------------------------------------------${rest}"
    
    vmess='{"add":"'$domain'","aid":"0","host":"'$domain'","id":"'$uuid'","net":"ws","path":"'$uuid'","port":"'$vmessport'","ps":"peyman-ws-tls","tls":"tls","sni":"'$domain'","type":"none","v":"2"}'
    encoded_vmess=$(echo -n "$vmess" | base64 -w 0)
    echo "vmess://$encoded_vmess"
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
        display_progress 20
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
$(config_tls | grep -o 'vmess://.*')"
        
        response=$(curl -s "https://api.telegram.org/bot$token/sendMessage" \
            --data-urlencode "chat_id=$chat_id" \
            --data-urlencode "text=$message")

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
                "strategy": "ipv4_only",
                "detour": "select"
            },
            {
                "tag": "local",
                "address": "https://223.5.5.5/dns-query",
                "strategy": "ipv4_only",
                "detour": "direct"
            },
            {
                "address": "rcode://success",
                "tag": "block"
            },
            {
                "tag": "dns_fakeip",
                "strategy": "ipv4_only",
                "address": "fakeip"
            }
        ],
        "rules": [
            {
                "outbound": "any",
                "server": "local"
            },
            {
                "disable_cache": true,
                "geosite": "category-ads-all",
                "server": "block"
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
          "independent_cache": true
        },
      "inbounds": [
    {
      "type": "tun",
      "inet4_address": "172.19.0.1/30",
      "inet6_address": "fdfe:dcba:9876::1/126",
      "auto_route": true,
      "strict_route": true,
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
        "vless-sb",
        "vmess-sb",
        "hy2-sb",
        "tuic5-sb"
      ]
    },
    {
      "type": "vless",
      "tag": "vless-sb",
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
                "enabled": $tf,
                "server_name": "$domain",
                "insecure": $tf,
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
        "vless-sb",
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
      "download_url": "https://github.com/Chocolate4U/Iran-sing-box-rules/releases/download/202311250159/geoip.db",
      "download_detour": "select"
    },
    "geosite": {
      "download_url": "https://github.com/Chocolate4U/Iran-sing-box-rules/releases/download/202311250159/geosite.db",
      "download_detour": "select"
    },
    "auto_detect_interface": true,
    "rules": [
      {
        "geosite": "category-ads-all",
        "outbound": "block"
      },
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

# Main menu
menu() {
    clear
    echo "-- VLESS --VMESS --TUIC-- HYSTERIA2-- ARGO--"
    echo "By --> Peyman * Github.com/Ptechgithub * "
    echo ""
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

options() {
    clear
    echo -e "${purple}1)${rest} Show Argo Host"
    echo -e "${purple}2)${rest} Change Vless SNI"
    echo -e "${red}0)${rest} Back to Menu"
    echo -e "${cyan}Enter your choice${rest} : \c"
    read choice
    
    case $choice in
        1)
            argo_host
            ;;
        2)
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
    read -p "Enter the new SNI (use: www --> www.yahoo.com): " new_sni

    sed -i "/\"type\": \"vless\"/,/\"type\":/s/\"server\": \".*\"/\"server\": \"$new_sni\"/" /etc/s-box/sb.json
    sed -i "/\"type\": \"vless\"/,/\"type\":/s/\"server_name\": \".*\"/\"server_name\": \"$new_sni\"/" /etc/s-box/sb.json
    sed -i "s/sni=[^\&]*/sni=$new_sni/" /root/peyman/configs/vless_config.txt
    systemctl stop s-box.service
    systemctl start s-box.service
    echo "SNI updated successfully! to $new_sni"
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