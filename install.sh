#!/bin/bash
echo -e "\033[1;36mMilitary Crypto Tool Installer\033[0m"

check_go() {
    if ! command -v go &> /dev/null; then
        echo -e "\033[1;31mخطا: Go نصب نیست!\033[0m"
        echo -e "نصب Go برای:"
        echo -e "ترموکس: \033[1;33mpkg install golang\033[0m"
        echo -e "دبیان: \033[1;33msudo apt install golang\033[0m"
        echo -e "آرچ: \033[1;33msudo pacman -S go\033[0m"
        exit 1
    fi
}

install() {
    echo -e "\033[1;32mدر حال نصب...\033[0m"
    go mod init military-crypto
    go mod tidy
    go build -o military-crypto
    chmod +x military-crypto
    mv military-crypto /usr/local/bin/ 2>/dev/null || sudo mv military-crypto /usr/local/bin/
}

check_go
install
echo -e "\n\033[1;32mنصب کامل شد!\033[0m"
echo "اجرا با دستور: military-crypto"