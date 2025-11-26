#!/bin/sh
set -e

# Cria diretórios necessários do sshd
mkdir -p /var/run/sshd

# Define a senha do root (mude "root" se quiser outra)
echo 'root:root' | chpasswd

# Habilita login de root e autenticação por senha
sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config && \
sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
sed -i 's@session\s\+required\s\+pam_loginuid.so@session optional pam_loginuid.so@g' /etc/pam.d/sshd

# Gera chaves do host (simples e direto)
ssh-keygen -A
