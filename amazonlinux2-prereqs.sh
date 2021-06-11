#!/bin/bash

# Script to install prerequistes on Amazon Linux 2

yum update -y
yum upgrade -y

# Install latest stable kubectl as per https://kubernetes.io/docs/tasks/tools/install-kubectl-linux/
cat <<EOF > /etc/yum.repos.d/kubernetes.repo
[kubernetes]
name=Kubernetes
baseurl=https://packages.cloud.google.com/yum/repos/kubernetes-el7-x86_64
enabled=1
gpgcheck=1
repo_gpgcheck=1
gpgkey=https://packages.cloud.google.com/yum/doc/yum-key.gpg https://packages.cloud.google.com/yum/doc/rpm-package-key.gpg
EOF
yum install -y kubectl

# Uninstall / Reinstall the CDK
npm uninstall -g aws-cdk
npm install -g aws-cdk --force

# Install the fluxctl
cd /tmp
wget -O fluxctl https://github.com/fluxcd/flux/releases/download/1.22.2/fluxctl_linux_amd64
chmod +x fluxctl
mv fluxctl /usr/local/bin

# Install Helm
curl https://raw.githubusercontent.com/helm/helm/master/scripts/get-helm-3 | bash
