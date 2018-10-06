package helper

import (
	"bytes"
	"fmt"
	"text/template"

	"github.com/Masterminds/sprig"
)

const (
	downloadBinariesTpl = `#!/bin/bash
set -xeuo pipefail

mkdir -p /opt/bin/

# crictl
if [ ! -f /opt/bin/crictl ]; then
    {{- if semverCompare ">=1.10.0-0, < 1.11.0-0" .KubeletVersion }}
    wget -O /opt/crictl.tar.gz https://github.com/kubernetes-sigs/cri-tools/releases/download/v1.0.0-beta.1/crictl-v1.0.0-beta.1-linux-amd64.tar.gz
    {{- else if semverCompare ">=1.11.0-0, < 1.12.0-0" .KubeletVersion }}
    wget -O /opt/crictl.tar.gz https://github.com/kubernetes-sigs/cri-tools/releases/download/v1.11.1/crictl-v1.11.1-linux-amd64.tar.gz
    {{- else }}
    wget -O /opt/crictl.tar.gz https://github.com/kubernetes-sigs/cri-tools/releases/download/v1.12.0/crictl-v1.12.0-linux-amd64.tar.gz
    {{- end }}
    tar -xvf /opt/crictl.tar.gz -C /opt/bin/
fi

# cni
if [ ! -f /opt/cni/bin/loopback ]; then
    wget -O /opt/cni-plugins.tar.gz https://github.com/containernetworking/plugins/releases/download/v0.6.0/cni-plugins-amd64-v0.6.0.tgz
    mkdir -p /opt/cni/bin /etc/cni/net.d
    tar -xvf /opt/cni-plugins.tar.gz -C /opt/cni/bin/
fi

# runc
if [ ! -f /opt/bin/runc ]; then
    wget -O /opt/bin/runc https://github.com/opencontainers/runc/releases/download/v1.0.0-rc5/runc.amd64        
    chmod +x /opt/bin/runc
fi

# containerd
if [ ! -f /opt/bin/containerd ]; then
    wget -O /opt/containerd.tar.gz https://github.com/containerd/containerd/releases/download/v1.2.0-rc.1/containerd-1.2.0-rc.1.linux-amd64.tar.gz
    sudo tar -xvf /opt/containerd.tar.gz -C /opt/
fi

# kubelet
if [ ! -f /opt/bin/kubelet ]; then
    wget -O /opt/bin/kubelet https://storage.googleapis.com/kubernetes-release/release/v{{ .KubeletVersion }}/bin/linux/amd64/kubelet
    chmod +x /opt/bin/kubelet
fi
`
)

// DownloadBinariesScript returns the script which is responsible to download all required binaries.
// Extracted into a dedicated function so we can use it to prepare custom images: TODO: Use it to prepare custom images...
func DownloadBinariesScript(kubeletVersion string) (string, error) {
	tmpl, err := template.New("download-binaries").Funcs(sprig.TxtFuncMap()).Parse(downloadBinariesTpl)
	if err != nil {
		return "", fmt.Errorf("failed to parse download-binaries template: %v", err)
	}

	data := struct {
		KubeletVersion string
	}{
		KubeletVersion: kubeletVersion,
	}
	b := &bytes.Buffer{}
	err = tmpl.Execute(b, data)
	if err != nil {
		return "", fmt.Errorf("failed to execute download-binaries template: %v", err)
	}

	return string(b.String()), nil
}
