package centos

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"text/template"

	"github.com/Masterminds/semver"
	"k8s.io/apimachinery/pkg/runtime"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"

	"github.com/kubermatic/machine-controller/pkg/providerconfig"
	"github.com/kubermatic/machine-controller/pkg/userdata/cloud"
	userdatahelper "github.com/kubermatic/machine-controller/pkg/userdata/helper"

	clusterv1alpha1 "sigs.k8s.io/cluster-api/pkg/apis/cluster/v1alpha1"
)

func getConfig(r runtime.RawExtension) (*Config, error) {
	p := Config{}
	if len(r.Raw) == 0 {
		return &p, nil
	}
	if err := json.Unmarshal(r.Raw, &p); err != nil {
		return nil, err
	}
	return &p, nil
}

// Config TODO
type Config struct {
	DistUpgradeOnBoot bool `json:"distUpgradeOnBoot"`
}

// Provider is a pkg/userdata.Provider implementation
type Provider struct{}

// UserData renders user-data template
func (p Provider) UserData(
	spec clusterv1alpha1.MachineSpec,
	kubeconfig *clientcmdapi.Config,
	ccProvider cloud.ConfigProvider,
	clusterDNSIPs []net.IP,
) (string, error) {

	tmpl, err := template.New("user-data").Funcs(userdatahelper.TxtFuncMap()).Parse(ctTemplate)
	if err != nil {
		return "", fmt.Errorf("failed to parse user-data template: %v", err)
	}

	kubeletVersion, err := semver.NewVersion(spec.Versions.Kubelet)
	if err != nil {
		return "", fmt.Errorf("invalid kubelet version: '%v'", err)
	}

	cpConfig, cpName, err := ccProvider.GetCloudConfig(spec)
	if err != nil {
		return "", fmt.Errorf("failed to get cloud config: %v", err)
	}

	pconfig, err := providerconfig.GetConfig(spec.ProviderConfig)
	if err != nil {
		return "", fmt.Errorf("failed to get provider config: %v", err)
	}

	if pconfig.OverwriteCloudConfig != nil {
		cpConfig = *pconfig.OverwriteCloudConfig
	}

	if pconfig.Network != nil {
		return "", errors.New("static IP config is not supported with CentOS")
	}

	osConfig, err := getConfig(pconfig.OperatingSystemSpec)
	if err != nil {
		return "", fmt.Errorf("failed to parse OperatingSystemSpec: '%v'", err)
	}

	serverAddr, err := userdatahelper.GetServerAddressFromKubeconfig(kubeconfig)
	if err != nil {
		return "", fmt.Errorf("error extracting server address from kubeconfig: %v", err)
	}

	kubeconfigString, err := userdatahelper.StringifyKubeconfig(kubeconfig)
	if err != nil {
		return "", err
	}

	kubernetesCACert, err := userdatahelper.GetCACert(kubeconfig)
	if err != nil {
		return "", fmt.Errorf("error extracting cacert: %v", err)
	}

	data := struct {
		MachineSpec      clusterv1alpha1.MachineSpec
		ProviderConfig   *providerconfig.Config
		OSConfig         *Config
		CloudProvider    string
		CloudConfig      string
		KubeletVersion   string
		ClusterDNSIPs    []net.IP
		ServerAddr       string
		JournaldMaxSize  string
		Kubeconfig       string
		KubernetesCACert string
	}{
		MachineSpec:      spec,
		ProviderConfig:   pconfig,
		OSConfig:         osConfig,
		CloudProvider:    cpName,
		CloudConfig:      cpConfig,
		KubeletVersion:   kubeletVersion.String(),
		ClusterDNSIPs:    clusterDNSIPs,
		ServerAddr:       serverAddr,
		JournaldMaxSize:  userdatahelper.JournaldMaxUse,
		Kubeconfig:       kubeconfigString,
		KubernetesCACert: kubernetesCACert,
	}
	b := &bytes.Buffer{}
	err = tmpl.Execute(b, data)
	if err != nil {
		return "", fmt.Errorf("failed to execute user-data template: %v", err)
	}
	return b.String(), nil
}

const ctTemplate = `#cloud-config
hostname: {{ .MachineSpec.Name }}

{{- if .OSConfig.DistUpgradeOnBoot }}
package_upgrade: true
package_reboot_if_required: true
{{- end }}

ssh_pwauth: no

{{- if ne (len .ProviderConfig.SSHPublicKeys) 0 }}
ssh_authorized_keys:
{{- range .ProviderConfig.SSHPublicKeys }}
  - "{{ . }}"
{{- end }}
{{- end }}

write_files:
- path: "/etc/systemd/journald.conf.d/max_disk_use.conf"
  content: |
    [Journal]
    SystemMaxUse={{ .JournaldMaxSize }}

- path: "/etc/sysctl.d/k8s.conf"
  content: |
    net.bridge.bridge-nf-call-ip6tables = 1
    net.bridge.bridge-nf-call-iptables = 1
    kernel.panic_on_oops = 1
    kernel.panic = 10
    vm.overcommit_memory = 1
    net.ipv4.ip_forward = 1

- path: /etc/sysconfig/selinux
  content: |
    # This file controls the state of SELinux on the system.
    # SELINUX= can take one of these three values:
    #     enforcing - SELinux security policy is enforced.
    #     permissive - SELinux prints warnings instead of enforcing.
    #     disabled - No SELinux policy is loaded.
    SELINUX=permissive
    # SELINUXTYPE= can take one of three two values:
    #     targeted - Targeted processes are protected,
    #     minimum - Modification of targeted policy. Only selected processes are protected.
    #     mls - Multi Level Security protection.
    SELINUXTYPE=targeted

- path: "/opt/bin/setup"
  permissions: "0777"
  content: |
    #!/bin/bash
    set -xeuo pipefail

    setenforce 0 || true
    sysctl --system

    yum install -y ebtables \
      ethtool \
      nfs-utils \
      bash-completion \
      sudo \
      wget

    # Download all required binaries
    /opt/bin/download_binaries

    systemctl enable --now containerd
    systemctl enable --now kubelet

- path: "/opt/bin/supervise.sh"
  permissions: "0755"
  content: |
    #!/bin/bash
    set -xeuo pipefail
    while ! "$@"; do
      sleep 1
    done

- path: "/opt/bin/download_binaries"
  permissions: "0755"
  content: |
{{ downloadBinariesScript .KubeletVersion | indent 4 }}

- path: "/etc/systemd/system/kubelet.service"
  content: |
{{ kubeletSystemdUnit .KubeletVersion .CloudProvider .MachineSpec.Name | indent 4 }}

{{ if ne .CloudConfig "" }}
- path: "/etc/kubernetes/cloud-config"
  content: |
{{ .CloudConfig | indent 4 }}
{{- end }}

- path: "/etc/kubernetes/bootstrap.kubeconfig"
  content: |
{{ .Kubeconfig | indent 4 }}

- path: "/etc/kubernetes/pki/ca.crt"
  content: |
{{ .KubernetesCACert | indent 4 }}

- path: "/etc/containerd/config.toml"
  permissions: "0644"
  content: |
{{ containerdConfig .KubeletVersion | indent 4 }}

- path: "/etc/systemd/system/containerd.service"
  permissions: "0644"
  content: |
{{ containerdSystemdUnit .KubeletVersion | indent 4 }}

- path: "/var/lib/kubelet/config.yaml"
  content: |
{{ kubeletConfig .ClusterDNSIPs "/etc/resolv.conf" | indent 4 }}

- path: "/etc/systemd/system/setup.service"
  permissions: "0644"
  content: |
    [Install]
    WantedBy=multi-user.target

    [Unit]
    Requires=network-online.target
    After=network-online.target

    [Service]
    Type=oneshot
    RemainAfterExit=true
    ExecStart=/opt/bin/supervise.sh /opt/bin/setup

- path: "/etc/crictl.yaml"
  permissions: "0644"
  content: |
    runtime-endpoint: unix:///run/containerd/containerd.sock

- path: "/etc/profile.d/opt-bin-path.sh"
  permissions: "0755"
  content: |
    export PATH="/opt/bin:$PATH"

runcmd:
- systemctl enable --now setup.service
`
