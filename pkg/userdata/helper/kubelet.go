package helper

import (
	"bytes"
	"fmt"
	"net"
	"text/template"

	"github.com/Masterminds/sprig"
)

const (
	kubeletSystemdUnitTpl = `[Unit]
After=containerd.service
Requires=containerd.service

[Install]
WantedBy=multi-user.target

[Service]
Restart=on-failure
RestartSec=5
Environment="PATH=/opt/bin:/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin/"
ExecStartPre=/sbin/modprobe br_netfilter
ExecStartPre=/bin/mkdir -p /etc/kubernetes/manifests
ExecStart=/opt/bin/kubelet \
    --config=/var/lib/kubelet/config.yaml \
    --container-runtime=remote \
    --container-runtime-endpoint=unix:///run/containerd/containerd.sock \
    --runtime-cgroups=/system.slice/containerd.service \
    --runtime-request-timeout=15m \
    --cadvisor-port=0 \
    --allow-privileged=true \
    --cni-bin-dir=/opt/cni/bin \
    --cni-conf-dir=/etc/cni/net.d \
    --hostname-override={{ .Hostname }} \
    --network-plugin=cni \
    {{- if .CloudProvider }}
    --cloud-provider={{ .CloudProvider }} \
    --cloud-config=/etc/kubernetes/cloud-config \
    {{- end }}
    --cert-dir=/etc/kubernetes/ \
    --pod-manifest-path=/etc/kubernetes/manifests \
    --kubeconfig=/etc/kubernetes/kubeconfig \
    --bootstrap-kubeconfig=/etc/kubernetes/bootstrap.kubeconfig
`
	kubeletConfigTpl = `address: 0.0.0.0
apiVersion: kubelet.config.k8s.io/v1beta1
authentication:
  anonymous:
    enabled: false
  webhook:
    cacheTTL: 2m0s
    enabled: true
  x509:
    clientCAFile: /etc/kubernetes/pki/ca.crt
authorization:
  mode: Webhook
  webhook:
    cacheAuthorizedTTL: 5m0s
    cacheUnauthorizedTTL: 30s
cgroupDriver: cgroupfs
cgroupsPerQOS: true
clusterDNS:
{{- range .ClusterDNSIPs }}
- {{ . }}
{{- end }}
clusterDomain: cluster.local
containerLogMaxFiles: 5
containerLogMaxSize: 10Mi
contentType: application/vnd.kubernetes.protobuf
cpuCFSQuota: true
cpuManagerPolicy: none
cpuManagerReconcilePeriod: 10s
enableControllerAttachDetach: true
enableDebuggingHandlers: true
enforceNodeAllocatable:
- pods
eventBurst: 10
eventRecordQPS: 5
evictionHard:
  imagefs.available: 15%
  memory.available: 100Mi
  nodefs.available: 10%
  nodefs.inodesFree: 5%
evictionPressureTransitionPeriod: 5m0s
failSwapOn: true
fileCheckFrequency: 20s
hairpinMode: promiscuous-bridge
healthzBindAddress: 127.0.0.1
healthzPort: 10248
httpCheckFrequency: 20s
imageGCHighThresholdPercent: 85
imageGCLowThresholdPercent: 80
imageMinimumGCAge: 2m0s
iptablesDropBit: 15
iptablesMasqueradeBit: 14
kind: KubeletConfiguration
kubeAPIBurst: 10
kubeAPIQPS: 5
makeIPTablesUtilChains: true
maxOpenFiles: 1000000
maxPods: 110
nodeStatusUpdateFrequency: 10s
oomScoreAdj: -999
podPidsLimit: -1
port: 10250
protectKernelDefaults: true
readOnlyPort: 0
registryBurst: 10
registryPullQPS: 5
resolvConf: {{ .ResolvConfPath }}
rotateCertificates: true
runtimeRequestTimeout: 15m
serializeImagePulls: true
staticPodPath: /etc/kubernetes/manifests
streamingConnectionIdleTimeout: 4h0m0s
syncFrequency: 1m0s
volumeStatsAggPeriod: 1m0s
`
)

// KubeletSystemdUnit returns the systemd unit for the kubelet
func KubeletSystemdUnit(kubeletVersion, cloudProvider, hostname string) (string, error) {
	tmpl, err := template.New("kubelet-systemd-unit").Funcs(sprig.TxtFuncMap()).Parse(kubeletSystemdUnitTpl)
	if err != nil {
		return "", fmt.Errorf("failed to parse kubelet-systemd-unit template: %v", err)
	}

	data := struct {
		KubeletVersion string
		CloudProvider  string
		Hostname       string
	}{
		KubeletVersion: kubeletVersion,
		CloudProvider:  cloudProvider,
		Hostname:       hostname,
	}
	b := &bytes.Buffer{}
	err = tmpl.Execute(b, data)
	if err != nil {
		return "", fmt.Errorf("failed to execute kubelet-systemd-unit template: %v", err)
	}

	return string(b.String()), nil
}

// KubeletConfig returns the config used by the kubelet
func KubeletConfig(dnsIPs []net.IP, resolvConfPath string) (string, error) {
	tmpl, err := template.New("kubelet-config").Funcs(sprig.TxtFuncMap()).Parse(kubeletConfigTpl)
	if err != nil {
		return "", fmt.Errorf("failed to parse kubelet-config template: %v", err)
	}

	data := struct {
		ClusterDNSIPs  []net.IP
		ResolvConfPath string
	}{
		ClusterDNSIPs:  dnsIPs,
		ResolvConfPath: resolvConfPath,
	}
	b := &bytes.Buffer{}
	err = tmpl.Execute(b, data)
	if err != nil {
		return "", fmt.Errorf("failed to execute kubelet-config template: %v", err)
	}

	return string(b.String()), nil
}
