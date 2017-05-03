#!/usr/bin/env bash
dir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

source "./helpers.bash"

set -e

logs_clear

echo "K8S flag is not set, ignoring test"
env

if [ -z $K8S ]; then
    exit 0
fi

if [[ "${IPV4}" -eq "1" ]]; then
    export 'IPV6_EXT'=0
    export 'K8S_CLUSTER_DNS_IP'=${K8S_CLUSTER_DNS_IP:-"172.20.0.10"}
else
    echo "This test is suppose to be run with IPv4 mode enabled, for example:"
    echo "IPV4=1 K8S=1 ./contrib/vagrant/start.sh"
    exit 0
fi

if [[ "$(hostname)" -ne "cilium-k8s-master" ]]; then
    echo "This test is suppose to be run on cilium-k8s-nodes where the guestbook"
    echo "pods are scheduled to be run (cilium-k8s-master). For example:"
    echo "IPV4=1 K8S=1 ./contrib/vagrant/start.sh"
    exit 1
fi

function cleanup {
    echo "Cleaning up"
    sleep 3s
    "${dir}/../examples/kubernetes/scripts/11-cleanup.sh"
    monitor_stop
}

trap cleanup EXIT

monitor_start

set -x

if [ ! "${dir}/../contrib/vagrant/cilium-k8s-install-2nd-part.sh" ]; then
    echo "File ${dir}/../contrib/vagrant/cilium-k8s-install-2nd-part.sh not found, falling back to default"
    . "${dir}/../examples/kubernetes/scripts/08-cilium.sh"
else
    # This way we configure kubectl with the same IPs set with start.sh
    . "${dir}/../contrib/vagrant/cilium-k8s-install-2nd-part.sh"
fi
"${dir}/../examples/kubernetes/scripts/09-dns-addon.sh"
"${dir}/../examples/kubernetes/scripts/10-1-smoke-test.sh"
"${dir}/wait-for-k8s-pod.bash" guestbook 100
"${dir}/wait-for-k8s-pod.bash" redis-slave 100
"${dir}/wait-for-k8s-pod.bash" redis-master 100

monitor_clear

echo "Testing connectivity between pods"

guestbook_pod=$(kubectl get pods | grep -Eo 'guestbook[^ ]+')
kubectl exec "${guestbook_pod}" -- sh -c 'sleep 60 && nc redis-master 6379 <<EOF
PING
EOF' || {
        abort "Unable to nc redis-master 6379"
    }

kubectl delete networkpolicies --all

until [ "$(cilium endpoint list | grep ready -c)" -eq "4" ]; do
    echo "Waiting for all endpoints to be ready"
    sleep 2s
done

kubectl exec "${guestbook_pod}" -- sh -c 'nc -w 5 redis-master 6379 <<EOF
PING
EOF' && {
     abort "Should have failed connecting to redis-master 6379"
}

echo "SUCCESS!"
