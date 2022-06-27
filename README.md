This document explains how to setup a lab where to deploy OpenShift in a simulated disconnected environment.

## Setup the host

Create isolated network

~~~
virsh net-define libvirt/isolated.xml
~~~

Drop all packet going out of our isolated network
~~~
iptables -A FORWARD -s 192.168.100.0/24 -j DROP
~~~

Remove default libvirt fowarding rule to avoid packet coming into our isolated network
~~~
iptables -D LIBVIRT_FWO -s 192.168.100.0/24 -i virbr100 -j ACCEPT
~~~

## Create the mirror registry VM

qemu-img create -f qcow2 -b /var/lib/libvirt/images/rhel-8.5-update-2-x86_64-kvm.qcow2 /var/lib/libvirt/images/registry.qcow2
qemu-img resize /var/lib/libvirt/images/registry.qcow2 +500G

virt-install --name=registry \
 --vcpus "sockets=1,cores=2,threads=1" --memory="8192" \
 --disk "size=500,path=/var/lib/libvirt/images/registry.qcow2,bus=virtio,cache=none,format=qcow2" \
 --network network=br-int,model=virtio,mac="52:54:00:6c:4c:01" \
 --network network=isolated,model=virtio,mac="52:54:00:6c:5c:10" \
 --console pty,target_type=serial \
 --os-type linux --os-variant=rhel8.5 \
 --controller type=scsi,model=virtio-scsi \
 --hvm --virt-type kvm --features kvm_hidden=on \
 --graphics vnc,listen=0.0.0.0,tlsport=,defaultMode='insecure' \
 --memballoon none --cpu host-passthrough --autostart --noautoconsole --events on_reboot=restart \
 --import

growpart /dev/vda 3
xfs_growfs /
subscription-manager register
dnf install -y podman wget jq

## Setup the mirror registry VM

### SSH configuration
The mirror registry will use a playbook to log into the host to perform the install

- Add private key and authorized_key
- Enable pub key auth

### Pull-secret
Add your pull secret in /opt/quay/pull-secret.json

## Deploy the mirror registry

~~~
wget https://developers.redhat.com/content-gateway/rest/mirror/pub/openshift-v4/clients/mirror-registry/latest/mirror-registry.tar.gz -O /opt/mirror-registry.tar.gz
wget https://mirror.openshift.com/pub/openshift-v4/clients/ocp/latest-4.10/openshift-client-linux.tar.gz -O /opt/openshift-client-linux.tar.gz
wget https://mirror.openshift.com/pub/openshift-v4/x86_64/clients/ocp/stable/oc-mirror.tar.gz -O /opt/oc-mirror.tar.gz
cd /opt ; tar zxvf mirror-registry.tar.gz; tar zxvf openshift-client-linux.tar.gz; tar zxvf oc-mirror.tar.gz; chmod u+x  oc-mirror; mv execution-environment.tar image-archive.tar oc oc-mirror mirror-registry kubectl  /usr/local/bin/

mkdir quay && cd quay
quayRoot='/opt/quay'
mirror-registry install \
  --initPassword password \
  --initUser admin \
  --quayHostname registry.isolated.local \
  --quayRoot $quayRoot
cp $quayRoot/quay-rootCA/rootCA.pem /etc/pki/ca-trust/source/anchors/
update-ca-trust extract

podman login --authfile privaterepo.json \
-u admin \
-p password \
registry.isolated.local:8443 \
--tls-verify=false 
jq -cM -s '{"auths": ( .[0].auths + .[1].auths ) }' privaterepo.json pull-secret.json > compiled-pull-secret.json

cp compiled-pull-secret.json ${XDG_RUNTIME_DIR}/containers/auth.json
~~~


## Setup variables
Define below the OpenShift release to use

~~~
LOCAL_SECRET_JSON='/opt/quay/compiled-pull-secret.json'
LOCAL_REGISTRY="registry.isolated.local:8443"
RELEASE_NAME="ocp-release"
ARCHITECTURE="x86_64"
OCP_RELEASE="4.10.14"
VERSION_SHORT="4.10"
LOCAL_REPOSITORY="ocp4/openshift4"
PRODUCT_REPO="openshift-release-dev"
~~~

## Mirror OpenShift Release

~~~
oc adm release mirror -a ${LOCAL_SECRET_JSON}  \
    --from=quay.io/${PRODUCT_REPO}/${RELEASE_NAME}:${OCP_RELEASE}-${ARCHITECTURE} \
    --to=${LOCAL_REGISTRY}/${LOCAL_REPOSITORY} \
    --to-release-image=${LOCAL_REGISTRY}/${LOCAL_REPOSITORY}:${OCP_RELEASE}-${ARCHITECTURE} --insecure=true

for IMAGE in assisted-installer-agent assisted-installer assisted-installer-controller assisted-service assisted-image-service assisted-installer-ui
do
  oc -a ${LOCAL_SECRET_JSON} image mirror quay.io/edge-infrastructure/$IMAGE:latest ${LOCAL_REGISTRY}/edge-infrastructure/$IMAGE:latest
done
oc -a ${LOCAL_SECRET_JSON} image mirror quay.io/centos7/postgresql-12-centos7:latest ${LOCAL_REGISTRY}/centos7/postgresql-12-centos7:latest
~~~

## Mirror operators to our registry

Login into the registries
~~~
podman login registry.isolated.local:8443
podman login registry.redhat.io
~~~

Mirror the selected operators
~~~
echo "apiVersion: mirror.openshift.io/v1alpha2
kind: ImageSetConfiguration
storageConfig:
  registry:
    imageURL: registry.isolated.local:8443/openshift
mirror:
  platform:
    channels:
      - name: stable-4.10
  operators:
    - catalog: registry.redhat.io/redhat/redhat-operator-index:v4.10
      packages:
        - name: local-storage-operator
    - catalog: registry.redhat.io/redhat/certified-operator-index:v4.10
      packages:
        - name: redhat-marketplace-operator
    - catalog: registry.redhat.io/redhat/community-operator-index:v4.10
      packages:
        - name: cert-manager" > /opt/quay/isc.yaml

oc-mirror--config=/opt/quay/isc.yaml docker://registry.isolated.local:8443
~~~

## Get RHCOS images and expose them with NGINX

~~~
mkdir -p /opt/downloads/rhcos/${VERSION_SHORT}
if [ ! -f /opt/downloads/rhcos/${OCP_RELEASE}/rhcos-live.x86_64.iso ]; then
  echo "  - Downloading RH CoreOS ISO..."
  curl -sSL https://mirror.openshift.com/pub/openshift-v4/dependencies/rhcos/${VERSION_SHORT}/latest/rhcos-live.x86_64.iso -o /opt/downloads/rhcos/${VERSION_SHORT}/rhcos-live.x86_64.iso
fi
if [ ! -f /opt/downloads/rhcos/${VERSION_SHORT}/rhcos-live-kernel-x86_64 ]; then
  echo "  - Downloading RH CoreOS Kernel..."
  curl -sSL https://mirror.openshift.com/pub/openshift-v4/dependencies/rhcos/${VERSION_SHORT}/latest/rhcos-live-kernel-x86_64 -o /opt/downloads/rhcos/${VERSION_SHORT}/rhcos-live-kernel-x86_64
fi
if [ ! -f /opt/downloads/rhcos/${VERSION_SHORT}/rhcos-live-initramfs.x86_64.img ]; then
  echo "  - Downloading RH CoreOS initramfs..."
  curl -sSL https://mirror.openshift.com/pub/openshift-v4/dependencies/rhcos/${VERSION_SHORT}/latest/rhcos-live-initramfs.x86_64.img -o /opt/downloads/rhcos/${VERSION_SHORT}/rhcos-live-initramfs.x86_64.img
fi
if [ ! -f /opt/downloads/rhcos/${VERSION_SHORT}/rhcos-live-rootfs.x86_64.img ]; then
  echo "  - Downloading RH CoreOS RootFS..."
  curl -sSL https://mirror.openshift.com/pub/openshift-v4/dependencies/rhcos/${VERSION_SHORT}/latest/rhcos-live-rootfs.x86_64.img -o /opt/downloads/rhcos/${VERSION_SHORT}/rhcos-live-rootfs.x86_64.img
fi
~~~

## Setup NGINX

~~~
oc -a ${LOCAL_SECRET_JSON} image mirror library/nginx:latest ${LOCAL_REGISTRY}/library/nginx:latest
cat > /opt/nginx/default.conf.template <<EOF
server {
   listen       8000;
   server_name  _;

   location / {
       root   /usr/share/nginx/html;
       index mirror-index.html;
       autoindex on;
       autoindex_format html;
       autoindex_exact_size off;
       autoindex_localtime on;
   }
}
EOF
~~~

## Setup Assisted Installer
~~~
mkdir /opt/assisted-service

cat > /opt/assisted-service/cm.yaml <<EOF
apiVersion: v1
kind: ConfigMap
metadata:
  name: config
data:
  ASSISTED_SERVICE_HOST: assisted-installer.isolated.local:8090
  ASSISTED_SERVICE_SCHEME: http
  AUTH_TYPE: none
  DB_HOST: 127.0.0.1
  DB_NAME: installer
  DB_PASS: admin
  DB_PORT: "5432"
  DB_USER: admin
  DEPLOY_TARGET: onprem
  DISK_ENCRYPTION_SUPPORT: "true"
  DUMMY_IGNITION: "false"
  ENABLE_SINGLE_NODE_DNSMASQ: "true"
  HW_VALIDATOR_REQUIREMENTS: '[{"version":"default","master":{"cpu_cores":4,"ram_mib":16384,"disk_size_gb":100,"installation_disk_speed_threshold_ms":10,"network_latency_threshold_ms":100,"packet_loss_percentage":0},"worker":{"cpu_cores":2,"ram_mib":8192,"disk_size_gb":100,"installation_disk_speed_threshold_ms":10,"network_latency_threshold_ms":1000,"packet_loss_percentage":10},"sno":{"cpu_cores":8,"ram_mib":16384,"disk_size_gb":100,"installation_disk_speed_threshold_ms":10}}]'
  IMAGE_SERVICE_BASE_URL: http://assisted-installer.isolated.local:8888
  IPV6_SUPPORT: "true"
  LISTEN_PORT: "8888"
  NTP_DEFAULT_SERVER: ""
  OS_IMAGES: '[{"openshift_version":"4.10","cpu_architecture":"x86_64","url":"http://registry.isolated.local:8000/pub/downloads/rhcos/4.10/rhcos-live.x86_64.iso","rootfs_url":"http://registry.isolated.local:8000/pub/downloads/rhcos/4.10/rhcos-live-rootfs.x86_64.img","version":"410.84.202201251210-0"}]'
  POSTGRESQL_DATABASE: installer
  POSTGRESQL_PASSWORD: admin
  POSTGRESQL_USER: admin
  PUBLIC_CONTAINER_REGISTRIES: 'registry.isolated.local:8443'
  RELEASE_IMAGES: '[{"openshift_version":"4.10","cpu_architecture":"x86_64","url":"registry.isolated.local:8443/ocp4/openshift4:4.10.14-x86_64","version":"4.10.14","default":true}]'
  SERVICE_BASE_URL: http://assisted-installer.isolated.local:8090
  STORAGE: filesystem
  INSTALLER_IMAGE: registry.isolated.local:8443/edge-infrastructure/assisted-installer:latest
  CONTROLLER_IMAGE: registry.isolated.local:8443/edge-infrastructure/assisted-installer-controller:latest
EOF

cat > /opt/assisted-service/pod.yaml <<EOF
apiVersion: v1
kind: Pod
metadata:
  labels:
    app: assisted-installer
  name: assisted-installer
spec:
  containers:
  - image: registry.isolated.local:8443/library/nginx:latest
    name: rhcos-repo
    ports:
    - hostPort: 8000
    env:
    - NGINX_PORT: 8000
    volumeMounts:
      - mountPath: /usr/share/nginx/html/pub/downloads
        name: rhcos-data
      - mountPath: /etc/nginx/templates
        name: nginx-config
  - args:
    - run-postgresql
    image: registry.isolated.local:8443/centos7/postgresql-12-centos7:latest
    name: db
    envFrom:
    - configMapRef:
        name: config
    volumeMounts:
      - mountPath: /var/lib/pgsql
        name: pg-data
  - image: registry.isolated.local:8443/edge-infrastructure/assisted-installer-ui:latest
    name: ui
    ports:
    - hostPort: 8080
    envFrom:
    - configMapRef:
        name: config
  - image: registry.isolated.local:8443/edge-infrastructure/assisted-image-service:latest
    name: image-service
    ports:
    - hostPort: 8888
    envFrom:
    - configMapRef:
        name: config
  - image: registry.isolated.local:8443/edge-infrastructure/assisted-service:latest
    name: service
    ports:
    - hostPort: 8090
    envFrom:
    - configMapRef:
        name: config
    volumeMounts:
      - mountPath: /data
        name: ai-data
      - mountPath: /etc/pki/ca-trust/extracted/pem
        name: registry-ca
  restartPolicy: Never
  volumes:
    - name: rhcos-data
      hostPath:
        path: /opt/downloads
        type: Directory
    - name: nginx-config
      hostPath:
        path: /opt/nginx
        type: Directory
    - name: ai-data
      persistentVolumeClaim:
        claimName: ai-service-data
    - name: pg-data
      persistentVolumeClaim:
        claimName: ai-db-data
    - name: registry-ca
      hostPath:
        path: /etc/pki/ca-trust/extracted/pem
        type: Directory
EOF

podman play kube --authfile ${LOCAL_SECRET_JSON} --configmap cm.yaml pod.yaml
~~~

## Create the cluster in Assisted Installer

Setup ssh socks port foward and set your browser proxy to use socks to the open port
~~~
ssh -D 1338 -q -C -N -f lab-s2
~~~

Navigate to assisted-installer.registry.local:8080

Create the cluster following the UI. Before generating the discovery ISO, perform the below steps.

### Create a registries.conf file
This file will contain all the mirrored registries required for Assisted Installer to perform the installation in a disconnected fashio.

~~~
cat << EOF > /opt/registries.conf
  unqualified-search-registries = ["registry.isolated.local:8443"]
  [[registry]]
     prefix = ""
     location = "quay.io/openshift"
     mirror-by-digest-only = false
     insecure = true
     [[registry.mirror]]
     location = "registry.isolated.local:8443/openshift4"
  [[registry]]
     prefix = ""
     location = "registry.redhat.io/openshift4"
     mirror-by-digest-only = false
     insecure = true
     [[registry.mirror]]
     location = "registry.isolated.local:8443/openshift4"
  [[registry]]
     prefix = ""
     location = "quay.io/edge-infrastructure"
     mirror-by-digest-only = false
     insecure = true
     [[registry.mirror]]
     location = "registry.isolated.local:8443/edge-infrastructure"
  [[registry]]
     prefix = ""
     location = "quay.io/openshift-release-dev/ocp-release"
     mirror-by-digest-only = false
     insecure = true
     [[registry.mirror]]
     location = "registry.isolated.local:8443/ocp4/openshift4"
  [[registry]]
     prefix = ""
     location = "quay.io/openshift-release-dev/ocp-v4.0-art-dev"
     mirror-by-digest-only = false
     insecure = true
     [[registry.mirror]]
     location = "registry.isolated.local:8443/ocp4/openshift4"
EOF
~~~

Find the `InfraEnv` ID using Assisted Installer API. The following command can be run either on the mirror VM providing the service, or externally if socks proxy is setup.

~~~
curl http://localhost:8090/api/assisted-install/v2/infra-envs
~~~

Send the request to add the registry certificate authority and the above configuration to the `InfraEnv`.

~~~
request_body=$(mktemp)
jq -n --arg OVERRIDE "{\"ignition\":{\"version\":\"3.1.0\"},\"storage\":{\"files\":[{\"path\":\"\/etc\/pki\/ca-trust\/source\/anchors\/extra_ca.pem\",\"mode\":420,\"overwrite\":true,\"user\":{\"name\":\"root\"},\"contents\":{\"source\":\"data:text\/plain;base64,$(cat /opt/quay/quay-rootCA/rootCA.pem | base64 -w 0)\"}},{\"path\":\"\/etc\/containers\/registries.conf\",\"mode\":420,\"overwrite\":true,\"user\":{\"name\":\"root\"},\"contents\":{\"source\":\"data:text\/plain;base64,$(cat /opt/registries.conf | base64 -w 0)\"}}]}}" \
'{
   "ignition_config_override": $OVERRIDE
}' > $request_body

curl \
    --header "Content-Type: application/json" \
    --request PATCH \
    --data  @$request_body \
"http://localhost:8090/api/assisted-install/v2/infra-envs/42b53b63-7998-424d-a167-2b8a0519ca23"
~~~

### Setup the image content sources
Similary to the configuration done with Assisted Installer in the previous step, we need to instruct OpenShift Installer to pull images from our mirror registry. As such, create the following file
~~~
echo "imageContentSources:
- mirrors:
  - registry.isolated.local:8443/ocp4/openshift4
  source: quay.io/openshift-release-dev/ocp-release
- mirrors:
  - registry.isolated.local:8443/ocp4/openshift4
  source: quay.io/openshift-release-dev/ocp-v4.0-art-dev
- mirrors:
  - registry.isolated.local:8443/openshift4
  source: registry.redhat.io/openshift4
- mirrors:
  - registry.isolated.local:8443/openshift-community-operators
  source: quay.io/openshift-community-operators
- mirrors:
  - registry.isolated.local:8443/jetstack
  source: quay.io/jetstack
- mirrors:
  - registry.isolated.local:8443/rh-marketplace
  source: quay.io/rh-marketplace
- mirrors:
  - registry.isolated.local:8443/redhat
  source: registry.redhat.io/redhat
- mirrors:
  - registry.isolated.local:8443/rh-marketplace
  source: registry.connect.redhat.com/rh-marketplace
- mirrors:
  - registry.isolated.local:8443/armada-master
  source: us.icr.io/armada-master" > /opt/quay/image-content-sources.yaml
~~~

### Configure the install-config

Get the list of clusters and find the ID of the one of interest
~~~
curl http://localhost:8090/api/assisted-install/v2/clusters
~~~

Patch the install-config by adding Quay CA and the imageContentSources. `yq -o=json /opt/quay/image-content-sources.yaml`

~~~
install_config_patch=$(mktemp)
jq -n --arg BUNDLE "$(cat /opt/quay/quay-rootCA/rootCA.pem)" \
'{
    "additionalTrustBundle": $BUNDLE,
    "imageContentSources": [
      {
        "mirrors": [
          "registry.isolated.local:8443/ocp4/openshift4"
        ],
        "source": "quay.io/openshift-release-dev/ocp-release"
      },
      {
        "mirrors": [
          "registry.isolated.local:8443/ocp4/openshift4"
        ],
        "source": "quay.io/openshift-release-dev/ocp-v4.0-art-dev"
      },
      {
        "mirrors": [
          "registry.isolated.local:8443/edge-infrastructure"
        ],
        "source": "quay.io/edge-infrastructure"
      },
      {
        "mirrors": [
          "registry.isolated.local:8443/openshift4"
        ],
        "source": "registry.redhat.io/openshift4"
      },
      {
        "mirrors": [
          "registry.isolated.local:8443/openshift-community-operators"
        ],
        "source": "quay.io/openshift-community-operators"
      },
      {
        "mirrors": [
          "registry.isolated.local:8443/jetstack"
        ],
        "source": "quay.io/jetstack"
      },
      {
        "mirrors": [
          "registry.isolated.local:8443/rh-marketplace"
        ],
        "source": "quay.io/rh-marketplace"
      },
      {
        "mirrors": [
          "registry.isolated.local:8443/redhat"
        ],
        "source": "registry.redhat.io/redhat"
      },
      {
        "mirrors": [
          "registry.isolated.local:8443/rh-marketplace"
        ],
        "source": "registry.connect.redhat.com/rh-marketplace"
      },
      {
        "mirrors": [
          "registry.isolated.local:8443/armada-master"
        ],
        "source": "us.icr.io/armada-master"
      }
    ]
  }| tojson' > $install_config_patch

curl \
    --header "Content-Type: application/json" \
    --header "Authorization: Bearer $TOKEN" \
    --request PATCH \
    --data  @$install_config_patch \
"http://localhost:8090/api/assisted-install/v2/clusters/657bf5d8-c34d-4838-9600-3ae75c9826c6/install-config"
~~~

Verify it has been properly patched
~~~
curl http://localhost:8090/api/assisted-install/v2/clusters/657bf5d8-c34d-4838-9600-3ae75c9826c6/install-config
~~~

### Generate and download the ISO

Download the ISO
~~~
wget -O discovery_image_sno.iso 'http://assisted-installer.isolated.local:8888/images/42b53b63-7998-424d-a167-2b8a0519ca23?arch=x86_64&type=full-iso&version=4.10'
~~~

Put the ISO at the right place
~~~
mv discovery_image_sno.iso /var/lib/libvirt/boot/discovery_image.iso
~~~

Create the VM (in case of the SNO)
~~~
virsh define libvirt/master.xml
~~~

Proceed with the rest of the installation through the UI.

## Credits

- https://kenmoini.com/post/2022/01/disconnected-openshift-assisted-installer-service
- https://github.com/latouchek/assisted-installer-disconnected
