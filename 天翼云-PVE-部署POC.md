# Debian GNU/Linux 10

1、天翼云原生镜像只有debian 10，需要采用apt方式升级到11
2、天翼云伸缩VM不支持VT-x，所以机器分配出来的VM无法启用嵌套的虚拟化技术
3、网络方面采用NAT单网卡方式进行

### 把Debian 10 升级为 11统一修改apt：

cat /etc/issue
Debian GNU/Linux 10 \n \l

### 更改为163源
sed -i 's#http://deb.debian.org#https://mirrors.163.com#g' /etc/apt/sources.list
sed -i 's#http://mirrors.aliyun.com#https://mirrors.163.com#g' /etc/apt/sources.list
### 更新源：
apt update && apt full-upgrade
......
reboot

### 把Debian10 升级为11
sed -i 's#buster#bullseye#g' /etc/apt/sources.list

### 更新源：
apt update && apt full-upgrade
......
reboot

### 升级成功！！！
 cat /etc/issue
Debian GNU/Linux 11 \n \l


### 主机名：
hostname pve
echo pve > /etc/hostname

cp /etc/hosts /etc/hosts.bak

cat << EOF > /etc/hosts
192.168.1.169  pve

127.0.1.1 localhost.localdomain 
127.0.0.1 localhost
EOF


检查ip地址和主机名对应关系：
hostname --ip-address

### 部署PVE7.2
echo "deb https://mirrors.tuna.tsinghua.edu.cn/proxmox/debian bullseye pve-no-subscription" > /etc/apt/sources.list.d/pve-install-repo.list

# 添加仓库key
wget https://enterprise.proxmox.com/debian/proxmox-release-bullseye.gpg -O /etc/apt/trusted.gpg.d/proxmox-release-bullseye.gpg 

更新系统
apt remove -y exim*
apt update && apt full-upgrade

安装PVE
apt install proxmox-ve postfix open-iscsi -y

安装过程中需要配置postfix，选择no configuration

等待安装完成，访问 https://<公网ip>:8006, 使用linux账户登陆root/<password>

如果您不是安装的双系统，则可以删除os-prober软件包
apt remove os-prober

优化内核参数
如果是海外的独立服务器，建议开启BBR来优化TCP传输，开启方法如下：

#修改内核配置
cat >>/etc/sysctl.conf << EOF
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
net.ipv4.ip_forward=1
EOF

#使配置生效
sysctl -p

# 去掉订阅信息：
cp /usr/share/javascript/proxmox-widget-toolkit/proxmoxlib.js /usr/share/javascript/proxmox-widget-toolkit/proxmoxlib.js.bak
sed -i.bak "s/data.status !== 'Active'/false/g" /usr/share/javascript/proxmox-widget-toolkit/proxmoxlib.js && systemctl restart pveproxy.service

### 删除企业订阅源
rm -rf /etc/apt/sources.list.d/pve-enterprise.list


# 安装openvswitch & 安装必须的包
apt install -y openvswitch-switch openvswitch-common hdparm iperf git sysstat htop wget net-tools ethtool parted

使用命令lsmod |grep bbr进行验证，当看到tcp_bbr字样，说明BBR开启成功。
tcp_bbr                20480  3

Linux默认描述符为1024，为避免后期出现各种问题，建议修改ulimit描述符限制，修改方法如下：

echo 'fs.file-max = 65535' >> /etc/sysctl.conf
echo '* soft nofile 65535' >> /etc/security/limits.conf
echo '* hard nofile 65535' >> /etc/security/limits.conf
echo 'ulimit -SHn 65535' >> /etc/profile


### 配置一个空桥接vmbr1
先安装ifupdown2包
apt install ifupdown2

配置NAT网卡配置：
cp /etc/network/interfaces /etc/network/interfaces.bak

auto lo
iface lo inet loopback

auto ens3
iface ens3 inet dhcp


auto vmbr0
iface vmbr0 inet dhcp
        bridge-ports ens3
        bridge-stp off
        bridge-fd 0

auto vmbr1
iface vmbr1 inet static
        address 10.0.0.1/24
        gateway 1.2.3.254
        bridge-ports none
        bridge-stp off
        bridge-fd 0
        post-up echo 1 > /proc/sys/net/ipv4/ip_forward
        post-up iptables -t nat -A POSTROUTING -s '10.0.0.0/24' -o vmbr0 -j MASQUERADE
        post-down iptables -t nat -D POSTROUTING -s '10.0.0.0/24' -o vmbr0 -j MASQUERADE
        
        post-up iptables -t nat -A PREROUTING -i vmbr0 -p tcp --dport 2022 -j DNAT --to 10.0.0.102:22
        post-down iptables -t nat -D PREROUTING -i vmbr0 -p tcp --dport 2022 -j DNAT --to 10.0.0.102:22

iptables -t nat -A PREROUTING -i vmbr0 -p tcp --dport 2022 -j DNAT --to 10.0.0.102:22

### 下载pfsense-CE 2.6.0版本
https://sgpfiles.netgate.com/mirror/downloads/pfSense-CE-2.6.0-RELEASE-amd64.iso.gz?_gl=1*7byrzs*_ga*NjIzNzAwNjE1LjE2NjgwMDc5NDU.*_ga_TM99KBGXCB*MTY2ODAwNzk0NC4xLjAuMTY2ODAwNzk0NC4wLjAuMA..

### 上传至pve机器上面
wget -O pfSense-CE-2.6.0-RELEASE-amd64.iso.gz https://atxfiles.netgate.com/mirror/downloads/pfSense-CE-2.6.0-RELEASE-amd64.iso.gz?_gl=1*eh1571*_ga*NjIzNzAwNjE1LjE2NjgwMDc5NDU.*_ga_TM99KBGXCB*MTY2ODAwNzk0NC4xLjEuMTY2ODAwODEzMy4wLjAuMA..

scp pfSense-CE-2.6.0-RELEASE-amd64.iso.gz root@125.124.144.197:/var/lib/vz/images


PROXMOX 单网卡，pfsense NAT拓扑图如下：
                                    +-----------------------------------------+
                                    |                                         |
                                    |  +-----+  +-----+                       |
                                    |  | VM1 |  | VM2 |                       |
                       +-----+      |  +--+--+ ++-----+                       |
       +-------+       |     |      |     |    | 192.168.1.169/24             |
       |  PC1 |--------+ SWITCH     |  +--+----++   +-------+                 |
       +-------|       |     |   ens3  |        |   |       |                 |
       +-------|       |    1+---------+ Vmbr1  +---+LAN    |                 |
       |  PC2 |--------+     |      || +--------+   |       |                 |
       +-------+       |     |      || |            |       |                 |
                       |     |      || +--------+   |       |                 |
      +----------------+8    |      +--+        |   |       |                 |
Internet               |     |      |  | Vmbr0  +---+WAN    |                 |
                       +-----+      |  +--------+   +-------+                 |
                                    |               PFSENSE VM                |
                                    |                                         |
                                    +-----------------------------------------+


pfSense禁止防火墙，用以进入GUI：
8
禁止防火墙
pfctl -d


admin/pfsense
admin/drpc123@!

pfctl -F ALL
ipfw -f flush
kldunload pf
kldunload ipfw

PVE NAT网络设置：
cp /etc/network/interfaces /etc/network/interfaces.bak
nano /etc/network/interfaces

auto lo
iface lo inet loopback

iface enp0s25 inet manual

auto vmbr0.100
iface vmbr0.100 inet static
        address 172.16.1.1/24
        gateway 172.16.1.1
        
auto vmbr0
iface vmbr0 inet static
        address 192.168.1.169/24
        gateway 192.168.1.1
        bridge-ports ens3
        bridge-stp off
        bridge-fd 0
        bridge-vlan-aware yes
        bridge-vids 2-4092



PVE下面部署docker和novnc GUI调试容器


cat <<"EOF" | bash                              
sudo apt update && \
sudo apt install apt-transport-https ca-certificates curl gnupg-agent software-properties-common -y && \
sudo apt-get remove docker  docker.io containerd runc -y && \
curl -fsSL https://download.docker.com/linux/debian/gpg | sudo apt-key add - && \
sudo add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/debian $(lsb_release -cs) stable" && \
sudo apt update && \
sudo apt install docker-ce docker-ce-cli containerd.io -y
EOF

sudo apt update && sudo apt upgrade
sudo systemctl status docker

不适用sudo运行docker
sudo usermod -aG docker $USER
newgrp docker


github地址介绍：https://github.com/accetto/ubuntu-vnc-xfce-firefox

docker pull accetto/ubuntu-vnc-xfce-firefox-default

改变端口启动docker
docker run -d --shm-size=256m -p 25901:5901 -p 26901:6901 accetto/ubuntu-vnc-xfce-firefox-default
df -h /dev/shm

天翼云开通端口：
http://125.124.144.197:26901/vnc.html?password=headless

docker gui 部署中文
apt-get update && apt-get install language-pack-zh-hans


vi /etc/network/interfaces

post-up echo 1 > /proc/sys/net/ipv4/ip_forward
post-up iptables -t nat -A POSTROUTING -s '10.10.10.0/24' -o ens5 -j MASQUERADE
post-down iptables -t nat -D POSTROUTING -s '10.10.10.0/24' -o ens5 -j MASQUERADE


配置LXC容器：

默认CT Template下载速度很慢，这里选择清华镜像源

cp /usr/share/perl5/PVE/APLInfo.pm /usr/share/perl5/PVE/APLInfo.pm_back

sed -i 's|http://download.proxmox.com|https://mirrors.tuna.tsinghua.edu.cn/proxmox|g' /usr/share/perl5/PVE/APLInfo.pm

配置容器NAT访问：

# Usage: bash nat.sh $(lxc-ls)
 
# 小鸡的端口转发规则 ssh 22 http 80 10<N>00 : 10<N>99
# ID 对应 IP 101: 10122 10180 10100 : 10199
#-------------------------------------------------------------#
input_id()
{
id=101
echo -e "测试默认 ID: \033[41;37m ${id} \033[0m 可以修改设置其他 ID; "
read -p "请输入 NAT 小鸡的 ID 号(按回车不修改): " -t 30 new
if [[ ! -z "${new}" ]]; then
id="${new}"
fi
nat_port
iptables -t nat -nvL PREROUTING
echo -e ":: PVE NAT 批量端口转发设置脚本: \033[41;37m bash nat.sh $(lxc-ls) \033[0m \n 使用参考: https://262235.xyz/index.php/archives/714/"
}
# 以 id 为 ip 设置端口转发
nat_port()
{
iptables -t nat -I PREROUTING -p tcp -m tcp --dport ${id}22 -j DNAT --to-destination 10.10.10.${id}:22
# iptables -t nat -I PREROUTING -p tcp -m tcp --dport ${id}80 -j DNAT --to-destination 10.10.10.${id}:80
iptables -t nat -A PREROUTING -p tcp -m multiport --dport ${id}00:${id}99 -j DNAT --to-destination 10.10.10.${id}
}
 
# 手工输入 id，input_id 调用 nat 端口转发
if [ $# -eq 0 ];
then
input_id
exit
fi
 
# 遍历参数 批量设置 nat 端口转发
for arg in $*
do
id=$arg
nat_port
done
 
# 查看 nat PREROUTING 端口映射规则
iptables -t nat -nvL PREROUTING
 
# 清空 nat PREROUTING 端口映射规则
# iptables -t nat -F PREROUTING


## 制作cmb-test-img
PVE1

下载centos 7.8 cloudimages
cd /var/lib/vz/template/iso
axel -n 10 https://cloud.centos.org/centos/7/images/CentOS-7-x86_64-GenericCloud-2003.qcow2

## 扩容cloudimg 空间
``` bash
qemu-img info CentOS-7-x86_64-GenericCloud-2003.qcow2
file format: qcow2
virtual size: 8 GiB (8589934592 bytes)
disk size: 836 MiB
cluster_size: 65536
Format specific information:
    compat: 0.10
    refcount bits: 16

```

扩充容量
qemu-img resize CentOS-7-x86_64-GenericCloud-2003.qcow2 100G
Image resized.

查看容量是否已经resize
qemu-img info CentOS-7-x86_64-GenericCloud-2003.qcow2
file format: qcow2
virtual size: 500 GiB (536870912000 bytes)
disk size: 836 MiB
cluster_size: 65536
Format specific information:
    compat: 0.10
    refcount bits: 16

## Centos7.8 cloud img 模板创建方法
``` bash
qm create 9001 --name k8s-master-1 --memory 2048 --net0 virtio,bridge=vmbr1 --cores 2 --sockets 2 --cpu cputype=kvm64 --description "cloud-k8s-lab-img"
qm importdisk 9001 CentOS-7-x86_64-GenericCloud-2003.qcow2 POOL
qm set 9001 --scsihw virtio-scsi-pci --virtio0 POOL:vm-9001-disk-0
qm set 9001 --serial0 socket
qm set 9001 --boot c --bootdisk virtio0
qm set 9001 --agent 1
qm set 9001 --vcpus 2
qm set 9001 --vga qxl
qm set 9001 --name k8s-master-1

#Cloud INIT
qm set 9001 --ide2 POOL:cloudinit
qm set 9001 --sshkey ~/.ssh/id_rsa.pub
qm set 9001 --ipconfig0 ip=10.0.0.102/24,gw=10.0.0.1

启动9003 VM
qm start 9001

公网外部访问：
iptables -t nat -A PREROUTING -i vmbr0 -p tcp --dport 2022 -j DNAT --to 10.0.0.102:22

NodePort NAT 映射：
service/kubernetes-dashboard        NodePort    10.68.183.157   <none>        443:31799/TCP            2m25s

rocky9 pct
pct console 100
yum update -y && yum install -y wget openssh-server neofetch epel-release

iptables -t nat -A PREROUTING -i vmbr0 -p tcp --dport 31799 -j DNAT --to 10.0.0.102:31799
iptables -t nat -L

eyJhbGciOiJSUzI1NiIsImtpZCI6IkJLWmFueGY5a0RCMW1KclptYUNoX1pvZjRwUENJb2N5VEVWMzZ4UEIwVDQifQ.eyJpc3MiOiJrdWJlcm5ldGVzL3NlcnZpY2VhY2NvdW50Iiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9uYW1lc3BhY2UiOiJrdWJlLXN5c3RlbSIsImt1YmVybmV0ZXMuaW8vc2VydmljZWFjY291bnQvc2VjcmV0Lm5hbWUiOiJhZG1pbi11c2VyIiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9zZXJ2aWNlLWFjY291bnQubmFtZSI6ImFkbWluLXVzZXIiLCJrdWJlcm5ldGVzLmlvL3NlcnZpY2VhY2NvdW50L3NlcnZpY2UtYWNjb3VudC51aWQiOiI4NmM3ZGMxYS1iYTMyLTQ1MjktYjI0MS00NzVhNDU2ZmNiMzUiLCJzdWIiOiJzeXN0ZW06c2VydmljZWFjY291bnQ6a3ViZS1zeXN0ZW06YWRtaW4tdXNlciJ9.fsAJAxo0DSw0fxsXczkxjxB54eQ8VO_mk2tb0jQYmPXIMuZ8eG8z9-GxUpWaCkoTr2__am2j-IYko6Yyz0eUy97_uV5REaICzLsWNwyNl6Q8zNwnD0SYqvyJ4uWPxp1A31AVKr_Kqs5osFfkrlEIN5KyPj3bMVYlj6QriEocbAKeWIJb_vvRnz-HOAWbt54JIMuo-HmC4_IAKRTOI8JxIdeJnhbERUBvoREuYrL1mv0KA36UE0q8PrVTrURuIu9BPGf4XcneC21qVZSBzmbsKZuZUJ9Vnge6gOTkrwNppD2EGhvpxgQvREdlmWqy-Z75o3g7wCl2OwOnTom6FAKmAQ

ssh root@10.0.0.102
qm terminal 9002

制作templete
qm template 9002



```


## 分配centos，创建yum-server,IP为：10.1.1.111

for ID in 2 
do
VMID="20$ID"
qm clone 9002 $VMID --name cmb-oss-test-20$ID --target pve1
qm set $VMID --name cmb-oss-test-20$ID
qm set $VMID --net0 model=virtio,bridge=vmbr2,tag=10
qm set $VMID --ipconfig0 ip=10.1.1.12$ID/24,gw=10.1.1.254
qm set $VMID --searchdomain dxlab-local.com
qm set $VMID --nameserver 192.168.2.1
qm set $VMID --onboot 0
qm start $VMID
done

for ID in 3 4 5 
do
VMID="20$ID"
qm clone 9002 $VMID --name cmb-oss-client-20$ID --target pve1
qm set $VMID --name cmb-oss-client-20$ID
qm set $VMID --net0 model=virtio,bridge=vmbr2,tag=10
qm set $VMID --ipconfig0 ip=10.1.1.12$ID/24,gw=10.1.1.254
qm set $VMID --searchdomain dxlab-local.com
qm set $VMID --nameserver 192.168.2.1
qm set $VMID --onboot 0
qm start $VMID
done


创建Rocky Linux8 CT Running Docker

for ID in 1 2 3
do
VMID="20$ID"
pct create $VMID /var/lib/vz/template/cache/rockylinux-8-default_20210929_amd64.tar.xz \
    -arch amd64 \
    -ostype centos \
    -hostname kubeasz-poc-20$ID  \
    -cores 2 \
    -memory 4096 \
    -swap 1024 \
    -storage POOL \
    -password drpc123@! \
    -net0 name=eth0,bridge=vmbr1,firewall=1,gw=10.0.0.1,ip=10.0.0.20$ID/24,type=veth&& \
    pct start $VMID && \
    sleep 10 && \
    pct resize $VMID rootfs +80G &&\
    pct set $VMID -features nesting=1,fuse=1 &&\
    pct exec $VMID -- bash -c "yum update -y &&\
    yum install -y openssh-server &&\
    systemctl start sshd &&\
    useradd -mU ibmer &&\
    echo "password" | passwd --stdin ibmer"
done

# LXC RockyLinux Dockerzation

## 需要pct开启nesting和fuse功能
for ID in 1 2 3
do
VMID="20$ID"
pct set $VMID -features nesting=1,fuse=1
done

for ID in 1 2 3
do
VMID="20$ID"
pct stop $VMID
sleep 5
pct start $VMID
pct console $VMID
done

cp /etc/pve/nodes/pve/lxc/201.conf  /soft/201.conf.bak

for ID in 1 2 3
do
VMID="20$ID"
cat >> /etc/pve/nodes/pve/lxc/20$ID.conf << EOF
cp /etc/pve/nodes/pve/lxc/$VMID.conf  /soft/$VMID.conf.bak
lxc.cgroup2.devices.allow: c 226:0 rwm
lxc.cgroup2.devices.allow: c 226:128 rwm
lxc.cgroup2.devices.allow: c 29:0 rwm
lxc.cgroup2.devices.allow: c 189:* rwm
lxc.apparmor.profile: unconfined
lxc.cgroup2.devices.allow: a
lxc.cap.drop:
lxc.mount.entry: /dev/dri/ dev/dri/ none bind,optional,create=dir 0, 0
lxc.mount.auto: "proc:rw sys:rw cgroup:rw"
EOF
done


## Docker ENV Set
for ID in 1 2 3
do
VMID="20$ID"
pct exec $VMID -- bash -c "dnf install 'dnf-command(config-manager)' -y &&\
sudo dnf update -y &&\
sudo dnf config-manager --add-repo=https://download.docker.com/linux/centos/docker-ce.repo -y &&\
sudo dnf update -y &&\
sudo dnf install docker-ce docker-ce-cli containerd.io -y &&\
sudo systemctl enable docker &&\
sudo systemctl start docker &&\
sudo usermod -aG docker $USER"
done


## 安装Ansible必须包
for ID in 1 2 3
do
VMID="20$ID"
pct exec $VMID -- bash -c "dnf install -y epel-release &&\
dnf module -y install python38 &&\
pip3 install setuptools-rust wheel &&\
pip3 install --upgrade pip &&\
python -m pip install ansible==5.7.1 &&\
dnf install python2-pip -y &&\
dnf install python3-pip -y &&\
dnf install ansible -y &&\
pip3 install netaddr &&\
pip3 install -upgrade jinja2 &&\
pip3 install pbr &&\
pip3 install --upgrade jmespath &&\
pip3 install ruamel.yaml &&\
pip3 install hvac"
done

## 安装GCC开发包 & skopeo
for ID in 1 2 3
do
VMID="20$ID"
pct exec $VMID -- bash -c "sudo dnf update  -y &&\
sudo dnf -y groupinstall "Development Tools"""
done


for ID in 1 2 3
do
VMID="20$ID"
pct exec $VMID -- bash -c "sudo dnf update  -y &&\
sudo dnf -y install "skopeo" --allowerasing"""
done

## 创建pct的snapshot
for ID in 1 2 3
do
VMID="20$ID"
pct snapshot $VMID inception -description 'roadmap snapshot' &&\
pct listsnapshot $VMID
done

## 制作pct模板
pct template 



## Xfce-Gui Env Set
sudo dnf install epel-release -y
rpm -qi epel-release
sudo dnf --enablerepo=epel group
sudo dnf group list | grep -i xfce -y
sudo dnf groupinstall "Xfce" "base-x" -y

sudo echo "exec /usr/bin/xfce4-session" >>  ~/.xinitrc
sudo systemctl set-default graphical

sudo dnf install tigervnc-server tigervnc firefox -y

sudo adduser vncuser
sudo passwd vncuser
sudo su - vncuser
vncpasswd

sudo cp /lib/systemd/system/vncserver@.service /etc/systemd/system/vncserver@:1.service

sudo vi /etc/tigervnc/vncserver.users

systemctl daemon-reload 
systemctl start vncserver@:1.service
systemctl enable vncserver@:1.service
systemctl status vncserver@:1.service

## 制作pct模板
pct template <vmid>

## stop & destroy pct

for ID in 1 2 3
do
VMID="20$ID"
pct stop $VMID
pct destroy $VMID
done


mkdir /soft;cd /soft
git clone https://gitee.com/heshucai/ansible-fastdfs.git

配置hosts解析

cat <<EOF > /etc/hosts
127.0.0.1   localhost localhost.localdomain localhost4 localhost4.localdomain4
::1         localhost localhost.localdomain localhost6 localhost6.localdomain6
# --- BEGIN PVE ---
10.0.0.201    kubeasz-poc-201
10.0.0.202    kubeasz-poc-202
10.0.0.203    kubeasz-poc-203
EOF

Tracker生成ssh公钥
ssh-keygen -t rsa -b 4096 -f ~/.ssh/id_rsa
cat ~/.ssh/id_rsa.pub


第二种方式同步公钥(Tracker执行)
ssh-copy-id -i ~/.ssh/id_rsa.pub root@kubeasz-poc-201
ssh-copy-id -i ~/.ssh/id_rsa.pub root@kubeasz-poc-202
ssh-copy-id -i ~/.ssh/id_rsa.pub root@kubeasz-poc-203


离线镜像 Skopeo配置：
https://www.51cto.com/article/710492.html
https://blog.k8s.li/docker-in-pod.html


sudo dnf -y install skopeo
skopeo login cr.imroc.cc

# 使用 kubespray 搭建集群

mkdir /soft;cd /soft

# 下载 kubespray
$ git clone --depth=1 https://github.com/kubernetes-sigs/kubespray.git
$ cd kubespray

# 安装依赖，包括 ansible
$ pip3 install --trusted-host https://pypi.org/packages/source/a/ansible/ansible-5.7.1.tar.gz ansible -d /soft/--user 

dnf module -y install python38
sudo alternatives --config python

There are 5 programs which provide 'python'.

  Selection    Command
-----------------------------------------------
*+ 1           /usr/libexec/no-python
   2           /usr/bin/python2
   3           /usr/bin/python3
   4           /usr/bin/python3.9
   5           /usr/bin/python3.8

Enter to keep the current selection[+], or type selection number: 4


pip3 install setuptools-rust wheel
pip3 install --upgrade pip
python -m pip install ansible==5.7.1

ansible --version


$ sudo pip3 install -r requirements.txt

# 复制一份配置文件
cp -rfp inventory/sample inventory/mycluster

修改配置
需要修改的配置文件列表:

inventory/mycluster/group_vars/all/*.yml
inventory/mycluster/group_vars/k8s-cluster/*.yml

下面介绍一些需要重点关注的配置，根据自己需求进行修改。

集群网络
修改配置文件 inventory/mycluster/group_vars/k8s_cluster/k8s-cluster.yml:

# 选择网络插件，支持 cilium, calico, weave 和 flannel
kube_network_plugin: cilium

# 设置 Service 网段
kube_service_addresses: 10.233.0.0/18

# 设置 Pod 网段
kube_pods_subnet: 10.233.64.0/18

其它相关配置文件: inventory/mycluster/group_vars/k8s_cluster/k8s-net-*.yml。

运行时
修改配置文件 inventory/mycluster/group_vars/k8s_cluster/k8s-cluster.yml:

# 支持 docker, crio 和 containerd，推荐 containerd.
container_manager: containerd

# 是否开启 kata containers
kata_containers_enabled: false

其它相关配置文件:

inventory/mycluster/group_vars/all/containerd.yml
inventory/mycluster/group_vars/all/cri-o.yml
inventory/mycluster/group_vars/all/docker.yml

集群证书
修改配置文件 inventory/mycluster/group_vars/k8s_cluster/k8s-cluster.yml:

# 是否开启自动更新证书，推荐开启。
auto_renew_certificates: true



for ID in 1 2 3
do
VMID="20$ID"
pct exec $VMID -- bash -c "dnf install -y pip3 && pip3 install setuptools-rust wheel && dnf module -y install python38 &&\
sudo pip3 install --upgrade pip && python -m pip install ansible==5.7.1"""
done

pip3 install setuptools-rust wheel
pip3 install --upgrade pip
python -m pip install ansible==5.7.1

ansible --version

ansible-playbook -i /soft/kubespray/inventory/inventory.ini cluster.yml -b -v \
  --private-key=~/.ssh/private_key
  
ansible -i /soft/kubespray/inventory/inventory.ini all -m ping



ansible-playbook -i /etc/kubeasz/clusters/default/hosts 02.etcd.yml 
