#!/usr/bin/env python3
"""
Usage: setup-cluster-images image-archive [num_nodes [targetdir]]
       image-archive - zip file as downloaded from raspberry-pi.org
       num_nodes     - number of nodes in the cluster [4]
       node_prefix   - prefix for the cluster nodes [gg]
       targetdir     - destination directory [current directory]
"""
import sys
from _sha256 import sha256
from contextlib import contextmanager
from logging import info, basicConfig, debug, DEBUG
from os import chdir, getcwd, makedirs, mkdir, geteuid, chmod, chown, stat, unlink, \
    listdir, rename
from shutil import rmtree, copy2
from subprocess import check_output, check_call
from tempfile import mkdtemp
from urllib import request
from zipfile import ZipFile

from os.path import join, abspath, isdir, dirname, isfile

# Number of raspberries in the cluster
BASE_IP = '192.168.8.2'
NODE_COUNT = 4
# prefix for the node names.
# nodes will be named <prefix>-master, <prefix>-node1, <prefix>-node2, ...
NODE_PREFIX = 'gg'

CFSSL_PROGS_SHA256 = """
0725a1cca3857392158807b543b75dc6388e2102e8a189792c4da7ac19f750b5  cfssl-bundle
48685e849565cd7d27ac2daf68faa835a5151fd3feac87c6715bcb92d58dc280  cfssl-certinfo
4106c11c61aa9e98b1967adab6db711d2b50a0f02f844329e9ad44f199bdf135  cfssl-newkey
71e41ef447f49ad236d75ec42152625c6fcf6c37122784740bd19b0a7c399560  cfssl-scan
11c708acaf48a69abf6f896f5c6158f7547a3c1bf44e14ca3b3ab440c1f808f1  cfssl
e138102329d96f5a67aa168034a256a8376febf4ecde7b8e837c3f2e08b1cd19  cfssljson
dac738390bc346b94c497b62a82f75cb05f0dafd5dad7d9dd63dedb9bc31092a  mkbundle
d53bbc0d2ac2d57c089d4f730d9e7b2d365701adc1bb417153a5f70a16bd10d6  multirootca
"""

# Shell script to setup the necessary software for kubernetes
# FIXME - howto add a static IP
# TODO - add static certificates
# TODO - add kubeadm call for master
PKG_SETUP = """\
#!/bin/sh
setup_params="$1"

setup_machine_id() {
    sudo rm -f /etc/machine-id /var/lib/dbus/machine-id
    sudo dbus-uuidgen --ensure=/etc/machine-id
}

setup_static_ip() {
}

set -e
nodename=`awk -F= '/^nodename=/ { print $2 }' "$setup_params"`
ipaddress=`awk -F= '/^ip=/ { print $2 }' "$setup_params"`
sudo hostname "$nodename"
setup_static_ip "$ipaddress"
curl -s https://packages.cloud.google.com/apt/doc/apt-key.gpg | sudo apt-key add -
echo "deb http://apt.kubernetes.io/ kubernetes-xenial main" | sudo tee /etc/apt/sources.list.d/kubernetes.list
sudo apt-get update -y
sudo apt-get install -y policykit-1 docker-ce
setup_machine_id
sudo dphys-swapfile swapoff
sudo dphys-swapfile uninstall
sudo update-rc.d dphys-swapfile remove
echo "Getting kubernetes packages"
sudo apt-get install -y kubelet kubeadm kubectl kubernetes-cni
sudo /usr/bin/raspi-config --expand-rootfs
"""

SETUP_SCRIPT = """
if [[ -e /boot/setup.txt ]] ; then
    tmp=`mktemp`
    rm -f /boot/setup.txt
    
    sh -x "%(setup_node_sh)s" "$tmp" >/boot/setup.log 2>&1
    rm -f "$tmp"
fi

"""


def absjoin(*params):
    return abspath(join(*params))


# FIXME - add comments to the methods
class ClusterSetup:
    def __call__(self, archive, node_names, targetdir, ipbase):
        targetinfo = stat(targetdir)
        with self._mktemp():
            info('Download cfssl')
            cfssldir = abspath('cfssl')
            self._download_cfssl(cfssldir)
            ipaddress = ipbase
            for name in node_names:
                node_image = absjoin(targetdir, '%s.img' % name)
                info('prepare image for node %s in %s' % (name, node_image))
                info('Unpacking archive %s' % archive)
                self._unzip(archive, node_image)
                try:
                    self._prepare_node_image(node_image, name, node_names[0], ipaddress, cfssldir)
                except Exception as e:
                    unlink(node_image)
                    raise

                chown(node_image, targetinfo.st_uid, targetinfo.st_gid)
                ipaddress = self._increment_ip(ipaddress)

        info('done')

    def _setup_cgroups(self):
        debug('setup cgrops in %s' % getcwd())
        with open(absjoin('boot', 'cmdline.txt'), 'a') as cmdline:
            cmdline.write('cgroup_enable=cpuset cgroup_memory=1')

    def _enable_ssh(self):
        debug('enable ssh in %s' % getcwd())
        with open(absjoin('boot', 'ssh'), 'w') as ssh:
            ssh.write('')

    def _prepare_node_image(self, image, nodename, master, ipadddress, cfssl):
        with self._mount(image):
            self._setup_nodename(master, nodename)
            self._enable_ssh()
            self._setup_cgroups()
            debug('install cfssl to %s' % absjoin('system', 'usr', 'local', 'bin'))
            self._copytree(cfssl, absjoin('system', 'usr', 'local', 'bin'))
            self._init_first_boot(ipadddress, nodename)

    def _copytree(self, srcdir, dstdir):
        for f in listdir(srcdir):
            copy2(absjoin(srcdir, f), dstdir)

    def _setup_nodename(self, master, nodename):
        debug('setup nodename %s in %s' % (nodename, getcwd()))
        with open(absjoin('system', 'etc', 'hostname'), 'w') as hostname:
            print(nodename, file=hostname)
        with open(absjoin('system', 'etc', 'hosts'), 'w') as hosts:
            print('127.0.1.1 %(nodename)s' % locals(), file=hosts)
            if nodename != master:
                print('10.0.0.1 %(master)s' % locals(), file=hosts)

    def _init_first_boot(self, ipadddress, nodename):
        debug('Prepare first boot in %s' % getcwd())
        with self._executable(absjoin('system', 'usr', 'local', 'bin', 'setup_node.sh')) as fname:
            self.create_setup_script(fname)
            with self._executable(absjoin('system', 'etc', 'rc.local')) as rclocal:
                self.setup_rclocal(rclocal, fname)
        self._create_setup_txt(absjoin('boot', 'setup.txt'), ipadddress, nodename)

    def create_setup_script(self, setup_node_sh):
        with open(setup_node_sh, 'x') as setup_node:
            print(PKG_SETUP % locals(), file=setup_node)

    def setup_rclocal(self, rc_local, setup_node_sh):
        with open(rc_local, 'r+') as script:
            script.write(self._edit(script.read(), SETUP_SCRIPT % locals()))

    def _create_setup_txt(self, fname, ipadddress, nodename):
        with open(fname, 'w') as setup:
            print('nodename=%s' % nodename, file=setup)
            print('ip=%s' % ipadddress, file=setup)

    def _edit(self, setup_script, setup_node_sh):
        lines = [l.rstrip() for l in setup_script.splitlines()]
        if 'exit 0' in lines:
            exit_line = lines.index('exit 0')
            lines.insert(exit_line, setup_node_sh)
        else:
            lines.append(setup_node_sh)
            lines.append('exit 0')

        return '\n'.join(lines)

    def _download_cfssl(self, dstdir):
        if not isdir(dstdir):
            makedirs(dstdir)

        for line in CFSSL_PROGS_SHA256.splitlines():
            if line:
                checksum, fname = line.split()
                dstfile = absjoin(dstdir, fname)
                self._download('https://pkg.cfssl.org/R1.2/%s_linux-arm' % fname, dstfile, checksum)
                chmod(dstfile, 0o755)

    def _download(self, url, dstfile, checksum):
        request.urlretrieve(url, dstfile)
        m = sha256()
        with open(dstfile, 'rb') as f:
            hash = m.update(f.read())

        if checksum != m.hexdigest():
            raise RuntimeError('Checksum of %s does not match!' % dstfile)

    @staticmethod
    def _unzip(archive, dst_image):
        with ZipFile(archive) as image_archive:
            for name in image_archive.namelist():
                if name.endswith('.img'):
                    image = image_archive.extract(name, dirname(dst_image))
                    if isfile(dst_image):
                        unlink(dst_image)

                    rename(image, dst_image)
                    return dst_image

        raise RuntimeError('No image file contained in archive %s' % archive)

    @contextmanager
    def _mktemp(self):
        here = getcwd()
        tempdir = mkdtemp()
        try:
            chdir(tempdir)
            yield tempdir, here
        finally:
            chdir(here)
            rmtree(tempdir)

    @contextmanager
    def _mount(self, image):
        with self._kpartx(abspath(image)) as nodes:
            with self._mktemp() as (here, cwd):
                for d in nodes.keys():
                    mkdir(d)

                boot = abspath('boot')
                system = abspath('system')
                with self._mounted(nodes['boot'], boot) as boot:
                    with self._mounted(nodes['system'], system) as system:
                        chdir(here)
                        yield boot, system

    @contextmanager
    def _kpartx(self, image):
        output = check_output(('sudo', 'kpartx', '-a', '-v', '-s', image), universal_newlines=True)
        # $ sudo kpartx -a -v -s 2018-03-13-raspbian-stretch-lite.img
        # add map loop1p1 (252:7): 0 85611 linear /dev/loop1 8192
        # add map loop1p2 (252:8): 0 3530752 linear /dev/loop1 98304
        try:
            nodes = []
            for l in output.splitlines():
                if l:
                    fields = l.split()
                    nodes.append((fields[2], fields[5]))

            assert len(nodes) == 2
            # sort nodes by size - the smaller node is 'boot'
            nodes.sort(key=lambda t: t[1], reverse=True)
            yield {'boot': '/dev/mapper/%s' % nodes[0][0], 'system': '/dev/mapper/%s' % nodes[1][0]}
        finally:
            check_call(('sudo', 'kpartx', '-d', image))

    @contextmanager
    def _mounted(self, mapping, mountpoint):
        try:
            debug('mount %s on %s' % (mapping, mountpoint))
            check_call(('sudo', 'mount', mapping, mountpoint))
            yield mountpoint
        finally:
            check_call(('sudo', 'umount', mountpoint))

    @contextmanager
    def _executable(self, param):
        yield param
        chmod(param, 0o755)

    def _increment_ip(self, ipbase):
        octets = [int(o) for o in ipbase.split('.')]
        octets[3] += 1
        return '.'.join([str(o) for o in octets])


def _check_ip(param):
    octets = [int(o) for o in param.split('.')]
    for o in octets:
        if 0 <= o <= 255:
            continue

        raise RuntimeError('Invalid IP address: %s' % param)

    return param


def main(*args):
    targetdir = getcwd() if len(args) < 4 else args[3]
    nodenames = prepare_names(
        NODE_COUNT if len(args) < 2 else int(args[1]),
        NODE_PREFIX if len(args) < 3 else args[2])
    ipaddress = BASE_IP if len(args) < 5 else _check_ip(args[4])
    raspbian_archive = abspath(args[0])
    setup = ClusterSetup()
    setup(raspbian_archive, nodenames, targetdir, ipaddress)


if __name__ == '__main__':
    def prepare_names(num_nodes, prefix):
        result = [prefix + '-master']
        for i in range(1, num_nodes):
            result += ['%s-node-%d' % (prefix, i)]

        return tuple(result)

    if len(sys.argv) < 2:
        exit(__doc__)

    if geteuid() != 0:
        exit("You must be root to use this software")

    basicConfig(level=DEBUG)
    try:
        main(*sys.argv[1:])
    except RuntimeError as e:
        exit('\n'.join((str(e), __doc__)))
