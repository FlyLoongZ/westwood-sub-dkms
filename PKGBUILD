_pkgbase=westwood-sub
pkgname=westwood-sub-dkms
pkgver=0.2
pkgrel=3
pkgdesc="The westwood-sub kernel modules (DKMS)"
arch=('x86_64')
url="https://github.com/FlyLoongZ/westwood-sub-dkms"
license=('GPL3')
depends=('dkms')
conflicts=("${_pkgbase}")
source=('Makefile'
        'dkms.conf'
        'tcp_westwood_sub.c'
        'Kbuild')
md5sums=('SKIP' 'SKIP' 'SKIP' 'SKIP')

package() {
    install -Dm644 Makefile dkms.conf tcp_westwood_sub.c Kbuild -t "${pkgdir}"/usr/src/${_pkgbase}-${pkgver}/
}


