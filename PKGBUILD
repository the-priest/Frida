# Maintainer: Luka <the-priest>
pkgname=frida-toolsmith
pkgver=2.2.0
pkgrel=1
pkgdesc="Describe a command-line tool, get a working one — a terminal toolsmith with no GUI anywhere in it"
arch=('any')
url="https://github.com/the-priest/frida"
license=('MIT')
depends=('python>=3.10')
optdepends=('ruff: free static analysis of generated code before a paid fix round'
            'uv: much faster dependency installs'
            'pyinstaller: single-file binaries via /freeze')
source=("$pkgname-$pkgver.tar.gz::$url/archive/refs/tags/v$pkgver.tar.gz")
sha256sums=('SKIP')

package() {
  cd "$srcdir/frida-$pkgver"
  install -dm755 "$pkgdir/usr/lib/frida/frida"
  install -Dm644 frida/*.py -t "$pkgdir/usr/lib/frida/frida/"
  install -Dm644 LICENSE "$pkgdir/usr/share/licenses/$pkgname/LICENSE"
  install -Dm644 README.md "$pkgdir/usr/share/doc/$pkgname/README.md"

  install -dm755 "$pkgdir/usr/bin"
  cat > "$pkgdir/usr/bin/frida" <<'LAUNCHER'
#!/usr/bin/env python3
import sys
sys.path.insert(0, "/usr/lib/frida")
from frida.main import run
run()
LAUNCHER
  chmod 755 "$pkgdir/usr/bin/frida"
}
