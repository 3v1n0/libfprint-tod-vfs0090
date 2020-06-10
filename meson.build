project('libfprint-tod-vfs0090', [ 'c' ],
    version: '0.8.5',
    license: 'LGPLv2.1+',
    default_options: [
        'buildtype=debugoptimized',
        'warning_level=1',
        'c_std=c99',
    ],
    meson_version: '>= 0.46.0')

vfs0090_deps = []

libfprint_tod_dep = dependency('libfprint-2-tod-1')
udev_dep = dependency('udev')

vfs0090_deps += libfprint_tod_dep
vfs0090_deps += dependency('nss')
vfs0090_deps += dependency('openssl')
vfs0090_deps += dependency('pixman-1')

fake_driver = shared_module('fprint-tod-vfs0090',
    sources: [
        'vfs0090.c',
    ],
    dependencies: vfs0090_deps,
    install: true,
    install_dir: libfprint_tod_dep.get_pkgconfig_variable('tod_driversdir')
)

install_data('60-libfprint-2-tod-vfs0090.rules',
    install_dir: udev_dep.get_pkgconfig_variable('udevdir'),
)
