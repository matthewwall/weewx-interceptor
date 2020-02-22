# installer for the weewx-interceptor driver
# Copyright 2016 Matthew Wall, all rights reserved
# Distributed under the terms of the GNU Public License (GPLv3)

from weecfg.extension import ExtensionInstaller

def loader():
    return InterceptorInstaller()

class InterceptorInstaller(ExtensionInstaller):
    def __init__(self):
        super(InterceptorInstaller, self).__init__(
            version="0.54",
            name='interceptor',
            description='Capture weather data from HTTP requests',
            author="Matthew Wall",
            author_email="mwall@users.sourceforge.net",
            files=[('bin/user', ['bin/user/interceptor.py'])]
            )
