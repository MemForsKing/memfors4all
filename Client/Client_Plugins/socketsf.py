# Volatility
#
# Authors:
# Mike Auty <mike.auty@gmail.com>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or (at
# your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details. 
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA 
#

#pylint: disable-msg=C0111

import volatility.plugins.common as common
import volatility.debug as debug
import volatility.win32 as win32
import volatility.utils as utils
import volatility.protos as protos

class Socketsf(common.AbstractWindowsCommand):
    """Print list of open sockets"""
    def __init__(self, config, *args, **kwargs):
        common.AbstractWindowsCommand.__init__(self, config, *args, **kwargs)
        config.add_option("PHYSICAL-OFFSET", short_option = 'P', default = False,
                          cache_invalidator = False,
                          help = "Physical Offset", action = "store_true")

    @staticmethod
    def is_valid_profile(profile):
        return (profile.metadata.get('os', 'unknown') == 'windows' and
                profile.metadata.get('major', 0) == 5)

    def render_text(self, outfd, data):
        offsettype = "(V)" if not self._config.PHYSICAL_OFFSET else "(P)"
		
        outfd.write("{0}||{1}||{2}||{3}||{4}||{5}||{6}\n".format('Offset(P)', 'PID', 'Port', 'Proto', 'Protocol', 'Address', 'Create Time'))

        for sock in data:
            if not self._config.PHYSICAL_OFFSET:
                offset = sock.obj_offset
            else:
                offset = sock.obj_vm.vtop(sock.obj_offset)
		
            outfd.write("{0:#x}||{1}||{2}||{3}||{4}||{5}||{6}\n".format(offset, sock.Pid, sock.LocalPort, sock.Protocol,
                           protos.protos.get(sock.Protocol.v(), "-"), 
						   sock.LocalIpAddress,sock.CreateTime))
    def calculate(self):
        addr_space = utils.load_as(self._config)

        if not self.is_valid_profile(addr_space.profile):
            debug.error("This command does not support the selected profile.")

        return win32.network.determine_sockets(addr_space)
