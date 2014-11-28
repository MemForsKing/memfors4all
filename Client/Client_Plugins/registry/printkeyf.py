# Volatility
# Copyright (C) 2008-2013 Volatility Foundation
# Copyright (c) 2008 Brendan Dolan-Gavitt <bdolangavitt@wesleyan.edu>
#
# This file is part of Volatility.
#
# Volatility is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License Version 2 as
# published by the Free Software Foundation.  You may not use, modify or
# distribute this program under any other version of the GNU General
# Public License.
#
# Volatility is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Volatility.  If not, see <http://www.gnu.org/licenses/>.
#

"""
@author:       AAron Walters and Brendan Dolan-Gavitt
@license:      GNU General Public License 2.0
@contact:      awalters@4tphi.net,bdolangavitt@wesleyan.edu
@organization: Volatility Foundation
"""

#pylint: disable-msg=C0111

# from volatility.win32.datetime import windows_to_unix_time
import volatility.win32.hive as hivemod
import volatility.win32.rawreg as rawreg
import volatility.debug as debug
import volatility.utils as utils
import volatility.commands as commands
import volatility.plugins.common as common
import volatility.plugins.registry.hivelist as hivelist

def vol(k):
    return bool(k.obj_offset & 0x80000000)

class PrintKeyf(hivelist.HiveList):
    "Print a registry key, and its subkeys and values"
    # Declare meta information associated with this plugin

    meta_info = commands.Command.meta_info
    meta_info['author'] = 'Brendan Dolan-Gavitt'
    meta_info['copyright'] = 'Copyright (c) 2007,2008 Brendan Dolan-Gavitt'
    meta_info['contact'] = 'bdolangavitt@wesleyan.edu'
    meta_info['license'] = 'GNU General Public License 2.0'
    meta_info['url'] = 'http://moyix.blogspot.com/'
    meta_info['os'] = 'WIN_32_XP_SP2'
    meta_info['version'] = '1.0'

    def __init__(self, config, *args, **kwargs):
        hivelist.HiveList.__init__(self, config, *args, **kwargs)
        config.add_option('HIVE-OFFSET', short_option = 'o',
                          help = 'Hive offset (virtual)', type = 'int')
        config.add_option('KEY', short_option = 'K',
                          help = 'Registry Key', type = 'str')

    def hive_name(self, hive):
        try:
            return hive.FileFullPath.v() or hive.FileUserName.v() or hive.HiveRootPath.v() or "[no name]"
        except AttributeError:
            return "[no name]"

    def calculate(self):
        addr_space = utils.load_as(self._config)

        if not self._config.HIVE_OFFSET:
            hive_offsets = [(self.hive_name(h), h.obj_offset) for h in hivelist.HiveList.calculate(self)]
        else:
            hive_offsets = [("User Specified", self._config.HIVE_OFFSET)]

        for name, hoff in set(hive_offsets):
            h = hivemod.HiveAddressSpace(addr_space, self._config, hoff)
            root = rawreg.get_root(h)
            if not root:
                if self._config.HIVE_OFFSET:
                    debug.error("Unable to find root key. Is the hive offset correct?")
            else:
                if self._config.KEY:
                    yield name, rawreg.open_key(root, self._config.KEY.split('\\'))
                else:
                    yield name, root

    def voltext(self, key):
        return "(V)" if vol(key) else "(S)"

    def render_text(self, outfd, data):
        #outfd.write("Legend: (S) = Stable   (V) = Volatile\n\n")
        keyfound = False
        for reg, key in data:
            if key:
                keyfound = True
                outfd.write("Registry: {0}\n".format(reg))
                outfd.write("Key name: {0} {1:3s}\n".format(key.Name, self.voltext(key)))
                outfd.write("Last updated: {0}\n".format(key.LastWriteTime))
                outfd.write("\n")
                outfd.write("Subkeys:\n")
                for s in rawreg.subkeys(key):
                    if s.Name == None:
                        outfd.write("  Unknown subkey: " + s.Name.reason + "\n")
                    else:
                        outfd.write("  {1:3s} {0}\n".format(s.Name, self.voltext(s)))
                outfd.write("\n")
                outfd.write("Values:\n")
                for v in rawreg.values(key):
                    tp, dat = rawreg.value_data(v)
                    if tp == 'REG_BINARY' or tp == 'REG_NONE':
                        dat = "\n" + "\n".join(["{0:#010x}  {1:<48}  {2}".format(o, h, ''.join(c)) for o, h, c in utils.Hexdump(dat)])
                    if tp in ['REG_SZ', 'REG_EXPAND_SZ', 'REG_LINK']:
                        dat = dat.encode("ascii", 'backslashreplace')
                    if tp == 'REG_MULTI_SZ':
                        for i in range(len(dat)):
                            dat[i] = dat[i].encode("ascii", 'backslashreplace')
                    outfd.write("{0:13} {1:15} : {3:3s} {2}\n".format(tp, v.Name, dat, self.voltext(v)))
                outfd.write("__________\n")
        if not keyfound:
            outfd.write("\n")

class HiveDumpf(common.AbstractWindowsCommand):
    """Prints out a hive"""
    def __init__(self, config, *args, **kwargs):
        common.AbstractWindowsCommand.__init__(self, config, *args, **kwargs)
        config.add_option('HIVE-OFFSET', short_option = 'o', type = 'int',
                          help = 'Hive offset (virtual)')

    def calculate(self):
        addr_space = utils.load_as(self._config)

        if not self._config.hive_offset:
            debug.error("A Hive offset must be provided (--hive-offset)")

        h = hivemod.HiveAddressSpace(addr_space, self._config, self._config.hive_offset)
        return rawreg.get_root(h)

    def render_text(self, outfd, data):
        outfd.write("{0:20s} {1}\n".format("Last Written", "Key"))
        self.print_key(outfd, '', data)

    def print_key(self, outfd, keypath, key):
        if key.Name != None:
            outfd.write("{0:20s} {1}\n".format(key.LastWriteTime, keypath + "\\" + key.Name))
        for k in rawreg.subkeys(key):
            self.print_key(outfd, keypath + "\\" + key.Name, k)
