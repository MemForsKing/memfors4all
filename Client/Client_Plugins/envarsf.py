# Volatility
# Copyright (C) 2007-2013 Volatility Foundation
# Copyright (c) 2012 Michael Ligh <michael.ligh@mnin.org>
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

import volatility.plugins.taskmods as taskmods

class Envarsf(taskmods.DllList):
    "Display process environment variables"

    def render_text(self, outfd, data):
        
        outfd.write("{0}||{1}||{2}||{3}||{4}\n".format('Pid', 'Process', 'Block', 'Variable', 'Value'))

        for task in data:
            for var, val in task.environment_variables():
                outfd.write("{0}||{1}||{2}||{3}||{4}\n".format(
                    task.UniqueProcessId,
                    task.ImageFileName,
                    task.Peb.ProcessParameters.Environment, 
                    var, val
                    ))
