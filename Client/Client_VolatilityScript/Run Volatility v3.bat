
@echo off

:: Define some variables and setup directoriess
set mm=%Date:~3,2%
set dd=%Date:~0,2%
set yyyy=%Date:~6,4%

SET currdt=%DATE:~4,2%_%DATE:~7,2%_%DATE:~-4%_%time:~0,2%_%time:~3,2%_%time:~6,2%

SET mm=%DATE:~4,2%
SET dd=%DATE:~7,2%
SET yyyy=%DATE:~-4%
SET timehour=%time:~0,2%
if "%timehour:~0,1%" equ " " set timehour=0%timehour:~1,1%
::SET timehour=%timehour: =0%
SET mins=%time:~3,2%
SET millis=%time:~6,2%

::##########################################################################
::#Setup the correct paths for your installation#
::##########################################################################

set CustomTimeStamp=%yyyy%%mm%%dd%%timehour%%mins%
set MDDDIR="C:\Program Files\Mdd"
set VOLDIR="C:\Python27\Scripts\"
set PYTHON="C:\Python27\python.exe"
::set PERL="C:\Perl\bin\perl.exe"
set MD5Chk="C:\Program Files\FCIV"
set ZipSoftware="C:\Program Files\7-Zip\7z.exe"
set ZipFileName=S:\Forensics\%COMPUTERNAME%_%CustomTimeStamp%.zip

mkdir S:\Image\%CustomTimeStamp%
set MemDumpFile="C:\Image.raw"

mkdir S:\Forensics\%CustomTimeStamp%
mkdir S:\Forensics\%CustomTimeStamp%\dumps

set CASELIB="S:\Forensics\%CustomTimeStamp%"
set DUMPS="S:\Forensics\%CustomTimeStamp%\dumps\"

set MEMDUMP="%MemDumpFile%"
set REPFILE="Log.txt"
set PROFILE=--profile="WinXPSP3x86"

%MDDDIR%\mdd -o  %MemDumpFile% >> %CASELIB%\%REPFILE%

echo "*** Usage: volcmd.bat 'memory_dump' 'name-of-report.txt'"
echo "*** Case directory: %CASELIB%
echo "*** Memory dump: %MEMDUMP%
echo "*** Report file: %REPFILE%
echo "*** Analyst Running Report: %USERNAME%


echo ############################################################>> %CASELIB%\%REPFILE%
echo # Volatility Assesment Report:  %date% at %time%  #>> %CASELIB%\%REPFILE%
echo ############################################################>> %CASELIB%\%REPFILE%
echo. >> %CASELIB%\%REPFILE%
echo ---  Report Created on %date% at %time% by %USERNAME% >> %CASELIB%\%REPFILE%
echo. >> %CASELIB%\%REPFILE%
echo ---  MD5 hash of Memory Sample 
echo Start %time%>> %CASELIB%\%REPFILE%
%MD5Chk%\FCIV -md5 %MEMDUMP% >> %CASELIB%\md5.txt
echo End  %time%>> %CASELIB%\%REPFILE%
echo. >> %CASELIB%\%REPFILE%
echo ####################################>> %CASELIB%\%REPFILE%
echo # Identifying Memory Image:        #>> %CASELIB%\%REPFILE%
echo ####################################>> %CASELIB%\%REPFILE%
echo command imageinfo.>> %CASELIB%\%REPFILE%
echo Start %time%>> %CASELIB%\%REPFILE% 
::%VOLDIR%\vol.py %PROFILE% imageinfo -f %MEMDUMP% >> %CASELIB%\imageinfo.txt
echo End  %time%>> %CASELIB%\%REPFILE%


echo command printkey
echo --- hivelist output >> %CASELIB%\%REPFILE%
echo Start %time%>> %CASELIB%\%REPFILE%
::%VOLDIR%\vol.py %PROFILE% hivelist -f %MEMDUMP%  >> %CASELIB%\hivelist.txt
%VOLDIR%\vol.py %PROFILE% printkeyf -K "Microsoft\Windows NT\CurrentVersion\Winlogon" -f %MEMDUMP% >> %CASELIB%\printkeyf.txt
%VOLDIR%\vol.py %PROFILE% printkeyf -K "Microsoft\Windows NT\CurrentVersion" -f %MEMDUMP% >> %CASELIB%\printkeyf.txt
%VOLDIR%\vol.py %PROFILE% printkeyf -K "ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile"  -f %MEMDUMP% >> %CASELIB%\printkeyf.txt
%VOLDIR%\vol.py %PROFILE% printkeyf -K "Microsoft\Windows NT\CurrentVersion\Run"  -f %MEMDUMP% >> %CASELIB%\printkeyf.txt
%VOLDIR%\vol.py %PROFILE% printkeyf -K "Microsoft\Windows NT\CurrentVersion\Wow"  -f %MEMDUMP% >> %CASELIB%\printkeyf.txt
%VOLDIR%\vol.py %PROFILE% printkeyf -K "Microsoft\Windows NT\CurrentVersion\Windows"  -f %MEMDUMP% >> %CASELIB%\printkeyf.txt

echo End %time%>> %CASELIB%\%REPFILE%


echo command hivelist 
echo --- hivelist output >> %CASELIB%\%REPFILE%
echo Start %time%>> %CASELIB%\%REPFILE%
::%VOLDIR%\vol.py %PROFILE% hivelist -f %MEMDUMP%  >> %CASELIB%\hivelist.txt
%VOLDIR%\vol.py %PROFILE% hivelistf -f %MEMDUMP% >> %CASELIB%\hivelistf.txt
echo End %time%>> %CASELIB%\%REPFILE%


echo command pstree
echo --- pstree output >> %CASELIB%\%REPFILE%
echo Start %time%>> %CASELIB%\%REPFILE%
::%VOLDIR%\vol.py %PROFILE% pstree -f  %MEMDUMP% >> %CASELIB%\pstree.txt
%VOLDIR%\vol.py %PROFILE% pstreef -f  %MEMDUMP% >> %CASELIB%\pstreef.txt
echo End %time%>> %CASELIB%\%REPFILE%


echo command symlinkscan
echo --- symlinkscan output >> %CASELIB%\%REPFILE%
echo Start %time%>> %CASELIB%\%REPFILE%
::%VOLDIR%\vol.py %PROFILE% pslist -f  %MEMDUMP% >> %CASELIB%\pslist.txt
%VOLDIR%\vol.py %PROFILE% symlinkscanf -f  %MEMDUMP% >> %CASELIB%\symlinkscanf.txt
echo End %time%>> %CASELIB%\%REPFILE%

echo command pslist
echo --- pslist output >> %CASELIB%\%REPFILE%
echo Start %time%>> %CASELIB%\%REPFILE%
%VOLDIR%\vol.py %PROFILE% pslistf -f  %MEMDUMP% >> %CASELIB%\pslistf.txt
echo End %time%>> %CASELIB%\%REPFILE%


echo #################################### >> %CASELIB%\%REPFILE%
echo # Network Connections Section:     #>> %CASELIB%\%REPFILE%
echo ####################################>> %CASELIB%\%REPFILE%



echo command connections
echo --- connections ouput>> %CASELIB%\%REPFILE%
echo --- Displays open network connections by walking the linked list in tcpip.sys>> %CASELIB%\%REPFILE%
echo Start %time%>> %CASELIB%\%REPFILE%
::%VOLDIR%\vol.py %PROFILE% connections -f %MEMDUMP% >> %CASELIB%\connections.txt
%VOLDIR%\vol.py %PROFILE% connectionsf -f %MEMDUMP% >> %CASELIB%\connectionsf.txt
echo End %time%>> %CASELIB%\%REPFILE%
echo. >> %CASELIB%\%REPFILE%

echo command connscan
echo --- connscan ouput>> %CASELIB%\%REPFILE%
echo --- Displays open network connections by walking the linked list in tcpip.sys>> %CASELIB%\%REPFILE%
echo Start %time%>> %CASELIB%\%REPFILE%
::%VOLDIR%\vol.py %PROFILE% connscan -f %MEMDUMP% >> %CASELIB%\connscan.txt
%VOLDIR%\vol.py %PROFILE% connscanf -f %MEMDUMP% >> %CASELIB%\connscanf.txt
echo End %time%>> %CASELIB%\%REPFILE%
echo. >> %CASELIB%\%REPFILE%

echo command sockets
echo --- sockets output >> %CASELIB%\%REPFILE%
echo --- Displays open client and server (listening) sockets by walking the linked list in tcpip.sys>> %CASELIB%\%REPFILE%
echo Start %time%>> %CASELIB%\%REPFILE%
::%VOLDIR%\vol.py %PROFILE% sockets -f %MEMDUMP% >> %CASELIB%\sockets.txt
%VOLDIR%\vol.py %PROFILE% socketsf -f %MEMDUMP% >> %CASELIB%\socketsf.txt
echo End %time%>> %CASELIB%\%REPFILE%
echo. >> %CASELIB%\%REPFILE%
echo command sockscan
echo --- sockscan output >> %CASELIB%\%REPFILE%
echo --- Scan physical memory for socket objects>> %CASELIB%\%REPFILE%
echo Start %time%>> %CASELIB%\%REPFILE%
::%VOLDIR%\vol.py %PROFILE% sockscan -f %MEMDUMP% >> %CASELIB%\sockscan.txt
%VOLDIR%\vol.py %PROFILE% sockscanf -f %MEMDUMP% >> %CASELIB%\sockscanf.txt
echo End %time%>> %CASELIB%\%REPFILE%


echo command psxview
echo --- psxview output >> %CASELIB%\%REPFILE%
echo Start %time%>> %CASELIB%\%REPFILE%
::%VOLDIR%\vol.py %PROFILE% psxview -f  %MEMDUMP% >> %CASELIB%\psxview.txt
%VOLDIR%\vol.py %PROFILE% psxviewf -f  %MEMDUMP% >> %CASELIB%\psxviewf.txt
echo End %time%>> %CASELIB%\%REPFILE%
echo command idt
echo --- idt output >> %CASELIB%\%REPFILE%
echo Start %time%>> %CASELIB%\%REPFILE%
::%VOLDIR%\vol.py %PROFILE% idt -f  %MEMDUMP% >> %CASELIB%\idt.txt
%VOLDIR%\vol.py %PROFILE% idtf -f  %MEMDUMP% >> %CASELIB%\idtf.txt
echo End %time%>> %CASELIB%\%REPFILE%
echo command gdt
echo --- gdt output >> %CASELIB%\%REPFILE%
echo Start %time%>> %CASELIB%\%REPFILE%
::%VOLDIR%\vol.py %PROFILE% gdt -f  %MEMDUMP% >> %CASELIB%\gdt.txt
%VOLDIR%\vol.py %PROFILE% gdtf -f  %MEMDUMP% >> %CASELIB%\gdtf.txt
echo End %time%>> %CASELIB%\%REPFILE%
echo command callbacks
echo --- callbacks output >> %CASELIB%\%REPFILE%
echo Start %time%>> %CASELIB%\%REPFILE%
::%VOLDIR%\vol.py %PROFILE% callbacks -f  %MEMDUMP% >> %CASELIB%\callbacks.txt
%VOLDIR%\vol.py %PROFILE% callbacksf -f  %MEMDUMP% >> %CASELIB%\callbacksf.txt
echo End %time%>> %CASELIB%\%REPFILE%
echo command timers
echo --- timers output >> %CASELIB%\%REPFILE%
echo Start %time%>> %CASELIB%\%REPFILE%
::%VOLDIR%\vol.py %PROFILE% timers -f  %MEMDUMP% >> %CASELIB%\timers.txt
%VOLDIR%\vol.py %PROFILE% timersf -f  %MEMDUMP% >> %CASELIB%\timersf.txt
echo End %time%>> %CASELIB%\%REPFILE%

echo command ldrmodules
echo --- ldrmodules output >> %CASELIB%\%REPFILE%
echo Start %time%>> %CASELIB%\%REPFILE%
::%VOLDIR%\vol.py %PROFILE% ldrmodules -f  %MEMDUMP% >> %CASELIB%\ldrmodules.txt
%VOLDIR%\vol.py %PROFILE% ldrmodulesf -f  %MEMDUMP% >> %CASELIB%\ldrmodulesf.txt
echo End %time%>> %CASELIB%\%REPFILE%

echo command FileScan
echo --- FileScan output >> %CASELIB%\%REPFILE%
echo Start %time%>> %CASELIB%\%REPFILE%
::%VOLDIR%\vol.py %PROFILE% filescan -f  %MEMDUMP% >> %CASELIB%\filescan.txt
%VOLDIR%\vol.py %PROFILE% filescanf -f  %MEMDUMP% >> %CASELIB%\filescanf.txt
echo End %time%>> %CASELIB%\%REPFILE%

echo command DriverScan
echo --- DriverScan  output >> %CASELIB%\%REPFILE%
echo Start %time%>> %CASELIB%\%REPFILE%
::%VOLDIR%\vol.py %PROFILE% driverscan -f  %MEMDUMP% >> %CASELIB%\driverscan.txt
%VOLDIR%\vol.py %PROFILE% driverscanf -f  %MEMDUMP% >> %CASELIB%\driverscanf.txt
echo End %time%>> %CASELIB%\%REPFILE%


echo command MutantScan
echo --- MutantScan output >> %CASELIB%\%REPFILE%
echo Start %time%>> %CASELIB%\%REPFILE%
::%VOLDIR%\vol.py %PROFILE% mutantscan -f  %MEMDUMP% >> %CASELIB%\mutantscan.txt
%VOLDIR%\vol.py %PROFILE% mutantscanf -f  %MEMDUMP% >> %CASELIB%\mutantscanf.txt
echo End %time%>> %CASELIB%\%REPFILE%

echo command PSScan
echo --- PSScan output >> %CASELIB%\%REPFILE%
echo Start %time%>> %CASELIB%\%REPFILE%
::%VOLDIR%\vol.py %PROFILE% psscan -f  %MEMDUMP% >> %CASELIB%\psscan.txt
%VOLDIR%\vol.py %PROFILE% psscanf -f  %MEMDUMP% >> %CASELIB%\psscanf.txt
echo End %time%>> %CASELIB%\%REPFILE%

echo command Handles
echo --- handles output >> %CASELIB%\%REPFILE%
echo Start %time%>> %CASELIB%\%REPFILE%
::%VOLDIR%\vol.py %PROFILE% handles -f  %MEMDUMP% >> %CASELIB%\handles.txt
%VOLDIR%\vol.py %PROFILE% handlesf -f  %MEMDUMP% >> %CASELIB%\handlesf.txt
echo End %time%>> %CASELIB%\%REPFILE%

echo command envars
echo --- envars output >> %CASELIB%\%REPFILE%
echo Start %time%>> %CASELIB%\%REPFILE%
::%VOLDIR%\vol.py %PROFILE% envars -f  %MEMDUMP% >> %CASELIB%\envars.txt
%VOLDIR%\vol.py %PROFILE% envarsf -f  %MEMDUMP% >> %CASELIB%\envarsf.txt
echo End %time%>> %CASELIB%\%REPFILE%



%ZipSoftware% a -tZip %ZipFileName% %CASELIB%\

::echo user MyUserName> ftpcmd.dat
::echo MyPassword>> ftpcmd.dat
echo bin>> ftpcmd.dat
echo put %ZipFileName% >> ftpcmd.dat
echo quit>> ftpcmd.dat
ftp -A -n -s:ftpcmd.dat 172.16.73.134 
del ftpcmd.dat
