option explicit
' CLIP: wscript.exe c:\asde\asde.vbs initdbox 1
' x64: run 16-bit ASDE.EXE under winevdm (otvdm). Do not wait for an XP VM.
dim WshShell : Set WshShell = WScript.CreateObject("WScript.Shell")
dim FSO : Set FSO = CreateObject("Scripting.FileSystemObject")
dim SaveCurrentDir : SaveCurrentDir = WshShell.CurrentDirectory
dim args, i, cmdLine, otvdm, goFile, doneFile

WshShell.Run """%CommonProgramFiles%\sagem sa\DgIpSvr.vbs"""
WshShell.CurrentDirectory = "C:\asde"

args = "initdbox 1"
if 0 < WScript.Arguments.Count then
	args = ""
	for i = 0 to WScript.Arguments.Count - 1
		if i > 0 then args = args & " "
		args = args & WScript.Arguments(i)
	next
end if

' Drop leftover VM handshake files if present.
goFile = "C:\ASDE\asde-go.cmd"
doneFile = "C:\ASDE\asde-done.txt"
if FSO.FileExists(goFile) then FSO.DeleteFile goFile, True
if FSO.FileExists(doneFile) then FSO.DeleteFile doneFile, True

otvdm = "C:\tmp\winevdm-master\build\otvdmw.exe"
if not FSO.FileExists(otvdm) then otvdm = "C:\tmp\winevdm-master\build\otvdm.exe"
if not FSO.FileExists(otvdm) then otvdm = FSO.BuildPath(FSO.GetParentFolderName(WScript.ScriptFullName), "..\build\otvdmw.exe")
if not FSO.FileExists(otvdm) then otvdm = FSO.BuildPath(FSO.GetParentFolderName(WScript.ScriptFullName), "..\build\otvdm.exe")

if FSO.FileExists(otvdm) then
	cmdLine = """" & otvdm & """ ASDE.EXE " & args
else
	cmdLine = "asde.exe " & args
end if

WshShell.Run cmdLine, 1, true
WshShell.CurrentDirectory = SaveCurrentDir
