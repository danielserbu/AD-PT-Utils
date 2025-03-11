@echo off
echo Adding toolkit directories to PATH...

set "PATH=%PATH%;C:\Personal\GithubProjects\AD-PT-Utils\wrappers\impacket"
set "PATH=%PATH%;C:\Personal\GithubProjects\AD-PT-Utils\wrappers\bloodhound"
set "PATH=%PATH%;C:\Personal\GithubProjects\AD-PT-Utils\wrappers\mimikatz"
set "PATH=%PATH%;C:\Personal\GithubProjects\AD-PT-Utils\wrappers\utilities"
set "PATH=%PATH%;C:\Personal\GithubProjects\AD-PT-Utils\bin"

echo Directories added to PATH for this session.
echo To make this permanent, update your system PATH environment variable.
