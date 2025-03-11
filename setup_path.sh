#!/bin/bash
echo Adding toolkit directories to PATH...

export PATH="$PATH:C:\Personal\GithubProjects\AD-PT-Utils\wrappers\impacket"
export PATH="$PATH:C:\Personal\GithubProjects\AD-PT-Utils\wrappers\bloodhound"
export PATH="$PATH:C:\Personal\GithubProjects\AD-PT-Utils\wrappers\mimikatz"
export PATH="$PATH:C:\Personal\GithubProjects\AD-PT-Utils\wrappers\utilities"
export PATH="$PATH:C:\Personal\GithubProjects\AD-PT-Utils\bin"

echo Directories added to PATH for this session.
echo To make this permanent, add these lines to your .bashrc or .zshrc file.
