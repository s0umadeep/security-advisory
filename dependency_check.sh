#!/bin/bash

echo ">> OWASP Dependency Check scan process started"
#export JAVA_HOME=/usr/lib/jvm/java-11-openjdk-11.0.18.0.10-1.el7_9.x86_64/
echo "Download and install the latest version of the OWASP dependency-check tool"
LATEST_RELEASE_URL=$(curl -s https://api.github.com/repos/jeremylong/DependencyCheck/releases/latest | grep -o -E "https://github.com/jeremylong/DependencyCheck/releases/download/.*?-release.zip")
wget $LATEST_RELEASE_URL
unzip "dependency-check-8.2.1-release.zip"
cd dependency-check/bin
chmod +x dependency-check.sh

echo "Run the OWASP dependency-check scan on the current directory"
cd ../..
./dependency-check/bin/dependency-check.sh --scan . --format HTML --project "Dependency_Check_Project" --out ./ --enableExperimental

echo ">> OWASP Dependency Check cleanup process started"
rm -rf dependency-check-8.2.1-release.zip dependency-check-ant-8.2.1-release.zip dependency-check
echo ">> OWASP Dependency Check cleanup process finished"
echo ">> OWASP Dependency Check scan process finished"