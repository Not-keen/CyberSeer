#!/bin/bash
# print all packages to a csv for checking
dpkg-query -W -f='${binary:Package},${Version}\n' > installed_software.csv
