To generate the cwe-mapping.xml (a serialized powershell hashtable containing the CWE ID to KICS query ID mapping), update the cwe-map.csv file using a tool of your choice, then generate the new cwe-mapping.xml file using the New-CWEMapping.ps1 script as follows:

.\New-CWEMapping.ps1 -filename .\cwe-map.ps1

Then copy the new cwe-mapping.xml file to the build directory and run the build.ps1 build script to build the container.