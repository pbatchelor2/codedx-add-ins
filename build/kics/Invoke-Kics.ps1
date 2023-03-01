# Kics runner script
# Invoke kics and transform the output to CodeDX format
# Paul Batchelor
#
# Copyright 2022 BlackBerry Limited
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#	http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

param (
	[Parameter(Mandatory=$true)][string] $sourcePath,
	[Parameter(Mandatory=$true)][string] $outputPath,
	[Parameter(Mandatory=$true)][string] $scanRequestFilePath
)

Set-PSDebug -Strict
$ErrorActionPreference = 'Stop'
$VerbosePreference = 'Continue'

. ./add-in.ps1

function Convert-KicsOutput( $kicsresults, $cwemappings ) {
	# This function translates the default JSON output from KICS into XML that is suitable for import into CodeDx.

$header=@"
<?xml version="1.0" encoding="UTF-8"?>
<report date="$($kicsresults.start)" tool="KICS" version="$($kicsresults.kics_version)">
	<findings>`n
"@

$footer=@"
	</findings>
</report>
"@
	
	$outputxml = [System.Text.StringBuilder]""
	$outputxml.Append($header) | out-null
	
	foreach ($query in $kicsresults.queries) {
			foreach ($finding in $query.files) {
				$queryname     = [System.Security.SecurityElement]::Escape($query.query_name)
				$description   = [System.Security.SecurityElement]::Escape($query.description)
				$expectedvalue = [System.Security.SecurityElement]::Escape($finding.expected_value)
				$actualvalue   = [System.Security.SecurityElement]::Escape($finding.actual_value)
	
				if ($cwemappings.ContainsKey($query.query_ID)){
					$cwe = '<cwe id="'+ $cwemappings[$query.query_id] + '"/>'
				} else {
					$cwe = ""
				}
	
			$findingdetail = @"
			<finding severity="$($query.severity)" type="static">
				<native-id name="query_id" value="$($query.query_id)" />
				$cwe            
				<tool name="KICS" category="$($query.category)" code="$($queryname)"/>
				<location type="raw-file" path="$($finding.file_name)">
					<line is-indeterminate="false" start="$($finding.line)" end="$($finding.line)"/>
				</location>
				<description format="plain-text" include-in-hash="false">$($description)</description>
				<metadata>
					<value key="resource_type">$($finding.resource_type)</value>
					<value key="issue_type">$($finding.issue_type)</value>
					<value key="expected_value">$($expectedvalue)</value>
					<value key="actual_value">$($actualvalue)</value>
					<value key="cloud_provider">$($query.cloud_provider)</value>
					<value key="platform">$($query.platform)</value>
				</metadata>
			</finding>`n
"@
				$outputxml.Append($findingdetail) | out-null
			}
		}
	
		$outputxml.Append($footer) | out-null
		
		return $outputxml.ToString()
	}

write-verbose "Reading scan request file ($scanRequestFilePath)..."
$scanRequestConfig = Get-Config $scanRequestFilePath

$options = $scanRequestConfig.options

write-verbose @"
Invoke-Kics-v1.0
options: $options
"@

write-verbose 'Step 1: Unpacking source code...'
$sourceDir = New-Item -ItemType Directory -Path (Join-Path ([io.path]::GetTempPath()) (split-path $sourcePath -LeafBase))
Expand-SourceArchive $sourcePath $sourceDir -restoreGitDirectory

write-verbose 'Validating options...'
$invalidOptionRegex = 'f'

$invalidOptions = $options -match "^\s*-($invalidOptionRegex)(?:=.+)?$"
write-verbose "Matches: $matches"

if ($invalidOptions) {
	Exit-Script  "The following options conflict with options set by Code Dx: $invalidOptions"
}

write-verbose 'Step 3: Running kics...'

kics version

kics scan --ci -p $sourceDir -o $outputPath @($options)

if (test-path ($outputPath + "/results.json")) {
	write-verbose "Translating kics output to codedx format.."
	$rawresults = (get-content ($outputPath + "/results.json")) | Convertfrom-json
	if ($null -ne $rawresults) {
		# We have valid findings from kics, translate into CodeDX XML format
		$cwemappings = import-clixml "/opt/codedx/kics/work/config/cwe-mapping.xml"
		$finalxml = Convert-KicsOutput $rawresults $cwemappings
		write-verbose ("Writing CodeDX XML to :" + $outputPath + "/kicsreport.xml")
		$finalxml | out-file ($outputPath + "/kicsreport.xml") -Encoding utf8
	}
} else {
	write-verbose "Kics did not produce any output"
}

write-verbose 'Done'