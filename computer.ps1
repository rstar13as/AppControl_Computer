<#		
	===========================================================================
	 Created:   	2023
	 Created by:    Rick Smith - srick@vmware.com
	 Organization: 	VMware Carbon Black - Professional Services     

	===========================================================================
	.DESCRIPTION

    Carbon Black App Control
    This script will change the policy of the computers specified in a CSV file to the policy also specified in the CSV file.

API : https://developer.carbonblack.com/reference/enterprise-protection/8.0/rest-api#computer

    CSV File Format:
        2 columns
        Column 1 header = Computer
        Column 2 header = Policy

        Column 1 should be a list of computers matching EXACTLY how they appear in the CBAC console, including "Domain\" if applicable
        Column 2 should be the EXACT name of the policy the computer should move to


    .NOTES

    You must specify the variables in the first section.

    No Warranty or Support
    Always test first on a small subset of machines!


#>



##################### SUPPLY THESE VARIABLES ##############################


#API Credentials must have permisson to View Computers, Manage Computers, and View Policies
$apiToken = "810201D2-9969-4284-B7D3-CF6330620266"

#CBAC server hostname or IP address.  Do not include "https://"
$serverName = "192.168.49.180"

#Path to the CSV input file, formatted as explained above
$csvFile = "C:\temp\ComputersNAMES2023-04-11.csv"

#If $true, only Log what would have happened but don't send the API command to change policy
$simulate = $true

#If $false then don't attempt to move disconnected agents
$moveDisconnected = $false

#Path and file name to use for output log in CSV format.  Make sure the folder exists and the script can write to it.
$logFile = "C:\temp\CBAC-API-CHANGE-POLICY-FROM-CSV-RESULT-LOG.csv"


##################### DO NOT EDIT BELOW THIS LINE #########################

$t = $apiToken
$s = $serverName
$h = "X-Auth-Token"
$u = "https://$s/api/bit9platform/v1"

add-type @"
    using System.Net;
    using System.Security.Cryptography.X509Certificates;
    public class TrustAllCertsPolicy : ICertificatePolicy {
        public bool CheckValidationResult(
            ServicePoint srvPoint, X509Certificate certificate,
            WebRequest request, int certificateProblem) {
            return true;
        }
    }
"@

[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy


cls
Write-Host "Attempting to get policy details from server......."
$policies = Invoke-RestMethod -Headers @{$h=$t} -Method Get -Uri "$u/policy?q=name:*"
Write-Host "Found" $policies.count "policies on the server."

Write-Host "`nImporting $csvFile...."
$records = Import-Csv $csvFile
Write-Host "Found" $records.count "rows in $csvFile"

$resultLog = @()

foreach ($record in $records) {

    $resultObject = New-Object psobject
    Add-Member -InputObject $resultObject -MemberType NoteProperty -Name "Computer" -Value $record.Computer
    Add-Member -InputObject $resultObject -MemberType NoteProperty -Name "APIRequestURI" -Value "N/A"
    Add-Member -InputObject $resultObject -MemberType NoteProperty -Name "APIRequestBody" -Value "N/A"
            
    $uri = "$u/Computer?q=name:" + $record.computer + "&q=deleted:false"

	Write-Host "`n--------------------------------------------------------"
    Write-Host "`nAttempting to find" $record.Computer "on $serverName"
    $computer = Invoke-RestMethod -Headers @{$h=$t} -Method Get -Uri $uri

    if ($computer) { #matching computer was found on server
       
        Add-Member -InputObject $resultObject -MemberType NoteProperty -Name "ComputerID" -Value $computer.id
        Add-Member -InputObject $resultObject -MemberType NoteProperty -Name "StartingPolicy" -Value $computer.policyName
        Add-Member -InputObject $resultObject -MemberType NoteProperty -Name "StartingPolicyID" -Value $computer.policyID
        Add-Member -InputObject $resultObject -MemberType NoteProperty -Name "Connected" -Value $computer.connected

        Write-Host "Found" $computer.name "in" $computer.policyName "with policyID" $computer.policyId
        
        Write-Host "`nAttempting to find the policyID for the destination policy:" $record.Policy
        foreach ($policy in $policies) {
            
            $body=""
            $result=""

            if ($policy.name -eq $record.Policy) { #Policy from input file was found to exist on server

                Add-Member -InputObject $resultObject -MemberType NoteProperty -Name "DestinationPolicyID" -Value $policy.id 
                
                write-host "Found policyId" $policy.id "for destination policy:" $record.Policy
                Write-Host "`nCreating API command to move:`n" $computer.name "from" $computer.policyname "to" $policy.name
                Write-Host " Computer ID" $computer.id "from Policy ID" $computer.policyId "to Policy ID" $policy.id

                
                $body='{"policyId":"' + $policy.id + '"}'
                $uri = "$u/Computer/" + $computer.id

                $resultObject.APIRequestBody = $body
                $resultObject.APIRequestURI = $uri
                
                if ($simulate -eq $true -and $moveDisconnected -eq $true) { #Don't actually call the API to change the policy

                    Add-Member -InputObject $resultObject -MemberType NoteProperty -Name "Result" -Value "Simulated - Policy Change request sent to API"

                } elseif ($simulate -eq $false -and $moveDisconnected -eq $true) { #Call the API to change the policy
                
                    $result = Invoke-RestMethod -uri $uri -Headers @{$h=$t} -Method Put -Body $body -ContentType "application/json"

                } elseif ($simulate -eq $true -and $moveDisconnected -eq $false) {

                    if ($computer.connected -eq "True") { #Check if computer shows as connected

                        Add-Member -InputObject $resultObject -MemberType NoteProperty -Name "Result" -Value "Simulated - Policy Change request sent to API"

                    } else {

                        Add-Member -InputObject $resultObject -MemberType NoteProperty -Name "Result" -Value "Simulated - No Action - Agent Disconnected"

                    }                  

                } elseif ($simulate -eq $false -and $moveDisconnected -eq $false) {

                    if ($computer.connected -eq "True") {

                        $result = Invoke-RestMethod -uri $uri -Headers @{$h=$t} -Method Put -Body $body -ContentType "application/json"

                    } else {

                        Add-Member -InputObject $resultObject -MemberType NoteProperty -Name "Result" -Value "No Action - Agent Disconnected"

                    }                                        
                
                }

                if ($result) { 

                    Add-Member -InputObject $resultObject -MemberType NoteProperty -Name "Result" -Value "Policy Change request sent to API"
                    
                    Write-Host "Policy Change request sent successfully"

                }

                break
                                               
            }

        }

        if (!$body) { #$body variable was never populated because the specified Destination policy could not be found.

            Add-Member -InputObject $resultObject -MemberType NoteProperty -Name "DestinationPolicyID" -Value "Not Found"
            Add-Member -InputObject $resultObject -MemberType NoteProperty -Name "Result" -Value "Error - Destination Policy Not Found"
            
            Write-Host "Could not find a policyID for" $record.Policy -ForegroundColor Yellow
        
        }
     

    } else { #Computer Name not found on server

        
        Add-Member -InputObject $resultObject -MemberType NoteProperty -Name "ComputerID" -Value "Not Found"
        Add-Member -InputObject $resultObject -MemberType NoteProperty -Name "StartingPolicy" -Value "Not Found"
        Add-Member -InputObject $resultObject -MemberType NoteProperty -Name "StartingPolicyID" -Value "Not Found"
        Add-Member -InputObject $resultObject -MemberType NoteProperty -Name "DestinationPolicyID" -Value "N/A" 
        Add-Member -InputObject $resultObject -MemberType NoteProperty -Name "Result" -Value "Error - Computer Name Not Found on Server"
        Add-Member -InputObject $resultObject -MemberType NoteProperty -Name "Connected" -Value "N/A"

        Write-Host "Could not find" $record.Computer -ForegroundColor Yellow

    }
    
    Add-Member -InputObject $resultObject -MemberType NoteProperty -Name "DestinationPolicy" -Value $record.Policy
    Add-Member -InputObject $resultObject -MemberType NoteProperty -Name "Timestamp" -Value (Get-Date -Format "MM-dd-yyyy HH:mm:ss")

    $resultLog += $resultObject
    $resultObject | Select-Object Timestamp, Computer, ComputerID, Connected, StartingPolicy, StartingPolicyID, DestinationPolicy, DestinationPolicyID, APIRequestURI, APIRequestBody, Result | Export-Csv -path $logFile -NoTypeInformation -Append -Force
 
    
}
