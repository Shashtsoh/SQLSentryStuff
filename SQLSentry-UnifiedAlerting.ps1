<#
.SYNOPSIS
    This script accepts inputs from a SentryOne alert and submits them to one or more web APIs.  
.DESCRIPTION
    This script accepts inputs from a SentryOne alert and submits them to one or more web APIs.  
    Currently implemented APIs:
        - ServiceNow
        - Teams
.EXAMPLE
    Place the following text into the PowerShell command window in a SentryOne PowerShell action:
        $params = @{
            "ConditionType" = "<Advisory/Legacy>"
            "isRepositoryQuery" = <$true/$false>
            "ServiceNow" = $true
            "ServiceNowInstance" = <InstanceName>
            "Teams" = $true
            "Email" = $false
            "Severity" = 2
            "MessageText" = '<%MessageText%>'
            "ServerName" = '<%ServerName%>'
            "ObjectName" = '<%ObjectName%>'
            "Condition" = '<%Condition%>'
            "EmailFrom" = '<somecustomemail>@ldschurch.org'
            "DebugAlert" = $false
        }
        & <path>\S1_Unified_Alerts.ps1 @params  
    
    SQLSentry will parse its dedicated tokens (entries following the <%text%> pattern) and replace them as appropriate
    before executing the script.  Parameters with <> surrounding the value that are not SQLSentry tokens must be edited manually
.INPUTS
    ConditionTyppe
        String
        ValidateSet
            Advisory
            Legacy
        Specifies what type of alert we're processing from SentryOne.  Currently needed to differentiate between alerts 
        that can be actively closed and those that must be passively closed.  
        Selecting 'Advisory' will pass the value 'SentryOne - Positive Close' to ServiceNow as the Alert Source
        Selecting 'Legacy' will send the value 'SentryOne - Passive Close' as the Alert Source
    isRepositoryQuery
        Bool (Default False)
        Specifies whether the condition is based off of a repository query instead of a 
        direct call to the monitored server.  Should only be set to true for advisory queries using a repository query.
        This changes how we must process certain sets of data, such as the servername passed to ServiceNow.
    S1Environment
        String
        Default: Prod
        ValidateSet
            Prod
        Only needed if there is more than one S1 install in the environment.  If/When more than one environment exists, 
        modify the ValidateSet options as needed.
    ServiceNow
        Bool
        Determines if the alert will be posted to ServiceNow
    ServiceNowInstance
        String
        Name of the ServiceNow instance to send the alert to.  Used to build the API URL.
    Teams
        Bool
        Determines if the alert will be posted to ServiceNow
    Email
        Bool
        Determines whether the script will send an email
    Severity
        Int (0-5)
        Declares the alert severity.  Primarily used for ServiceNow.
        Severity options
            1 - Emergency (Don't use this unless you want full visibility at all levels)
            2 - Critical
            3&4 - Warning (treated same in SN
            5 - Info (don't use)
            0 - Clear alert (don't use in this script)
    MessageText
        String
        Should always be submitted as the <%MessageText%> token when used from S1
    ServerName
        String
        Should always be submitted as the <%ServerName%> token when used from S1
    ObjectName
        String
        Should always be submitted as the <%ObjectName%> token when used from S1
        Actual alerting object CI - anything from server to database to job
    Condition
        String
        Should always be submitted as the <%Condition%> token when used from S1
    EmailFrom
        String
        Lets us pick a custom from address for easier grouping in Outlook
    DebugAlert
        Bool (default false)
        Will output a file called DebugAlert.txt with the information submitted to the APIs

.NOTES
    General notes
#>

[CmdletBinding()]
param (
    [Parameter()]
    [ValidateSet("Advisory","Legacy")]
    [string]$ConditionType,

    [Parameter()]
    [bool]$isRepositoryQuery = $false,

    [Parameter()]
    [string]$S1Environment = "Prod", 

    [Parameter()]
    [bool]$ServiceNow,

    [Parameter()]
    [ValidateSet("lds","ldssand")]
    [string]$ServiceNowInstance,

    [Parameter()]
    [bool]$Teams,

    [Parameter()]
    [bool]$Email,

    [Parameter()]
    [int]$Severity,

    [Parameter()]
    [string]$MessageText,

    [Parameter()]
    [string]$ServerName,

    [Parameter()]
    [string]$ObjectName,

    [Parameter()]
    [string]$Condition,

    [Parameter()]
    [string]$EmailFrom,

    [Parameter()]
    [bool]$DebugAlert = $false
)

################################################################
#region Set Hardcoded Variables
################################################################
#############
#SentryOne
#############
$S1Instance = 'MSAOL12111\S01'
$crypt = '76492d1116743f0423413b16050a5345MgB8AHUAbwArAEMAaQBrAHIAegByAFMARQBqADkAUABjAFcAdQBKAE8AVQBtAHcAPQA9AHwAYwA1ADgAZgA1ADgANQBhADYANgAyADcAYgAwAGYAOQAyAGEAMQBjAGEAMwBmAGYAZAAyADkAZQBhADcANQA3AGMAMwBkADQANgBjADIAMwA4ADIAZQAzADAAMQBhAGYAOAAzADIAMgBjADcAOAA2AGIAYgAwAGQAYwA2AGQAYQA='
[pscredential]$S1UtilityLogin = new-object System.Management.Automation.PSCredential ("S1_Script_Utility", (ConvertTo-SecureString -String $crypt -Key (1..16)))

#############
#ServiceNow
#############
$is_SN_live = $true #This internal flag lets us turn SN alerts on/off without changing calls in S1

# API Creds.  User should be least privilige, with only the ability to post to the API.  Set up this way, we don't care about hardcoding credentials 
# Code assumes that all possible instances use the same creds.  If this is not the case, additional logic will be needed to differentiate them.
$SNuser = 'snc-sqlsentry'
$SNpass = ConvertTo-SecureString 'A@KvzpRgBB2q9G8hVy6&om86' -AsPlainText -Force 


#############
#Teams
#############
$is_Teams_Live = $true #This internal flag lets us turn Teams alerts on/off without changing calls in S1
# Teams connector URL
$TeamsURI = 'https://office365lds.webhook.office.com/webhookb2/5c45be95-a591-4ec9-b82c-a78880d67d22@61e6eeb3-5fd7-4aaa-ae3c-61e8deb09b79/IncomingWebhook/bd465143d39a437681d7f7e2ddda1f8d/be8a6c5e-93f7-4288-9a9b-b40f18597046'
            
$TeamsContentType = 'application/json'
$facts = @() #used for adaptive card

#endregion Set Hardcoded Variables
################################################################
#region Generate PSCustomObject from parameters
################################################################
$MessageObject = [PSCustomObject]@{
    # Orig values from params
    "MessageIn" = $MessageText
    "ServerNameIn" = $ServerName
    "ObjectNameIn" = $ObjectName
    "ConditionIn" = $Condition

    # Generally needed fields
    "General" = [PSCustomObject]@{
        "ShortDesc" = if($isRepositoryQuery){ "$($Condition) on $($ServerName)" } 
            else{ "$($Condition) on $($ObjectName)" }
        "ServerName" = if($isRepositoryQuery){
                if($ServerName -match '\\'){($ObjectName | Select-String -Pattern '[A-Za-z0-9.]+(?=\\)').Matches.Value} else{$ObjectName}
            } 
            else {
                if($ServerName -match '\\'){($ServerName | Select-String -Pattern '[A-Za-z0-9.]+(?=\\)').Matches.Value} else{$ServerName}
            }
        "MessageText" = $null
        "MessageProperties" = [PSCustomObject]@{}
        "EventID" = $null
        "ActionID" = $null
        "HeadID" = $null
        "CategoryName" = $null
        "KBArticle" = "KB44541"
    }

    # Output messages & objects
    "Output" = [PSCustomObject]@{
        "ServiceNow" = [PSCustomObject]@{
                Post = $null
                OpenQueue = $null
            }
        "Teams" = $null
        "Email" = $null
        "Errors" = [PSCustomObject]@{}
    }
    # Other misc values to be populated later for troubleshooting.
    "Misc" = [PSCustomObject]@{
        "ExtrasQuery" = $null
        "InsertQueueQuery" = $null
    }
    
    #Populating with nulls due to possibility that they won't be needed.  Properties will be populated later as necessary
    # ServiceNow
    "ServiceNow" = [PSCustomObject]@{
        "URI" = $null
        "Cred" = $null
        "Headers" = $null
        "ContentType" = $null
        "AlertSource" = $null
        "AlertSourceInstance" = $null
        "Severity" = $null
        "EventID" = $null  
    }
    
    # Teams
    "Teams" = [PSCustomObject]@{
        "URI" = $null
        "Facts" = $null
    }
}

###################################
#region General Object Properties
###################################
# Generate key/value pairs from message, where each pair takes on the form "[KEY]: VALUE"
$MessageArray = ($MessageText -split '(\[.+\]:.+\n)', 0, "regexmatch") | foreach-object {if($_ -eq $null -or $_ -eq ''){$null} else {$_}}
$arrayStart = if($null -eq $MessageArray[0]){1} else {0}

# $MessageObject.General.MessageText
$CleanMessage = if($null -eq $MessageArray[0]){""} else {(($MessageArray[$arrayStart].replace("-----",'')).replace("`n`n",'')).replace("`r",'')}
$MessageObject.General.MessageText = $CleanMessage


# Generate one object property in $MessageObject.General per key/value in $MessageArray
($arrayStart+1)..(($MessageArray.Count)-1) | foreach-object{
    if($null -ne $MessageArray[$_] -and $MessageArray[$_] -notmatch "-----"){
        $MessageArray[$_] = ($MessageArray[$_].replace("`n",'')).replace("`r",'')

        $npname = (($MessageArray[$_] | Select-String -Pattern "(?<=\[).+(?=\]:)").Matches.Value).Trim()
        $npvalue = (($MessageArray[$_] | Select-String -Pattern "(?<=(\]: )).*").Matches.Value).Trim()

        $MessageObject.General.MessageProperties | Add-Member -NotePropertyName $npname -NotePropertyValue $npvalue

        # Populate $facts
        $facts += (@{
            "title"="$npname"
            "value"="$npvalue"
        })        
    }
}

if($ConditionType -eq 'Advisory'){
    $MessageObject.General.MessageProperties | Add-Member -NotePropertyName 'URL' -NotePropertyValue ((($MessageText | Select-String -Pattern 'url:sqlsentry:\S*').Matches.Value).Replace('`r',''))
    $facts += $MessageObject.General.MessageProperties.URL
}

#Get Additional info about record from S1 database
try{
    if($ConditionType -eq 'Legacy'){
        $minutes = switch ($MessageObject.General.MessageProperties.'Response Ruleset') {
            'ServiceNow Passive Close - 1 min delay' {3}
            'ServiceNow Passive Close - 1 hr delay' {180}
            Default {10}
        }
        $MessageObject.Misc.ExtrasQuery = ";with 
        act as (
            select CategoryName
                , ID
                , NormalizedEventStartTime
                , iif(datediff(minute,lag(NormalizedEventStartTime) over(order by ID),NormalizedEventStartTime) < $minutes, 0, 1) as ChainHead    
            from vwObjectConditionActionHistory
            where ActionTypeName = 'Execute PowerShell'
                and ObjectName = '$($ObjectName)'
                and ConditionTypeName = '$($Condition)'
        )
        select top 1 ID, CategoryName
        from act 
        where  ChainHead = 1 and NormalizedEventStartTime <= '$($MessageObject.General.MessageProperties."Timestamp (UTC)")'
        order by id desc"

        $extra = Invoke-DbaQuery -SqlInstance "$S1Instance" -Database SentryOne -SqlCredential $S1UtilityLogin -query $MessageObject.Misc.ExtrasQuery -ErrorAction Stop | select-object ID, CategoryName
        $MessageObject.General.HeadID = $extra.ID
        $MessageObject.General.CategoryName = $extra.CategoryName
    }
  

    if($ConditionType -eq 'Advisory'){
        $MessageObject.General.EventID = (($MessageText | Select-String -Pattern '(url:sqlsentry:\S*(id=(?<ID>\d+)))').Matches.Groups | Where-Object -Property Name -eq 'ID').Value

        $MessageObject.Misc.ExtrasQuery = "        
            select isnull(CategoryName,'Advisory') as CategoryName
                , ID
            from vwObjectConditionActionHistory
            where ActionTypeName = 'Execute PowerShell'
                and ObjectName = '$($ObjectName)'
                and ConditionTypeName = substring('$($Condition)',0,51) /* The underlying table for the action stores this field as a varchar(50) despite the system allowing much longer names */
                and dateadd(ms, -1*datepart(ms,NormalizedEventEndTime),NormalizedEventEndTime) = '$($MessageObject.General.MessageProperties."Timestamp (UTC)")'
        "
        
        $extra = Invoke-DbaQuery -SqlInstance "$S1Instance" -Database SentryOne -SqlCredential $S1UtilityLogin -query "$($MessageObject.Misc.ExtrasQuery)" -ErrorAction Stop #| select-object ID, CategoryName

        $MessageObject.General.ActionID = $extra.ID
        $MessageObject.General.CategoryName = $extra.CategoryName
        
        $MessageObject.Misc.InsertQueueQuery = "
            select $($MessageObject.General.EventID) as EventID, ID as ActionID
            from vwObjectConditionActionHistory 
            where ActionTypeName = 'Execute PowerShell'
                and ObjectName = '$($ObjectName)'
                and ConditionTypeName = substring('$($Condition)',0,51) /* The underlying table for the action stores this field as a varchar(50) despite the system allowing much longer names */
                and dateadd(ms,-1*datepart(ms,EventStartTime),EventStartTime) = '$($MessageObject.General.MessageProperties."Start Time")'
                and message like '%url%?id=$($MessageObject.General.EventID)%'
            except
            select EventID, ActionID from Custom.SNow_Close_Queue
            "
    }
}
catch{
    $MessageObject.Misc | Add-Member -NotePropertyName ExtrasError -NotePropertyValue $_.exception.Message
}

#endregion General Object Properties
##########################################
#region ServiceNow Object Properties
##########################################
if($ServiceNow -and $is_SN_live){
    $MessageObject.ServiceNow.Uri = 'https://'+$ServiceNowInstance+'.service-now.com/api/global/em/jsonv2' #This one works
    $MessageObject.ServiceNow.Cred = New-Object System.Management.Automation.PSCredential -ArgumentList ($SNuser, $SNpass)
    $MessageObject.ServiceNow.Headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
        $MessageObject.ServiceNow.Headers.Add('Authorization',('Basic {0}' -f $base64AuthInfo)) #This one works.
        $MessageObject.ServiceNow.Headers.Add('Accept','application/json')
        $MessageObject.ServiceNow.Headers.Add('Content-Type',$contenttype)
        $MessageObject.ServiceNow.Headers.Add('Cache-Control', 'no-cache')
    $MessageObject.ServiceNow.ContentType = 'application/json'
    $MessageObject.ServiceNow.AlertSource = if($ConditionType -eq "Advisory"){'SentryOne - Positive Close'} else{'SentryOne - Passive Close'}
        # Alert source is used by ServiceNow to help differentiate which event rule to use.  
        # At least two rules are currently needed - one for alerts that can send a positive close signal and one for events that must time out to close
        # The names here are somewhat arbitrary, but they must be unique and match the event rule filter in ServiceNow
    $MessageObject.ServiceNow.AlertSourceInstance = "$S1Environment"
    $MessageObject.ServiceNow.Severity = "$Severity"

    # $MessageObject.ServiceNow.EventID
        # EventID is the Unique Key for the SN event record.  This must be unique per event from S1
        $eventID = switch ($conditionType) {
            "Advisory" {(($MessageText | Select-String -Pattern 'url:sqlsentry:\S*').Matches.Value).Replace('`r','')}  #gets url from message if it exists
            "Legacy" {"$($MessageObject.ConditionIn)$($MessageObject.ObjectNameIn)$($MessageObject.General.HeadID)"}
            Default {"CouldNotGenerateIDFromAlert"}
        }
        $eventID = ("$eventID $(if($ConditionType -eq 'Advisory'){''} else{'Passive'})").Replace(" ","")
        $MessageObject.ServiceNow.EventID = $eventID
}
#endregion ServiceNow Object Properties
#################################
#region Teams Object Properties
#################################
if($Teams){
    $MessageObject.Teams.URI = 'https://office365lds.webhook.office.com/webhookb2/5c45be95-a591-4ec9-b82c-a78880d67d22@61e6eeb3-5fd7-4aaa-ae3c-61e8deb09b79/IncomingWebhook/bd465143d39a437681d7f7e2ddda1f8d/be8a6c5e-93f7-4288-9a9b-b40f18597046'
    $MessageObject.Teams.Facts = $facts
}
#endregion Teams Object Properties
#endregion Generate PSCustomObject from parameters

################################################################
#region Process ServiceNow
################################################################
if($ServiceNow -and $is_SN_live){
    # ServiceNow API stuff
    [net.ServicePointmanager]::SecurityProtocol = "tls12, tls11, tls"
  
    #################################
    #Set variables used by API Call
    #################################
    $shortdesc
    $additional = @{
        "short_description" = "$($MessageObject.General.ShortDesc)"
        "name" = "$(if($ObjectName){"$($MessageObject.ObjectNameIn)"} else {"N/A"})"
        "S1ResponseRuleset" = $MessageObject.General.MessageProperties.'Response RuleSet'
        "portalURL" = "https://sqlsentry.ldschurch.org/"
    } | ConvertTo-Json

    $rawbody = @{
        #'additional_info' = "$($additional.replace('\','\\'))"
        'additional_info' = $additional
        'description' = "$($MessageObject.General.ShortDesc) `nKB Article = $($MessageObject.General.KBArticle) `n----------------------------------------------------------------------`n`nDescription= $($MessageObject.General.MessageText)`n`n Notes= $($alert_notes)"
        'event_class' = $MessageObject.ServiceNow.AlertSourceInstance
        'node' = $MessageObject.General.ServerName
        #'resource' = "$($alert_resource)"
        'severity' = $MessageObject.ServiceNow.Severity
        'source' = $MessageObject.ServiceNow.AlertSource
        'type' = $MessageObject.ConditionIn
        'message_key' = $MessageObject.ServiceNow.EventID
    }
    $body = (ConvertTo-Json $rawbody)
    $body = '{"records":['+$body+']}'

    $parameters = @{
        "Uri"         = $MessageObject.ServiceNow.Uri
        "Headers"     = $MessageObject.ServiceNow.Headers
        "Method"      = 'POST'
        "Body"        = $body
        "ContentType" = $MessageObject.ServiceNow.ContentType
        "Credential"  = $MessageObject.ServiceNow.Cred
    }

    try{
        $MessageObject.Output.ServiceNow.Post = Invoke-RestMethod @parameters -ErrorAction Stop
    } 
    catch{
        $MessageObject.Output.Errors | Add-Member -NotePropertyName "ServiceNow - Post" -NotePropertyValue $_.Exception.Message
    } 

    try{
        if($ConditionType -eq 'Advisory'){
            Invoke-DbaQuery -SqlInstance "$S1Instance" -Database SentryOne -SqlCredential $S1UtilityLogin -query "$($MessageObject.Misc.InsertQueueQuery)" -ErrorAction Stop | `
                ConvertTo-DbaDataTable -ErrorAction Stop | `
                Write-DbaDbTableData -SqlInstance "$S1Instance" -Database SentryOne -Schema Custom -Table SNow_Close_Queue -SqlCredential $S1UtilityLogin -ErrorAction Stop
            
                $MessageObject.Output.ServiceNow.OpenQueue = "Insert Succeeded"
        }
        else {$MessageObject.Output.ServiceNow.OpenQueue = "N/A"}
    }  
    catch{
        $MessageObject.Output.Errors | Add-Member -NotePropertyName "ServiceNow - OpenQueue" -NotePropertyValue "Insert Failed - $($_.Exception.Message)"
    }
        
    
}
#endregion Process ServiceNow
################################################################
#region Process Teams
################################################################
if($Teams -and $is_Teams_Live){
    #Create Adaptive Card JSON
    $card = [ordered]@{
        "type" = "message"
        "attachments" =  @(
            @{
                "contenttype" = "application/vnd.microsoft.card.adaptive"
                "content" = @{
                    '$schema' = "http =//adaptivecards.io/schemas/adaptive-card.json"
                    "type" = "AdaptiveCard"
                    "version" = "1.3"
                    "msTeams" = @{"width" = "full"}
                    "body" = @(
                        @{
                            "type" = "ColumnSet"
                            "columns" = @(
                                @{
                                    "type" = "Column"
                                    "items" = @(
                                        @{
                                            "type" = "TextBlock"
                                            "size" = "Large"
                                            "weight" = "Bolder"
                                            "text" = "$(($MessageObject.ObjectNameIn).replace("\",'\\'))"
                                        }
                                    )
                                    "width" = "auto"
                                }
                                @{
                                    "type" = "Column"
                                    "items" = @(
                                        @{
                                            "type" = "TextBlock"
                                            "text" = "$($MessageObject.ConditionIn)"
                                            "wrap" = $true
                                            "fontType" = "Default"
                                            "size" = "Medium"
                                        }
                                    )
                                    "width" = "stretch"
                                }
                            )
                        }
                        @{
                            "type" = "TextBlock"
                            "spacing" = "None"
                            "text" = "Created $($MessageObject.General.'Timestamp (Local)')"
                            "isSubtle" = $true
                            "wrap" = $true
                        }
                        @{
                            "type" = "TextBlock"
                            "text" = "$(($MessageObject.General.MessageText).replace("`n",'  \n'))"
                            "wrap" = $true
                        }
                        @{
                            "type" = "FactSet"
                            "facts" = $MessageObject.Teams.Facts
                        }                    
                    )
                }
            }
        )
    } | ConvertTo-Json -Depth 20

    $card = $card.replace("  \\n","  \n") #needed because the convert to json undoes the newline replacement done in object definition.  This should only target markdown newlines in textblocks

    $parameters = @{
        "URI"         = $TeamsURI
        "Method"      = 'POST'
        "Body"        = $card
        "ContentType" = $TeamsContentType
    }

    try{
        $MessageObject.Output.Teams = Invoke-RestMethod @parameters -ErrorAction Stop
    }
    catch{
        $MessageObject.Output.Errors | Add-Member -NotePropertyName "Teams - Post" -NotePropertyValue $_.Exception.Message
    }
}
#endregion Process Teams


##############################################################################
# Email functionality as requested by Manpreet
# This section will send one email every time this script es executed.
# Implemented here per request to avoid needing to set up individual email
#   alerts for every condition.  
##############################################################################
if($Email){
    $EmailTo = "<toaddress>" #We don't want to use this often, so we're going to restrict it to send to the platform team only
    $Subject = "$($Condition) on $($ServerName)."",""name"":""$($ObjectName)"
    $Body = $MessageText
    $SMTPServer = "<smtp server>"

    $msg = new-object Net.Mail.MailMessage
    $SMTPClient = New-Object Net.Mail.SmtpClient($SmtpServer, 25)
    $msg.From = $EmailFrom
    $msg.To.Add($EmailTo)
    $msg.Subject = $Subject
    $msg.Body = $Body
    $SMTPClient.EnableSsl = $false
    
    $MessageObject.Output.Email = try{$SMTPClient.Send($msg)} catch{$_.Exception.Message}
}


########################################
# Misc stuff for testing
########################################
if($DebugAlert){
    $MessageObject | ConvertTo-Json -Depth 10 | Out-File -FilePath "c:\sentryone\debug-MessageObject.txt"

    $MessageObject.Misc.ExtrasQuery | out-file -FilePath "c:\sentryone\debug-query.txt"
    $extra | Out-File -FilePath "c:\sentryone\debug-extra.txt"
    
    $ObjectName | out-file -FilePath "c:\sentryone\debug-inputs.txt"
    $Condition | out-file -FilePath "c:\sentryone\debug-inputs.txt" -Append
    $ServerName | out-file -FilePath "c:\sentryone\debug-inputs.txt" -Append
    $MessageText | out-file -FilePath "c:\sentryone\debug-inputs.txt" -Append
}
