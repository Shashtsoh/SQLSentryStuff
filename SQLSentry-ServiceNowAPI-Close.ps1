<#
.SYNOPSIS
	SQLSentry ServiceNow API call to close open alerts.
.DESCRIPTION
	The custom condition "_ServiceNow Event Sweeper" in SQLSentry
	checks the event log against two custom tables to identify all closed
	events which we sent into ServiceNow with the Active Close rule.  
	
	This script is designed to be run as a response to that condition;
	It queries the SQLSentry database to retrieve data about those events; it
	then loops through each to send an API call to close the alert in ServiceNow
.EXAMPLE
	Place the following text into the PowerShell command window in the SentryOne PowerShell action:
        
		& <path>\SQLSentry-ServiceNowAPI-Close.ps1 -ServiceNowInstance <InstanceName>
.INPUTS
	ServiceNowInstance
        String
        Name of the ServiceNow instance to send the alert to.  Used to build the API URL.
.NOTES
	General Notes
#>

[CmdletBinding()]
param (
	[Parameter()]
    [ValidateSet("<prodInstance>","<devInstance>")]
    [string]$ServiceNowInstance
)

# Import needed modules
Import-Module dbatools

function create-alertobject {
	[CmdletBinding()]
	param (
		[Parameter()]
		$AlertRow
	)

	# This script will only ever close advisory conditions.  This variable lets us avoid refactoring the code to 
	# remove all of the logic for legacy alerts.  In turn, this lets us keep nearly identical code to the initial
	# script that creates the alerts.
	$ConditionType = 'Advisory' 

	################################################################
	#region Generate PSCustomObject from parameters
	################################################################
	$MessageObject = [PSCustomObject]@{
		# Orig values from params
		"MessageIn" = $AlertRow.Message
		"ServerNameIn" = $AlertRow.ObjectName
		"ObjectNameIn" = $AlertRow.ObjectName
		"ConditionIn" = $Null

		# Generally needed fields
		"General" = [PSCustomObject]@{
			"ShortDesc" = "$($AlertRow.Condition) on $($AlertRow.ObjectName)"
			"ServerName" = if($AlertRow.ObjectName -match '\\'){($AlertRow.ObjectName | Select-String -Pattern '[A-Za-z0-9.]+(?=\\)').Matches.Value} else{$AlertRow.ObjectName}
			"MessageText" = $null
			"MessageProperties" = [PSCustomObject]@{}
			"EventID" = $null
			"ActionID" = $null
			"HeadID" = $null
			"CategoryName" = $null
		}

		# Output messages & objects
		"Output" = [PSCustomObject]@{
			"ServiceNow" = $null
			"Teams" = $null
			"Email" = $null
		}
		# Other misc values to be populated later for troubleshooting.
		"Misc" = [PSCustomObject]@{
			"ExtrasQuery" = $null
			"InsertQueueQuery" = $null
			"DeleteQueueQuery" = $null
		}
		
		#Populating with nulls due to possibility that they won't be needed.  Properties will be populated later as necessary
		# ServiceNow
		"ServiceNow" = [PSCustomObject]@{
			"URI" = $null
			"Cred" = $null
			"Headers" = $null
			"ContentType" = $null
			"AlertSource" = $null
			"AlertSourceInstance" = 'Prod'
			"Severity" = $null
			"EventID" = $null      
		}
	}

	$MessageObject.MessageIn = $AlertRow.Message
	$MessageObject.ServerNameIn = $AlertRow.ObjecttName
	$MessageObject.ObjectNameIn = $AlertRow.ObjectName

	###################################
	#region General Object Properties
	###################################
	# Generate key/value pairs from message, where each pair takes on the form "[KEY]: VALUE"
	$MessageArray = ($MessageObject.MessageIn -split '(\[.+\]:.+\n)', 0, "regexmatch") | foreach-object {if($_ -eq $null -or $_ -eq ''){$null} else {$_}}
	$arrayStart = if($null -eq $MessageArray[0]){1} else {0}

	# $MessageObject.General.MessageText
	$CleanMessage = if($null -eq $MessageArray[0]){""} else {(($MessageArray[$arrayStart].replace("-----",'')).replace("`n`n",'')).replace("`r",'')}
	$MessageObject.General.MessageText = $CleanMessage


	# Generate one object property in $MessageObject.General per key/value in $MessageArray
	$facts = @()
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

	$MessageObject.General.MessageProperties | Add-Member -NotePropertyName 'URL' -NotePropertyValue ((($MessageObject.MessageIn | Select-String -Pattern 'url:sqlsentry:\S*').Matches.Value).Replace('`r',''))
	$MessageObject.ConditionIn = $MessageObject.General.MessageProperties.Condition
	#Get Additional info about record from SS database
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
					and ObjectName = '$($MessageObject.ObjectNameIn)'
					and ConditionTypeName = '$($MessageObject.ConditionIn)'
			)
			select top 1 ID, CategoryName
			from act 
			where  ChainHead = 1 and NormalizedEventStartTime <= '$($MessageObject.General.MessageProperties."Timestamp (UTC)")'
			order by id desc"

			$extra = Invoke-DbaQuery -SqlInstance "$SSInstance" -Database SentryOne -SqlCredential $SSUtilityLogin -query $MessageObject.Misc.ExtrasQuery -ErrorAction Stop | select-object ID, CategoryName
			$MessageObject.General.HeadID = $extra.ID
			$MessageObject.General.CategoryName = $extra.CategoryName
			
		}
	

		if($ConditionType -eq 'Advisory'){
			$MessageObject.General.EventID = (($MessageObject.MessageIn | Select-String -Pattern '(url:sqlsentry:\S*(id=(?<ID>\d+)))').Matches.Groups | Where-Object -Property Name -eq 'ID').Value

			$MessageObject.Misc.DeleteQueueQuery = "
				delete 
				from Custom.SNow_Close_Queue
				where EventID = $($MessageObject.General.EventID)
			"
		}

		$MessageObject.General.EventID = ($MessageObject.General.EventID).replace(" ","")
	}
	catch{
		$MessageObject.Misc | Add-Member -NotePropertyName ExtrasError -NotePropertyValue $_.exception.Message
		$MessageObject.Misc.ExtrasQuery | out-file -FilePath "c:\sentryone\debug-query.txt"
		
		$extra | Out-File -FilePath "c:\sentryone\debug-extra.txt"
		$ObjectName | out-file -FilePath "c:\sentryone\debug-inputs.txt"
		$Condition | out-file -FilePath "c:\sentryone\debug-inputs.txt" -Append
		$ServerName | out-file -FilePath "c:\sentryone\debug-inputs.txt" -Append
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
		$MessageObject.ServiceNow.AlertSourceInstance = "$SSEnvironment"
		$MessageObject.ServiceNow.Severity = "0"
		
		# $MessageObject.ServiceNow.EventID
        # EventID is the Unique Key for the SN event record.  This must be unique per event from SS
        $eventID = switch ($ConditionType) {
            "Advisory" {$MessageObject.General.MessageProperties.URL}  #gets url from message if it exists
            "Legacy" {"$($MessageObject.ConditionIn)$($MessageObject.ObjectNameIn)$($MessageObject.General.HeadID)"}
            Default {"CouldNotGenerateIDFromAlert"}
        }
        $eventID = ("$eventID $(if($ConditionType -eq 'Advisory'){''} else{'Passive'})").Replace(" ","")
        $MessageObject.ServiceNow.EventID = $eventID
	}
	#endregion ServiceNow Object Properties

	$MessageObject
}

################################################################
#region Set Global Variables
################################################################
#############
#SentryOne
#############
$SSInstance = '<SQLSentry Repository Instance>'
$crypt = '76492d1116743f0423413b16050a5345MgB8AHUAbwArAEMAaQBrAHIAegByAFMARQBqADkAUABjAFcAdQBKAE8AVQBtAHcAPQA9AHwAYwA1ADgAZgA1ADgANQBhADYANgAyADcAYgAwAGYAOQAyAGEAMQBjAGEAMwBmAGYAZAAyADkAZQBhADcANQA3AGMAMwBkADQANgBjADIAMwA4ADIAZQAzADAAMQBhAGYAOAAzADIAMgBjADcAOAA2AGIAYgAwAGQAYwA2AGQAYQA='
[pscredential]$SSUtilityLogin = new-object System.Management.Automation.PSCredential ("SS_Script_Utility", (ConvertTo-SecureString -String $crypt -Key (1..16)))

#############
#ServiceNow
#############
$ServiceNow = $true #Internal var to maintain code equivalance with the unified alert script, which uses this as a parameter
$is_SN_live = $true #This internal flag lets us turn SN alerts on/off without changing calls in SS
$ServiceNowInstance = 'lds' #Use ldssand for the dev environment

[net.ServicePointmanager]::SecurityProtocol = "tls12, tls11, tls"

# API Creds.  User should be least privilige, with only the ability to post to the API.  Set up this way, we don't care about hardcoding credentials 
# Code assumes that all possible instances use the same creds.  If this is not the case, additional logic will be needed to differentiate them.
$SNuser = 'snc-sqlsentry'
$SNpass = ConvertTo-SecureString 'A@KvzpRgBB2q9G8hVy6&om86' -AsPlainText -Force 
#endregion Set Global Variables

#region Queries
# Query the SS repo to get list of all event IDs to be closed
$q1 = "declare @Buffer_Min int;
select @Buffer_Min = -5;
with 
	/* Anything that can be actively closed (has a url) */
	ac (ObjectTypeName, ObjectName, ID, Condition, Message, EndTime, RowNum, EventID, CategoryName) as (
		select
			--CategoryName, ConditionTypeName,
			ObjectTypeName
			, ObjectName
			, a.ID
			, a.ConditionTypeName
			, a.Message
			, a.NormalizedEventEndTime
			, ROW_NUMBER() over(partition by objecttypename, objectname, conditiontypename, NormalizedEventStartTime order by id desc) as rownum
			, x.EventID
			, isnull(a.CategoryName,'Advisory Conditions')
		from custom.SNow_Close_Queue as cq
			inner join vwObjectConditionActionHistory as a on cq.ActionID = a.ID
			inner join [custom].SNow_Last_Closed_Time as z on a.NormalizedEventEndTime >= dateadd(minute,@Buffer_Min,z.LastClearedEndTime) or a.NormalizedEventEndTime = '1753-01-01 00:00:00.000'
			inner join [custom].[SNow_Close_Queue] as x on a.ID = x.ActionID
		where ActionTypeName = 'Execute PowerShell'
			and ObjectTypeName in(
				'Blocking SQL' --Blocking Source; found in BlockChain
				, 'Top SQL' --Top SQL Source; found inPerformanceAnalysisTraceData
				, 'SQL Server' --Found in vwEventsLog
				, 'Windows Computer' --Found in vwEventsLog
				, 'Global' --Found in vwEventsLog
				)
			and message like '%url:sqlsentry:%id=%'
			and not ConditionTypeName = '_ServiceNow_Event_Sweeper'
	) --select * from ac
	,fin (ObjectTypeName, ObjectName, EventID, Condition, Category, FullUrl, ID, Message, EndTime) as (
		select 
			ObjectTypeName
			, ObjectName
			--, [EventID] = convert(bigint, RIGHT(SUBSTRING(message,PATINDEX('%url:sqlsentry%',message), charindex(char(13),message,PATINDEX('%url:sqlsentry%',message)) - PATINDEX('%url:sqlsentry%',message)),charindex('=',REVERSE(SUBSTRING(message,PATINDEX('%url:sqlsentry%',message), charindex(char(13),message,PATINDEX('%url:sqlsentry%',message)) - PATINDEX('%url:sqlsentry%',message))),0 )-1)) --Get the ID for the event from the URL
			, EventID
			, Condition
			, CategoryName
			, [FullURL] = SUBSTRING(message,PATINDEX('%url:sqlsentry%',message), charindex(char(13),message,PATINDEX('%url:sqlsentry%',message)) - PATINDEX('%url:sqlsentry%',message)) --get just the url from the message
			, ID
			, Message
			, EndTime
		from ac 
		where RowNum = 1
	)
	select * from fin
	--select * into #ac from fin;

/* Anything that must be passively closed (no URL)
The commented code below is necessary only if records are being created in ServiceNow which cannot be actively closed
and are not covered by ServiceNow auto-close rules.  Last mod to commented code was from a implementation in 2020 prior
to breaking changes in SQLSentry.  It will need to be revisited and modified to fit current SQLSentry practices before
implementation*/
/*;with

	a1 (ObjectTypeName, ObjectName, EventID, Condition, Category, FullUrl, ID, Message, EndTime, RowNum)	as (
		select 
			convert(nvarchar(200),ObjectTypeName)
			, ObjectName
			, -1
			, ConditionTypeName
			, isnull(a.CategoryName,'Advisory Conditions')
			, 'N/A'
			, ID
			, Message
			, NormalizedEventEndTime
			, ROW_NUMBER() over(partition by objecttypename, objectname, conditiontypename, NormalizedEventStartTime order by id desc) as rownum
		from vwObjectConditionActionHistory as a
			inner join [custom].SNow_Last_Closed_Time as z on a.NormalizedEventEndTime >= dateadd(minute,@Buffer_Min,z.LastClearedEndTime)
		where ActionTypeName = 'Execute PowerShell'
			and message not like '%url:sqlsentry:%id=%'
	),
	--ac as (select * from a where RowNum = 1),
	ev (ObjectTypeName, EventID, EndTime) as (
		--Blocking SQL
		select 
			'Blocking SQL' as ObjectTypeName,
			ID as EventID, 
			NormalizedEndTime as [EndTime]
		from BlockChain as z
			inner join [custom].SNow_Last_Closed_Time as c on z.NormalizedEndTime >= dateadd(minute,@Buffer_Min,c.LastClearedEndTime)

		union
		--Advisory Conditions (SQL Server, Windows Computer, Global, etc.)
		select 
			z.ObjectType as ObjectTypeName,
			ID as EventID, 
			z.NormalizedEndTimeUtc as [EndTime]
		from vwEventsLog as z
			inner join [custom].SNow_Last_Closed_Time as c on z.NormalizedEndTimeUTC >= dateadd(minute,@Buffer_Min,c.LastClearedEndTime)

		union
		--Top SQL
		select 
			'Top SQL' as ObjectTypeName,
			ID as EventID, 
			z.NormalizedEndTime as [EndTime]
		from PerformanceAnalysisTraceData as z
			inner join [custom].SNow_Last_Closed_Time as c on z.NormalizedEndTime >= dateadd(minute,@Buffer_Min,c.LastClearedEndTime)
	),
	fin as(
		select 
			ac.ObjectTypeName, ac.EventID, ac.Condition, ev.EndTime,
			ac.FullURL, ac.Message
		from #ac as ac
			inner join ev
				on ev.ObjectTypeName = ac.ObjectTypeName 
					and ev.EventID = ac.EventID

		union

		select ObjectTypeName, EventID, Condition, EndTime, FullURL, Message from a1 where RowNum = 1
	) --select * from a1
select *, 
	case
		when message like '%\[Connection\]%' escape '\' then 'Legacy'
		when message like '%\[Server Name\]%' escape '\' then 'New'
	end as AlertNodeType 
from fin;

drop table #ac
*/"
#endregion queries

$idList = @(Invoke-DbaQuery -SqlInstance $SSInstance -Database SentryOne -SqlCredential $SSUtilityLogin -ReadOnly -Query $q1 | Sort-Object -Property EndTime -Descending)
#| Where-Object ($_.NormalizedEndTimeUtc -ne "") 
$lastClosedDate = $idList[0].EndTime


foreach ($i in $idList) # Loop through results and send close signal to SN for each event.
{
	$AlertObject = create-alertobject -AlertRow $i
	
	$additional = @{
		"short_description" = "$($AlertObject.General.ShortDesc)"
		"name" = $AlertObject.ObjectNameIn
		"SSResponseRuleset" = $AlertObject.General.MessageProperties.'Response RuleSet'
		"portalURL" = "https://sqlsentry.ldschurch.org/"
	} | ConvertTo-Json

	$rawbody = @{
		#'additional_info' = "$($additional.replace('\','\\'))"
		'additional_info' = $additional
		'description' = "$($AlertObject.General.ShortDesc) `n`n Description= $($AlertObject.General.MessageText)`n`n Notes= $($alert_notes)"
		'event_class' = $AlertObject.ServiceNow.AlertSourceInstance
		'node' = $AlertObject.General.ServerName
		#'resource' = "$($alert_resource)"
		'severity' = 0 # hardcoded value to close alert
		'source' = $AlertObject.ServiceNow.AlertSource
		'type' = $AlertObject.ConditionIn
		'message_key' = $AlertObject.ServiceNow.EventID
	}
   
    $body = (ConvertTo-Json $rawbody)
    $body = '{"records":['+$body+']}'

    $parameters = @{
        "Uri"         = $AlertObject.ServiceNow.Uri
        "Headers"     = $AlertObject.ServiceNow.Headers
        "Method"      = 'POST'
        "Body"        = $body
        "ContentType" = $AlertObject.ServiceNow.ContentType
        "Credential"  = $AlertObject.ServiceNow.Cred
    }

    try{
        $response = $AlertObject.Output.ServiceNow = Invoke-RestMethod @parameters -ErrorAction Stop
        
		$out = Invoke-DbaQuery -SqlInstance "$SSInstance" -Database SentryOne -SqlCredential $SSUtilityLogin -query $AlertObject.Misc.DeleteQueueQuery -ErrorAction Stop
		$AlertObject.Output | Add-Member -NotePropertyName OpenQueue -NotePropertyValue $out
    } 
    catch{
        $_.Exception.Message
    }
}


	$q2 = "update [custom].SNow_Last_Closed_Time set LastClearedEndTime = '$($lastClosedDate.Month)/$($lastClosedDate.Day)/$($lastClosedDate.Year) $($lastClosedDate.Hour):$($lastClosedDate.Minute):$($lastClosedDate.Second):$($lastClosedDate.Millisecond)' --main close script"
	Invoke-DbaQuery -SqlInstance $SSInstance -Database SentryOne -SqlCredential $SSUtilityLogin -Query $q2




$tempbody | Out-File "c:\sentryone\clear_tempbodyout.txt"
$body | Out-File "c:\sentryone\clear_bodyout.txt"
$response | Out-File "c:\sentryone\clear_responseout.txt"
$idlist | Out-File "c:\sentryone\clear_data.txt"




