# Unified Alerting via Powershell for ServiceNow and Teams
I wrote the core of this integration a few years ago while with my previous employer, then brought it with me and updated it in my current position.  I hadn't really thought about making the code public until SQL PASS this year where a few people asked me what I did to integrate with ServiceNow.  There was enough interest that I figured I should write up something semi-official and get it out to the world in hopes that somebody will find it useful.  All code can be found at my [repo](https://github.com/Shashtsoh/SQLSentryStuff).  

## Introduction
SQLSentry has traditionally relied on email for alerting going out of the program. This is simple and effective, but also lacks flexibility - I really don't like the xml editor - and adds potentially undesired (depending on your exchange admin) load to the email systems.  ServiceNow *can* consume emails, but it also provides a robust API which can be leveraged for alerting.  Teams also provides an API for posting to a channel.  With APIs for both systems at my fingertips, all I needed to do is intercept the alert message and send it in.  SQLSentry provides token replacement for the message, alerting object, etc., which meant that I could capture those inside my script very easily.

To take advantage of these APIs, I use the Powershell action in SQLSentry run one of two custom powershell scripts.  
1. SQLSentry-UnifiedAlerting.ps1 - this is the unified alerting script; its job is to send alerts into ServiceNow, teams, etc.  
2. SQLSentry-ServiceNowAPI-Close.ps1 - this one is specific to ServiceNow; it's job is to close alerts.    

## Deployment

All integrations for SQLSentry are placed into the PowerShell script I've named "SQLSentry-UnifiedAlerting.ps1". In my environment, we chose to place the integrated alert script at C:\\SQLSentry\\ on each monitoring server. All PowerShell responses pointing to this script should be set to run from "Monitoring Server" in the condition/action settings. Distributing the script in this manner gives us resiliency in our environment, allowing alerts to go out even when one or more monitoring servers goes offline.

# Integrations
## ServiceNow

The integration with ServiceNow (SN) is comprised of two separate steps:

1. Open the alert
2. Close the alert (advisory conditions only)

Both utilize the event processing API in SN. The event processing subsystem in SN is designed to consume and take action on events from multiple sources. A single real-world event may generate and send one or more event messages to this API; if we set things up properly, all event messages for a given real-world event will be treated by SN as updates for a single event in SN.  

### Opening an alert

We need to call the unified alerting script via a powershell action.  The call for an advisory condition will look something like this:
```powershell
$params = @{
    <# Control Parameters #>
    "ConditionType" = "Advisory"	
    "isRepositoryQuery" = $false # Repository query conditions can be finicky; this triggers some extra logic to handle them.
    "DebugAlert" = $false
    
    <# ServiceNow Parameters #>
    "ServiceNow" = $true
    "ServiceNowInstance" = "<your SN instance name>" # If your servicenow url is myorg.servicenow.com, the value here should be "myorg"
    "Severity" = 2 # This is the ServiceNow event severity.  For opening alerts, use values from 1-5; 1 being highest priority
    
    <# Teams Parameters #>
    "Teams" = $false

    <# Email parameters #>
    "Email" = $false
    "EmailFrom" = '<somecustomemail>@<yourorg.com>'
    
    <# SQLSentry Message Tokens #>
    "MessageText" = "<%MessageText%>"
    "ServerName" = "<%ServerName%>"
    "ObjectName" = "<%ObjectName%>"
    "Condition" = "<%Condition%>"
}
& C:\SentryOne\S1_Unified_Alerts.ps1 @params

```

Calls for Legacy conditions (General, Failsafe, Audit) will be nearly identical, but use the value "Legacy" for the ConditionType parameter.  The script will take care of the rest.  

### Closing an alert
One of the requirements my organization gave me was that any tickets opened via alerts I sent should be able to 'auto-close'.  This meant that I needed a way to send a close signal to ServiceNow.  I soon discovered that closing alerts in ServiceNow is a bit trickier due to how SQLSentry handles conditions.  There are two main hurdles to overcome.
1. Advisory Conditions and Legacy Conditions play by very different rules inside of SQLSentry.
   * In short, while Advisory Conditions have a definitive start and end time, starting in 2021, Legacy Conditions do not.  All legacy conditions are currently treated as immediately closed as soon as they evaluate to true.
1. SQLSentry doesn't have the concept of sending an alert on event close.
   * The official solution to this issue is to create a second negating condition that detects when the condition is complete.  Unfortunately, ServiceNow relies on a provided alert ID to tie multiple messages for the same event together.  A new alert from a separate condition equates to a new alert IDs, making it very difficult to accurately tie a close alert to its corresponding open alert.

To clear these hurdles, I needed two ways to close tickets in ServiceNow.  

### Option 1 - Active/Positive Close
All Advisory Conditions in SQLSentry have a definite duration, with start and end times. The real trick was how to actively grab the close time for an event and send it into SN.  I chose to utilize two custom tables in the SQLSentry database.  
1) Custom.SNow_Close_Queue - When an Advisory Condition event is sent to ServiceNow, the unified alerting script inserts the internal eventID from SQLSentry into this table.  This gives us a running queue of events that SN thinks are open
2) Custom.SNow_Last_Closed_Time - This stores a single value indicating the last time a close signal was sent to ServiceNow.

Using these two tables, I then built an advisory condition that queries SQLSentry database for the count of events closed where:
1. The event ID is in the queue table
1. The closed timestamp for the event is after the timestamp stored in the custom table
1. The action for the event is PowerShell  

If the count is greater than zero, this advisory condition evaluates to true. I then assigned a PowerShell action to this condition which - upon evaluating to true - queries all event tables in SQLSentry for the details of these closed alerts and iterates through them, sending each into ServiceNow with a close signal.


### Option 2 - Passive Close
As much as I would love to be able to use the active close for legacy conditions, it is not currently possible.  Here I had to rely on functionality in ServiceNow.  ServiceNow uses event processing rules to determine what to do with new events; these rules are highly customizeable, and can be set to key off of multiple fields in an event to determine what to do.  After looking at the problem with my ServiceNow team, we decided to have ServiceNow close these alerts if SQLSentry did not send an update within a given amount of time.  We just needed a field we could reliably key off of to distinguish the passive-close events.  The best oene I could find was ResponseRuleset; it is included in every event message, and we have control in SQLSentry over what they're named.  Passively closed alerts in my system all use a response ruleset with "ServiceNow Passive Close" in the name.  I have configured a couple; one for alerts that should close if idle for 5 min, and one that will close if idle for an hour.  These rulesets are generally configured to take the assigned action every 1 min, meaning SN will get a new update for the event every minute.  

In ServiceNow, we then created rules for each of the SQLSentry rulesets that will close tickets with that ruleset if no new events are received for the specified time.  

_**Actions with these rulesets should only be used to send the events to ServiceNow. Using them to send notifications to Teams and/or EMail will result in a lot of unnecessary noise.**_


## Teams

The integration to MS Teams is a relatively straightforward API call. Within the teams channel, a new incoming webhook connector must be created. The URL of this webhook can then be used to send in the alerts. The script is currently hardcoded to use a single URL; this can be modified if multiple channels are desired.

To send alerts to your Teams channel; set the Teams parameter to True:
```powershell
$params = @{
    <# Control Parameters #>
    "ConditionType" = "Advisory"	
    "isRepositoryQuery" = $false # Repository query conditions can be finicky; this triggers some extra logic to handle them.
    "DebugAlert" = $false
    
    <# ServiceNow Parameters #>
    "ServiceNow" = $false
    "ServiceNowInstance" = "<your SN instance name>" # If your servicenow url is myorg.servicenow.com, the value here should be "myorg"
    "Severity" = 2 # This is the ServiceNow event severity.  For opening alerts, use values from 1-5; 1 being highest priority
    
    <# Teams Parameters #>
    "Teams" = $true

    <# Email parameters #>
    "Email" = $false
    "EmailFrom" = '<somecustomemail>@<yourorg.com>'
    
    <# SQLSentry Message Tokens #>
    "MessageText" = "<%MessageText%>"
    "ServerName" = "<%ServerName%>"
    "ObjectName" = "<%ObjectName%>"
    "Condition" = "<%Condition%>"
}
& C:\SentryOne\S1_Unified_Alerts.ps1 @params

```

I started by sending in the raw alert text, but quickly got complaints.  The text was too long, and formatting did not translate well.  I enlisted the help of a teammate to customize the fomatting using Adaptive Cards. (see [https://adaptivecards.io/](https://adaptivecards.io/) for more information). The formatting is ***much*** nicer now, and the only real complaint is that teams does not show any of the card content in pop-up alerts; I'm not sure if this is a hard limitation or a deficiency in our card.  Either way, the nice formatting is worth that small hassle in my mind.

## Email
Yes the script can send emails, too.  No, I have not actually used this feature since testing it.  It's there, but not the focus of the script.

# Conclusion
That covers the core functionality and deployment of my solution.  I am happy to do a post breaking down the code if there is sufficient interest.  Again, all code can be found at my [repo](https://github.com/Shashtsoh/SQLSentryStuff); contributions are welcome!