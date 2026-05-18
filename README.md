# SIEM-Honeypot-lab-Azure-Sentinel






IN DRAFT YET!!!!!!!!!!!!!!!




Step 1: Azure account creatinon







Step 4
Click on the workspace honeypot-law
Settings | Defender plans
Foundational CSPM (Cloud Security Posture Management): ON (Defaulted)
Servers: ON

Click Save


Step 6 : Setup Microsoft Sentinel
Look for "Microsoft Sentinel"
Hit Create Microsoft Sentinel
Choose the correct resource group name (honeypot-vm_group)
Choose Log Analytics Workspace name (honeypot-law)
click review + create
and then hit create again
wait a few seconds for deployment to complete
Go back to the main "Microsoft Sentinel" page and it should appear there.




make sure vm is on while setting up the DCR rule
VM was added to the DCR while it was deallocated/off — try removing the VM from the DCR resources, making sure the VM is fully Running, then re-adding it

after setting up the vm you must add a monitoring agent to collect the data and send to the DRC
search for Monitor at the top, then under settings click on data colection rules
then click on the existing dcr
18= Go to log analytics workspaces, select, select honeypot-law, click on settings and then table, and then create a new table
for the data extracted from the API

20= Fill in such details according to the table previously created. and then click on next
21= On the host, create a file on the notepad, and past the exact content in it:

[
  {
    "TimeGenerated": "2026-05-17T12:00:00Z",
    "RawData": "latitude:47.91542,longitude:-120.60306,destinationhost:samplehost,username:fakeuser,sourcehost:24.16.97.222,state:Washington,country:United States,label:United States - 24.16.97.222,timestamp:2021-10-26 03:28:29"
  }
]

Click File -> Save As...

Change the Save as type dropdown from Text Documents (*.txt) to All Files (*.*).

Name the file jason_sample.json (for example) and save it to your desktop.
Upload the file 

click on next and then create
21ss

Now that Azure knows the FAILED_RDP_WITH_GEO_CL table officially exists in the database, we link it to the VM's file directory:

Navigate to Data Collection Rules -> Click on honeypot-dcr.
then click on Configuration -> Data sources -> + Add
ss22
Set Data Source Type to Custom Text Logs.

File Pattern: C:\ProgramData\failed_rdp.log

Table Name: Select FAILED_RDP_WITH_GEO_CL from the dropdown menu (it will now appear smoothly without errors!).

Record Delimiter: Set this to End of line.

Transform: Type source into the box.

Go to the Destination tab, click + Add destinations, select honeypot-law workspace, and hit Apply

ss23

Step 10, Query and extract custom fileds from logs
Search for Log Analytics Workspaces
Navigate to the newly established workspace (honeypot-law) 
Click on Logs
We then can run a query and extract the different data filtering by different fields such as latitude, longitude, destinationhost, etc.
On the Query panel click on "Choose working mode" and select KQL and thne paste the following script in the text box:
FAILED_RDP_WITH_GEO_CL 
| extend username = extract(@"username:([^,]+)", 1, RawData),
         timestamp = extract(@"timestamp:([^,]+)", 1, RawData),
         latitude = extract(@"latitude:([^,]+)", 1, RawData),
         longitude = extract(@"longitude:([^,]+)", 1, RawData),
         sourcehost = extract(@"sourcehost:([^,]+)", 1, RawData),
         state = extract(@"state:([^,]+)", 1, RawData),
         label = extract(@"label:([^,]+)", 1, RawData),
         destination = extract(@"destinationhost:([^,]+)", 1, RawData),
         country = extract(@"country:([^,]+)", 1, RawData)
| where destination != "samplehost"
| where sourcehost != ""
| summarize event_count=count() by timestamp, label, country, state, sourcehost, username, destination, longitude, latitude, 

and then click on run
if nothing shows up clear the terminal and type:
Heartbeat
| where Computer == "honeypot-vm"
| order by TimeGenerated desc
| take 5

If nothing shows up again the VM was added to the DCR while it was deallocated/off — try removing the VM from the DCR resources, making sure the VM is fully Running, then re-add it and wait 10-15 min.

then run the previous command again:
Heartbeat
| where Computer == "honeypot-vm"
| order by TimeGenerated desc
| take 5

If that returns results, the pipeline is working
ss24

next run 
FAILED_RDP_WITH_GEO_CL
| count

 If it returns a number greater than 0 it means the data is flowing and we can run the full extraction query
 ss25

 then run
 FAILED_RDP_WITH_GEO_CL 
| extend username = extract(@"username:([^,]+)", 1, RawData),
         timestamp = extract(@"timestamp:([^,]+)", 1, RawData),
         latitude = extract(@"latitude:([^,]+)", 1, RawData),
         longitude = extract(@"longitude:([^,]+)", 1, RawData),
         sourcehost = extract(@"sourcehost:([^,]+)", 1, RawData),
         state = extract(@"state:([^,]+)", 1, RawData),
         label = extract(@"label:([^,]+)", 1, RawData),
         destination = extract(@"destinationhost:([^,]+)", 1, RawData),
         country = extract(@"country:([^,]+)", 1, RawData)
| where destination != "samplehost"
| where sourcehost != ""
| summarize event_count=count() by timestamp, label, country, state, sourcehost, username, destination, longitude, latitude

and you should see logs underneath the terminal
ss26


step 11, World Map Attack
Search for Microsoft Defender -> General -> Workbooks
and then click on + New
ss 27

Click Add->Add query
ss28

After clicking Add query, look immediately above the big empty text box where you type code. You will see a row of configuration dropdowns. Change them to match this exactly:

Resource type: Change this dropdown to Log Analytics.

Log Analytics Workspace: Click load all subscriptions and select your specific honeypot workspace (honeypot-law).
ss29

Paste and Configure Your Query
Now that the panel is pointing directly into your honeypot database, paste your extraction script into the main code window:
FAILED_RDP_WITH_GEO_CL 
| extend username = extract(@"username:([^,]+)", 1, RawData),
         timestamp = extract(@"timestamp:([^,]+)", 1, RawData),
         latitude = extract(@"latitude:([^,]+)", 1, RawData),
         longitude = extract(@"longitude:([^,]+)", 1, RawData),
         sourcehost = extract(@"sourcehost:([^,]+)", 1, RawData),
         state = extract(@"state:([^,]+)", 1, RawData),
         label = extract(@"label:([^,]+)", 1, RawData),
         destination = extract(@"destinationhost:([^,]+)", 1, RawData),
         country = extract(@"country:([^,]+)", 1, RawData)
| where destination != "samplehost"
| where sourcehost != ""
| summarize event_count=count() by timestamp, label, country, state, sourcehost, username, destination, longitude, latitude

ss30

then click on visualization drop-down box at the type and select Map
The map settings panel will open on the right side of the screen. Map the columns precisely to your extracted data:

Layout Settings
Location info using: Latitude/Longitude
Latitude: latitude
Longitude: longitude
Size by: event_count

Color Settings

Coloring Type: Heatmap
Color by: event_count
Aggregation for color: Sum of Values
Color palette: Green to Red

Metric Settings

Metric Label: label
Metric Value: event_count

Click Apply button and Save and Close

Click Apply at the bottom of the map panel, and hit Save and Close.
click Done Editing on the bottom of the query block
Then at the very top of the workbook page click on the floppy disk icon (save) to save the global attack map.
then on the pop-up window select the correct subscription, the correct resource group and location of the vm, and then save as, and it will automaticlaly save
the paremeters, then next click on Done Editing at the top, and on the floppy disk again and it will be saved
ss31
Keep refreshing the map to show more inbound failed RDP attacks

Event Viewer showcasing failed RDP logon efforts. Event ID: 4625
SS32

Data processing from a custom Powershell script using a third party API (ipgeolocation.io)
ss33









