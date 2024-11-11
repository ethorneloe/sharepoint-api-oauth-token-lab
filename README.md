# Overview
This repo provides a PowerShell implementation for testing API connectivity to SharePoint through both the Microsoft Graph API and the older Sharepoint REST API.  The goal is to enable learning and exploration around obtaining a bearer token for API access in PowerShell using either a client secret or JSON Web Token (JWT) with signed client-assertion.

# Scenarios covered
1. Accessing the Sharepoint REST API using a bearer token obtained with a JWT and also with a client secret.
2. As above but with the Microsoft Graph API.

# How to use the script
1. Add your required values in the `Configure Variables` section near the bottom of `sharepoint-api-oauth-token-lab.ps1`.
2. Run the script in a PowerShell environment.
3. Review the output to see the responses from the SharePoint and Graph APIs.

# Script requirements
- An app registration in Microsoft Entra ID with `client secret` and `certificate`.
- API permissions configured on the app registration, and SharePoint site permissions granted accordingly. In particular `Sites.Selected` configured as API permissions for both Microsoft Graph and Sharepoint is ideal, with access to the specific SharePoint site(s) configured for the app reg.
- Follow the guide below if you need to configure the above requirements.

# App Registration and Sharepoint Access Configuration Steps
## Azure App Registration Setup

### Register the Application
1. Navigate to App registrations in the Azure Portal.
1. Click on New registration.
1. Enter a name for your application (e.g., SharePointApp).
1. Supported account types: Choose `Accounts in this organizational directory only.`
1. Redirect URI: Leave it blank for server-to-server communication.
1. Click `Register`.

### Configure API Permissions
#### For Microsoft Graph API
1. From the main config page of your app registration in the Azure Portal, navigate to Manage, API Permissions.
2. Click on Add a permission.
3. Select Microsoft Graph.
4. Choose Application permissions.
5. Search for and select the required permissions (Ideally Sites.Selected rather than read to all SPO sites).
6. Click Add permissions.

#### Grant Admin Consent
Before continuing, if you do not have authority to grant these permissions, log a job with the service desk, or get in touch with the appropriate people to obtain permission to get this actioned.

1. Click on Grant admin consent for [Your Tenant].
1. Confirm by clicking Yes.

#### For SharePoint REST API
1. In the same fashion as before for Graph, click on `Add a permission`.
2. Search for SharePoint and select it.
3. Choose Application permissions and Select `Sites.Selected`.
4. Click `Add permissions`.

#### Grant Admin Consent
Before continuing, if you do not have authority to grant these permissions, log a job with the service desk, or get in touch with the appropriate people to obtain permission to get this actioned.
1. Click on Grant admin consent for [Your Tenant].
1. Confirm by clicking Yes.

### Add a Certificate to the App Registation
#### Generate a Certificate:
The self-signed powershell snippet is shown below. Ideally this would be a cert from an internal PKI for better maintenance and tracking. Change the details as required to suit your naming and cert store.
```powershell
$cert = New-SelfSignedCertificate -Subject "CN=SharePointApp" -KeyExportPolicy Exportable -CertStoreLocation "Cert:\CurrentUser\My"
```
 

Extract the Public Certificate:
Change the filename to suit and export.



Export-Certificate -Cert $cert -FilePath "C:\temp\SharePointApp.cer" | Out-Null
 

Upload the Public Certificate to App Registration:

In your app registration, select Certificates & secrets.

Click Upload certificate.

Select the .cer file you exported.

Click Add.

Configure Site Permissions
The Sites.Selected permission requires you to grant access to specific sites.  Below are the steps to grant this site level access using either PnP PowerShell or Graph REST API.

Using PnP PowerShell
Install PnP PowerShell Module (if not already installed):



Install-Module -Name PnP.PowerShell -Scope CurrentUser
 

Connect to SharePoint Admin Site:



Connect-PnPOnline -Url "https://YourTenantName-admin.sharepoint.com" -Interactive
 

Grant Access to the App Registration:
Be sure to choose the most appropriate permission level.  Set the appId and siteUrl as required.



$appId = "Your-Client-Id" 
$siteUrl = "https://YourTenantName.sharepoint.com/sites/YourSite" 
Grant-PnPAzureADAppSitePermission -AppId $appId -DisplayName "SharePointApp" -Site $siteUrl -Permissions "Read"
 

Verify Permissions:



Get-PnPAzureADAppSitePermission -Site $siteUrl
Using REST API
Go to the Graph Explorer Graph Explorer | Try Microsoft Graph APIs - Microsoft Graph

Sign in with the required credentials at the top right.

You will now have a token that can be used for the session.

Open image-20241105-221844.png
image-20241105-221844.png
 

Get the SiteID by running thisGET request
https://graph.microsoft.com/v1.0/sites?select=webUrl,Title,Id&$search="test*"

Open image-20241106-031607.png
image-20241106-031607.png
 
The results  should show the website you are looking for and its SiteID.

Open image-20241106-031753.png
image-20241106-031753.png
 

 We now need to make a POST to this URL.  Be sure to a.dd in your SiteID.



https://graph.microsoft.com/v1.0/sites/SiteID-From-Step-Above/permissions
 

Request Body (Add in your app reg clientId)



{
    "roles": [
        "permissions to assign"
    ],
    "grantedToIdentities": [
        {
            "application": {
                "id": "clientId of your app reg",
                "displayName": "Your display name"
            }
        }
    ]
}
 

The response should show the permissions where added.  Now the app reg can access Sharepoint with the Sites.Selected API permission.

Open image-20241106-032408.png
image-20241106-032408.png
 

Connect to APIs
Use the script included here to connect to the APIs now that the prerequisites have been set up.

Additional Notes
Using Postman
There are some public Postman collections for connecting to Sharepoint and Graph.  Make sure when using these that you are getting tokens using the correct audience in the JWT payload.  Also make sure to avoid any collections referring to https://accounts.accesscontrol.windows.net as this is a legacy endpoint for Microsoft Azure Access Control Service (ACS) which has been retired.

SharePoint Add-Ins and Azure ACS retirement FAQ

 

References and Relevant Links
 

Getting an App Only access token for SharePoint REST APIs - Martin Loitzl's Blog 

Sites.Selected Permissions what is it, and how do I use it 

Installing PnP PowerShell | PnP PowerShell 

SharePoint Add-Ins and Azure ACS retirement FAQ

Graph Explorer | Try Microsoft Graph APIs - Microsoft Graph

Working with SharePoint sites in Microsoft Graph - Microsoft Graph v1.0 

