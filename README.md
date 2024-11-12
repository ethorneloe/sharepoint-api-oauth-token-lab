# Overview
This repo provides a PowerShell implementation for testing API connectivity to SharePoint through both the Microsoft Graph API and the older Sharepoint REST API.  The goal is to enable learning and exploration around obtaining a bearer token for API access in PowerShell using either a client secret or JSON Web Token (JWT) with signed client-assertion.

# Scenarios Covered
1. Accessing the Sharepoint REST API using a bearer token obtained with a JWT and also with a client secret.
2. As above but with the Microsoft Graph API.

# How to Use the Script
1. Add your required values in the `Configure Variables` section near the bottom of `sharepoint-api-oauth-token-lab.ps1`.
2. Run the script in a PowerShell environment.
3. Review the output to see the responses from the SharePoint and Graph APIs.

# Script Requirements
- An app registration in Microsoft Entra ID with `client secret` and `certificate`.
- API permissions configured on the app registration, and SharePoint site permissions granted accordingly. In particular `Sites.Selected` configured as API permissions for both Microsoft Graph and Sharepoint is ideal, with access to the specific SharePoint site(s) configured for the app reg.
- Follow the guide below if you need to configure the above requirements.

# App Registration and Sharepoint Access Configuration Steps
## Azure App Registration Setup

### Register the Application
1. Navigate to App registrations in the Azure Portal.

   ![image](https://github.com/user-attachments/assets/7bf182af-9f27-4df5-aebb-a628d6e1199d)
1. Click on `New registration`.

   ![image](https://github.com/user-attachments/assets/cc3157b8-9ce5-4570-ab18-8f93ea072f51)
1. Enter a name for your application (e.g., sharepoint-api-testing).  The rest of the details can be left as shown.

   ![image](https://github.com/user-attachments/assets/8e478524-48fb-47d6-9509-ed446fda696b)
   
1. Click `Register`.
   ![image](https://github.com/user-attachments/assets/662db734-783d-4e69-84ea-c8fd8f99580c)

### Configure API Permissions
#### For Microsoft Graph API
1. From the main config page of your app registration in the Azure Portal, navigate to `Manage, API Permissions`.  Click on `Add a permission`.

   ![image](https://github.com/user-attachments/assets/fdc733e3-145f-4334-bc08-1b647a04ea3b)

   
2. Select `Microsoft Graph`.

   ![image](https://github.com/user-attachments/assets/383841b3-00ff-4e06-9319-99f3eebfa2d9)

3. Choose `Application permissions` and select the `Sites.Selected` permission in the `Sites` section.  If you need other permissions, select as required.
   
   ![image](https://github.com/user-attachments/assets/41a8bd6f-8768-4160-9f2e-6a9646930e2b)


4. Click `Add permissions`.
   
   ![image](https://github.com/user-attachments/assets/7e925230-24f2-488c-a236-3ae25f0b1860)


#### Grant Admin Consent
Before continuing, if you do not have authority to grant these permissions, log a job with your service desk, or get in touch with the appropriate people to obtain permission to get this actioned.

5. Click on `Grant admin consent for [Your Tenant]`.

   ![image](https://github.com/user-attachments/assets/2b4ce311-4aae-49d1-90fe-84782504a49f)

6. Confirm by clicking `Yes`.

   ![image](https://github.com/user-attachments/assets/c1ce186c-647f-4ada-aba7-c42b291d7262)

7. You should now see your granted API permissions.

   ![image](https://github.com/user-attachments/assets/2eb18e0c-7569-4c8d-9d3a-ac81a387f938)


#### For SharePoint REST API
1. Repeat the steps above but instead of selecting Microsoft Graph, scroll down a bit and choose SharePoint.

   ![image](https://github.com/user-attachments/assets/94ce702c-48ac-49f8-8239-d97c59fe1eb0)

2. Choose the `Sites.Selected` permission. Add other permissions if needed.

   ![image](https://github.com/user-attachments/assets/2739e31e-0001-4ded-ab0e-c79e57807cc7)

3. Click `Add permissions`.
   
   ![image](https://github.com/user-attachments/assets/7e925230-24f2-488c-a236-3ae25f0b1860)

4. Once again, click on `Grant admin consent for [Your Tenant]`.

   ![image](https://github.com/user-attachments/assets/2b4ce311-4aae-49d1-90fe-84782504a49f)

5. Confirm by clicking `Yes`.

   ![image](https://github.com/user-attachments/assets/c1ce186c-647f-4ada-aba7-c42b291d7262)

6. You should now see your granted API permissions.

   ![image](https://github.com/user-attachments/assets/f53e6cdb-8952-4b2a-9d98-5126d661a681)



### Add a Certificate to the App Registation
1. Generate a certificate. Ideally this would be a cert from an internal PKI for better maintenance and tracking if you need more permanent API access. For testing, this can be done quickly using PowerShell to create a self-signed cert as shown below.
   ```powershell
   $cert = New-SelfSignedCertificate -Subject "CN=SharePointApp" -CertStoreLocation "Cert:\CurrentUser\My"
   ```
2. Extract the public certificate. Change the filename to suit and export.
   ```powershell
   Export-Certificate -Cert $cert -FilePath "C:\temp\SharePointApp.cer" | Out-Null
   ```
3. In your app registration, select `Certificates & secrets`. Click on `Upload certificate`.

   ![image](https://github.com/user-attachments/assets/472e1cad-0ffc-48f9-84f3-1db4a262a16c)

4. Select the .cer file you exported. Click `Add` at the bottom.

   ![image](https://github.com/user-attachments/assets/165deeaf-5504-4d9b-9e43-873ef3b7ab25)

   ![image](https://github.com/user-attachments/assets/688db092-bd77-4e69-afd9-13214f795439)


## Configure Site Permissions
The `Sites.Selected` API permission requires you to grant access to specific SharePoint sites.  Below are the steps to grant this site level access using either PnP PowerShell or Graph REST API.

### Using PnP PowerShell
If you do not want to install this module and create the app registration required for this method to work, you can skip to the Graph REST API method below.
1. Install PnP PowerShell Module.  Change the scope if required.
   ```powershell
   Install-Module -Name PnP.PowerShell -Scope CurrentUser
   ```
 
2. Create an app reg for interactive login.  If you want to customise this app reg for PnP PowerShell, check out the documentation below, otherwise run the command below with your required values.

   *For more info on the app reg needed for PnP PowerShell:*
   <br />
   https://pnp.github.io/powershell/articles/registerapplication.html

   *Run this if happy with defaults for the PnP PowerShell app reg permissions:*
   ```powershell
   Register-PnPEntraIDAppForInteractiveLogin -ApplicationName "PnP Interactive" -Tenant <yourtenant>.onmicrosoft.com -Interactive
   ```
   You should recieve a success message that your app reg was created successfully, and the ClientId (AppId) will be in the output.  If not check your Azure access levels.

4. Connect to your tenant with PnP PowerShell.
   ```powershell
   Connect-PnPOnline -Url <your-tenant-name>.sharepoint.com -Interactive -ClientId <new-client-Id>
   ```
 
3. Grant Access to the App Registration. Be sure to choose the most appropriate permission level.  Set `$appId` and `$siteUrl` as required.
   ```powershell
   $appId = "your-client-id" 
   $siteUrl = "https://<your-tenant-name>.sharepoint.com/sites/<your-site-name>" 
   Grant-PnPAzureADAppSitePermission -AppId $appId -DisplayName "SharePointApp" -Site $siteUrl -Permissions "Read"
   ```

   The output should show the new permissions for your app reg, but if you want to confirm use the command below.
   ```powershell
   Get-PnPAzureADAppSitePermission -Site $siteUrl
   ```
### Using REST API
1. Head to the Graph Explorer here: https://developer.microsoft.com/en-us/graph/graph-explorer

2. Sign in with the required credentials at the top right.
   
   ![image](https://github.com/user-attachments/assets/30f1fe5a-6f10-4646-9460-e104a3e6778c)


4. You will now have a token that can be used for the session.  You can modify the permissions in the `Modify Permissions` section here if needed.

   ![image](https://github.com/user-attachments/assets/9466c864-f09e-4d50-a7f1-d9548f6a9ce1)


5. Change the search section of this URL below to suit the name of your site.

   ```
   https://graph.microsoft.com/v1.0/sites?select=webUrl,Title,Id&$search="test*"`
   ```

6. Paste the amended link into your Graph session and make sure the request type is set to `GET` like so.

   ![image](https://github.com/user-attachments/assets/3a2b04a1-1f1d-471d-9dca-7314a02e56c8)

6. Click on `Run Query`.
   
   ![image](https://github.com/user-attachments/assets/8d4f026f-218d-4374-a562-ffd6340d0764)


   The results should look something like this.

   ![image](https://github.com/user-attachments/assets/e2325cec-7ebd-4cd9-91d3-193153130b6e)

6. Using the `id` of your site in the results above, amend the URL below which will be used for setting the permissions for the app reg.

   ```
   https://graph.microsoft.com/v1.0/sites/<site-id-from-step-above>/permissions
   ```

7.  Now add this amended URL to your Graph Explorer session and set the method to `POST`.  Also add in the following to the request body. Make sure to copy in your app id of the app registration that was assigned the API permissions earlier in the guide.

   ```json
   {
       "roles": [
           "permissions to assign"
       ],
       "grantedToIdentities": [
           {
               "application": {
                   "id": "<AppId of your app reg>",
                   "displayName": "Your display name"
               }
           }
       ]
   }
   ```

  Your Graph Explorer session should look something like this.

  ![image](https://github.com/user-attachments/assets/46f810f5-26ed-48c1-b697-644d70e7920b)

8. Click on `Run Query`.
   
   ![image](https://github.com/user-attachments/assets/8d4f026f-218d-4374-a562-ffd6340d0764)

The response should be similar to the image below. If so the permissions have now been assigned.

![image](https://github.com/user-attachments/assets/1fb90659-32f5-429e-9bad-e25afa30297d)

 
# Connect to APIs

Use the script included in this repo to connect to the APIs now that the prerequisites have been set up. Further instructions can be found in the comments section of the script.

# Additional Notes
## Using Postman

There are some public Postman collections for connecting to Sharepoint and Graph.  Make sure when using these that you are getting tokens using the correct audience in the JWT payload.  Also make sure to avoid any collections referring to `https://accounts.accesscontrol.windows.net` as this is a legacy endpoint for Microsoft Azure Access Control Service (ACS) which has been retired.

# References and Relevant Links
  
- *Getting an App Only access token for SharePoint REST APIs - Martin Loitzl's Blog*
  
  https://blog.loitzl.com/posts/getting-an-app-only-access-token-for-sharepoint-rest-apis/

- *Sites.Selected Permissions what is it, and how do I use it*

  https://blog.dan-toft.dk/2022/12/sites-selected-permissions/

- *Installing PnP PowerShell | PnP PowerShell*

  https://pnp.github.io/powershell/articles/installation.html

- *SharePoint Add-Ins and Azure ACS retirement FAQ*

  https://learn.microsoft.com/en-us/sharepoint/dev/sp-add-ins/add-ins-and-azure-acs-retirements-faq

- *Graph Explorer | Try Microsoft Graph APIs - Microsoft Graph*

  https://developer.microsoft.com/en-us/graph/graph-explorer

- *Working with SharePoint sites in Microsoft Graph - Microsoft Graph v1.0*

  https://learn.microsoft.com/en-us/graph/api/resources/sharepoint?view=graph-rest-1.0

- *Register an Entra ID Application to use PnP PowerShell*

  https://pnp.github.io/powershell/articles/registerapplication.html

