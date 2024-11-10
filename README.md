# Overview
This repo provides a PowerShell implementation for testing API connectivity to SharePoint through both the Microsoft Graph API and the older Sharepoint REST API.
This could be done with Graph PowerShell modules or PnP PowerShell, however, for learning and troubleshooting purposes it is also useful to achieve this without those layers of abstraction to better understand the steps of the API authentication process.

## Scenarios covered
1. Accessing the Sharepoint REST API using a bearer token obtained with a JSON Web Token (JWT) and also with a client secret.
2. As above but with the Microsoft Graph API.

## Helper functions are used to:
- Generate a JWT with a specified header and payload.
- Retrieve a bearer token using a client secret or JWT with signed client assertion.
- Retrieve data from an API endpoint using a bearer token.

# How to use the script
1. Add your required values in the "Configure Variables" section near the bottom.
2. Run the script in a PowerShell environment.
3. Review the output to see the responses from the SharePoint and Graph APIs.

# Requirements
- A `Microsoft Entra ID` tenant with access to create an `app registration` with `client secret` and `certificate`.
- Ensure that the necessary API permissions are configured on the app registration, and any SharePoint site permissions have been granted accordingly. In particular `Sites.Selected` configured as API permissions for both `Microsoft Graph` and `Sharepoint` is ideal, with access to the required SharePoint sites configured for the app reg.

# Full Guide


