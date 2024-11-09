# Overview
This repo contains a `PowerShell` implementation of connection testing to `SharePoint` through both the `Microsoft Graph API` and the `Sharepoint REST API`.  It was designed for learning and testing API connectivity.

### Four scenarios are covered:
1. Accessing the `Sharepoint REST API` using a bearer token obtained with a `JWT`.
2. Accessing the `Sharepoint REST API` using a bearer token obtained with a `client secret` (fails by design).
3. Accessing the `Microsoft Graph API` using a bearer token obtained with a `JWT`.
4. Accessing the `Microsoft Graph API` using a bearer token obtained with a `client secret`.

### Helper functions are used to:
- Convert input to a Base64Url-safe encoded string.
- Generate a JSON Web Token (JWT) with a specified header and payload.
- Retrieve a bearer token from a token endpoint using `client secret` or `certificate-based` authentication.
- Retrieve data from a specified REST API endpoint using a bearer token.

# How to use this script
1. Replace the placeholder values in the "Configure Variables" section at the bottom with your required values.
2. Run the script in a PowerShell environment.
3. Review the output to see the responses from the SharePoint and Graph APIs.

# Requirements
- A `Microsoft Entra ID` tenant with access to create an `app registration` with `client secret` and `certificate`.
- Ensure that the necessary API permissions are configured on the app registration, and any SharePoint site permissions have been granted accordingly. In particular `Sites.Selected` configured as API permissions for both `Microsoft Graph` and `Sharepoint` is ideal, with access to the required SharePoint sites configured for the app reg.
