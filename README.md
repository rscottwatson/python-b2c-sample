# Python Web App and Python Web Api for Azure AD B2C
This solution uses consists of a simple Python web application and web API that can be used to experiment with [Azure AD B2C](https://docs.microsoft.com/en-us/azure/active-directory-b2c/).  Both components are built using the [Flask web framework](https://flask.palletsprojects.com/en/1.1.x/).  THe web app uses the [Microsoft Authentication Library (MSAL)](https://docs.microsoft.com/en-us/azure/active-directory/develop/msal-overview) to authenticate the user against Azure AD B2C.

## What problem does this solve?
Azure AD B2C provides a powerful solution to the business-to-consumer (B2C) identity problem.  The Python samples for Azure AD B2C demonstrate basic authentication, but do not demonstrate the more powerful features of the service such as step-up authentication and how Azure AD B2C can be used to secure access to an API.  This solution seeks to demonstrate those capabilities.

## The design
The solution consists of a web app front-end and a web API backend which emulates a financial services website interacting with a backend database exposed by a web API.  Both components are built using the Python Flask web framework.

Access to the front-end application is secured using Azure AD B2C.  The front-end provides the web interface for the user and does the following

* Displays a home page with the user's name pulled from the ID token
* Allows the user to test that the API is up by accessing a public endpoint of the API
* View the account information about the user pulled from the back-end API based on the user's email address pulled from the access token
* Modify user's beneficiary in the back-end API after successful MFA authentication which demonstrates the step-up authentication capability of Azure AD B2C
* View the claims within the user's ID token
* Edit the user's profile within Azure AD B2C
* Logout of the front end application

## Setup

Temporary holder


