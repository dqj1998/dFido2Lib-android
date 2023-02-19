# dFido2Lib-andriod
A FIDO2 native framework for Android.  
FIDO2/WebAuthn heavily depends on browsers' implementation. A native lib is significantly usable in providing stable and customizable user experiences.

Support Android 6(API 23)+

# Target of this project
1. a Modern project 

  * Modern Kotlin runBlocking/async mechanism rather than embedded callbacks. 
  * Support the latest FIDO spec

2. Use OS native lib as many as possible

3. Keep the external APIs as simple as possible and speak the programers' language

4. Keep source code structure as simple as possible

# Compatible FIDO2 servers 
* fido2-node (https://github.com/dqj1998/fido2-node.git) 

* LINE FIDO2 server (https://github.com/line/line-fido2-server.git).  
** Does not support real non-resident credentials
** Requires cookies managemant of client side to manage sessions
 
# Extension features

## Multiple rps
One domain can support multiple RPs by set rp.id. has to work with fido2-node server.

## Enterprise authenticator
Support aaguid checking for enterprise attestation.
1. Register enterpise rpids and aaguids in env file of fido2-node server by ENTERPRISE_RPs and ENTERPRISE_AAGUIDs
2. Call setPlatformAuthenticatorAAGUID and addEnterpriseRPIds on SDK side

## Rooted devices check

# Thanks
* https://github.com/lyokato/WebAuthnKit-Android.git

# Contact
* d@dqj.work
