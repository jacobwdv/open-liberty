-include= ~${workspace}/cnf/resources/bnd/feature.props
symbolicName=com.ibm.websphere.appserver.ltpa.ckds-1.0
visibility=public
singleton=true
IBM-ShortName: ltpa.ckds-1.0
IBM-Process-Types: server
Subsystem-Name: LTPA CKDS Hardware Crypto Support 1.0
-features=com.ibm.websphere.appserver.appSecurity-3.0
-bundles=com.ibm.ws.crypto.ltpakeyutil
kind=ga
edition=base
# Uncomment for production - restricts feature to z/OS only
#WLP-Platform: zos
WLP-InstantOn-Enabled: true