-include= ~${workspace}/cnf/resources/bnd/feature.props
symbolicName=io.openliberty.passwordEncryptionKeyProvider-1.0
WLP-DisableAllFeatures-OnConflict: false
visibility=public
singleton=true
IBM-ShortName: passwordEncryptionKeyProvider-1.0
IBM-SPI-Package: com.ibm.wsspi.security.crypto; type="ibm-spi"
Subsystem-Name: Password Encryption Key Provider 1.0
-features=com.ibm.websphere.appserver.bells-1.0, \
  com.ibm.websphere.appserver.passwordUtilities-1.0; ibm.tolerates:="1.1"
-bundles=com.ibm.ws.crypto.passwordutil
-jars=com.ibm.websphere.appserver.spi.passwordEncryptionKeyProvider; location:=dev/spi/ibm/
kind=ga
edition=core
WLP-InstantOn-Enabled: true
