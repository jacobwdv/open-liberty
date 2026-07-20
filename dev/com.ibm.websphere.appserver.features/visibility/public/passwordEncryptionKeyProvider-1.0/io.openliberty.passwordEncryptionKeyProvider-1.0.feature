-include= ~${workspace}/cnf/resources/bnd/feature.props
symbolicName=io.openliberty.passwordEncryptionKeyProvider-1.0
WLP-DisableAllFeatures-OnConflict: false
visibility=public
singleton=true
IBM-ShortName: passwordEncryptionKeyProvider-1.0
IBM-SPI-Package: com.ibm.wsspi.security.crypto; type="ibm-spi"
Subsystem-Name: Password Encryption Key Provider 1.0
-features=com.ibm.websphere.appserver.bells-1.0
-jars=com.ibm.websphere.appserver.spi.passwordEncryptionKeyProvider; location:=dev/spi/ibm/
kind=ga
edition=core
WLP-InstantOn-Enabled: true
