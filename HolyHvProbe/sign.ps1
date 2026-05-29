$cert = New-SelfSignedCertificate -Subject "CN=HolyTest" -Type CodeSigningCert -CertStoreLocation "Cert:\CurrentUser\My"
$signtool = "C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x64\signtool.exe"
& $signtool sign /v /s My /n "HolyTest" /fd sha256 "HolyHvProbe.sys"
