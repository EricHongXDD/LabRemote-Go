# 随安装程序分发新增内嵌组件的许可、版权与修改说明。
    File /oname=LICENSE.txt "..\..\..\LICENSE"
    File "..\..\..\THIRD_PARTY_NOTICES.md"
    SetOutPath "$INSTDIR\licenses\go-openvpn"
    File "..\..\..\third_party\go-openvpn\LICENSE"
    File "..\..\..\third_party\go-openvpn\LICENSE_USAGE_EXCEPTION"
    File "..\..\..\third_party\go-openvpn\LABREMOTE_CHANGES.md"
    SetOutPath "$INSTDIR\licenses\go-lzo"
    File /oname=LICENSE "..\..\..\third_party\licenses\go-lzo-LICENSE"
    SetOutPath "$INSTDIR\licenses\atrust"
    File "..\..\..\internal\atrust\protocol\LICENSE"
    File "..\..\..\internal\atrust\protocol\NOTICE"
    File "..\..\..\internal\atrust\protocol\MODIFICATIONS.md"
    SetOutPath $INSTDIR
