murl
=====

mapping url

usage
------

```sh
$ murl https://www.google.com
```

```console
[302 Found] <172.217.26.4> https://www.google.com [text/html; charset=UTF-8] => 156978b9bba5e8ceb99474a4cd27a86d746aa3ab44e9f3d36d98b49eabf45bbe
  [200 OK] <172.217.31.131> https://www.google.co.jp/?gfe_rd=cr&dcr=0&ei=_DxaWqyyLIzf8AfvhqjYAw [text/html; charset=Shift_JIS] => 69ba82791caa2d0ab904738f01e79b527a9d72565fe4fff1d83c317a2fc587c8
```

### optional

* show virustotal result of url / content if VirusTotal API Key is specified.
* save contents into specified directory.

```console
$ murl -c local_dir -key $VTAPIKEY http://xxxxxxxxx.com/xxx.exe
[200 OK] <XXX.XXX.XXX.XXX> http://xxxxxxxxx.com/xxx.exe [VT: 5] [application/x-msdos-program] => <sha256> [VT: 38]
```

setup
------

```sh
go get -u github.com/0x75960/murl
```