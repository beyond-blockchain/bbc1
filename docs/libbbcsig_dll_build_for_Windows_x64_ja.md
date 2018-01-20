libbbcsig の 64bit Windows DLL ビルドについて
=========
ここでは、libbbcsig を 64bit Windows DLL にビルドする方法について記載する。
libbbcsig は内部で OpenSSL の関数を使用しているため、まず、OpenSSL を Windows 向けにビルドする必要がある。

## OpenSSL のビルド

### ビルド環境の構築

以下のソフトウェアが必要になる。インストールを行う。

* [Visual Studio Community 2017](https://www.microsoft.com/ja-jp/dev/products/community.aspx)
* [ActiveParl](https://www.activestate.com/activeperl)

### OpenSSL ソースダウンロード & ビルド

[https://www.openssl.org/](https://www.openssl.org/) からソースをダウンロードする。

※ 以下、 1.0.2n の場合について記載する。

ソースの展開ディレクトリに移動し、以下のコマンドを実行する。

`cd <<ソースの展開ディレクトリ>>\openssl-1.0.2n`

`perl Configure no-asm --prefix=..\x64 VC-WIN64A`

`ms\do_win64a.bat`

`nmake -f ms\nt.mak clean`

`nmake -f ms\nt.mak install`

※ **nt.mak** を指定し、スタティックライブラリにすること。
※ `..\x64\lib` ディレクトリに、libeay32.lib と ssleay32.lib ができれば OK

## libbbcsig のビルド

### libbbcsig の Visual Studio プロジェクト生成

Visual Studio で空のプロジェクトを新規作成する。(名称: libbbcsig)

`bbc1/common/libbbcsig` にある以下のファイルをプロジェクトに追加する。

* libbbcsig.h
* libbbcsig.c
* dllmain.c
* libbbcsig.def

### libbbcsig プロジェクトの設定

プロジェクトのプロパティを以下のように設定する。

|項目|設定値|
|:-:|:-:|
|プラットフォーム| x64|
|構成の種類|dll|
|追加のインクルードディレクトリ|<<ソースの展開ディレクトリ>>\x64\include|
|追加のインクルードディレクトリ|<<ソースの展開ディレクトリ>>\openssl-1.0.2n|
|ランタイムライブラリ|/MT|
|追加の依存ファイル|<<ソースの展開ディレクトリ>>\x64\lib\libeay32.lib|
|追加の依存ファイル|<<ソースの展開ディレクトリ>>\x64\lib\ssleay32.lib|
|モジュール定義ファイル|libbbcsig.def|

### ビルド

ビルドを行い、`x64\Debug` または `x64\Release` ディレクトリに libbbcsig.dll が出来ることを確認する。
