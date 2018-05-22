# BBc-1 Core チュートリアル: インストールガイド

<!---
contributors:
* ks91
* oopth
* kichinosukey
* houeda
--->

## 1. はじめに
BBc-1 Core では、記録の存在を証明するとともに、権限をもつ本人であることをデジタル署名で証明可能な場合に限り、その記録を更新することができます。

このチュートリアルでは、以下のことを説明しています。
* BBc-1 Core のインストールと起動

#### 誰にとって有益か
* BBc-1 Core を初めて動かして試してみたい方

## 2. 前準備
以下の説明では bash の利用を前提とします。

### 2-1. 前提となる環境
* Python
  * python 3.5.0 以降 (3.6.0以降推奨)
  * pipenv を使用できます (README を参照ください)
* macOS の場合 (Homebrew の使用を前提として説明します)
  ```
  $ brew install libtool automake pkg-config libffi autoconf openssl
  ```

* Linux の場合 (Ubuntu 16.04 LTS の使用を前提として説明します)
  ```
  $ sudo apt install -y git tzdata openssh-server libffi-dev net-tools autoconf automake libtool libssl-dev pkg-config make
  ```

* Windows 10 の場合 (Linux サブシステムの使用を前提とします)
Linux サブシステムのインストールはこちらを参照してください。
  * https://qiita.com/yukio_tokuyoshi/items/042546812c663ceeccf3
  * すでにインストールされているサブシステムをリセットする場合は、コマンドプロンプト (または Windows PowerShell) から以下を実行し、
    ```
    C:> lxrun /uninstall /full
    ```
    さらに以下を実行してください (エラーが出る場合もありますが、その場合は Windows を再起動してから試してみてください)。
    ```
    C:> lxrun /install
    ```
  次のコマンドで bash を起動できます (cd コマンドで Linux ユーザのホームディレクトリに移動してください)。
  ```
  C:> bash
  $ cd
  ```
  Ubuntu 16.04 LTS がインストールされていますので、以降は Linux の方法に従ってください。

* geth (Ethereum クライアント) と solidity (Ethereum のスマートコントラクトのプログラミング言語コンパイラ) についてはこのチュートリアルでは使用しません。レッジャーサブシステムのチュートリアルを参照してください。

### 2-2.  Python3 環境の構築

#### macOS
```
$ brew install python3
```
<!---
pipenv を利用する場合は以下も行います。
```
$ brew install pipenv
```
--->
#### Linux
```
$ sudo add-apt-repository ppa:deadsnakes/ppa  
$ sudo apt update  
$ sudo apt install python3.6 python3.6-dev python3.6-venv
```
※ 16.10 以降の版では python3 (python3.6) をそのまま apt でインストールできます。
<!---
pipenv を利用する場合は (python3 環境下で) 以下も行います。
```
$ pip install pipenv
```
--->

#### Python 仮想環境の利用
macOS の場合は 'python3.6' を 'python3' と読み替えてください。
```
$ python3.6 -m venv bbcenv  
$ source bbcenv/bin/activate  
(bbcenv) $ pip install -U pip
```
仮想環境から出る場合は次のコマンドを用います。
```
(bbcenv) $ deactivate
```

## 3. BBc-1 Core のインストール
BBc-1 Core をインストールするためには以下を実行します。

#### ソースツリーの取得
```
$ git clone git@github.com:beyond-blockchain/bbc1.git
```
または
```
$ git clone https://github.com/beyond-blockchain/bbc1.git
```
#### ソースツリーのトップへ
```
$ cd bbc1
```
<!---
2018年4月23日現在、この時点で 0.10系のソースツリーが形成されています。1.0系のソースツリーに切り替える場合は次のコマンドを用いてください。
```
$ git checkout 1.0-pre
```
以降は 1.0-pre を前提に進めます。
--->

#### 一部C言語で記述されている部分のコンパイル等をして実行準備を整えます
```
$ sh prepare.sh
```
#### 必要な Python パッケージをインストールします
```
$ pip install -r requirements.txt
```

#### 開発中の pip インストールの方法
ソースツリーから tar ボールを作成し、pip インストールすることもできます。ソースツリーのトップで次を行ってください。
```
$ python setup.py sdist
$ pip install dist/bbc1-<バージョン>.tar.gz
```

## 4. bbc_core の起動

bbc_core.py があるディレクトリに移動し、起動します (pip インストールされている場合は、任意の場所で bbc_core.py をコマンドとして起動できます)。
```
$ cd bbc1/core
$ python bbc_core.py --no_nodekey
```
"`--no_nodekey`" はノードに対するアクセス制御を行わないことを指定する起動オプションです。ここでは簡単なサンプルの試用を想定して、このオプションを指定しています。

ターミナルにはログが表示されます。

終了させたい場合は Ctrl+C を押します。

## 5. おわりに
以上が BBc-1 Core のインストールと単体での起動の説明です。次はぜひサンプルアプリケーションを通して実際に BBc-1 Core の機能を試してみてください。

* 「BBc-1 Core チュートリアル :  file_proof を用いて」( BBc1_core_tutorial_file_proof_ja_r3.md )

> Written with [StackEdit](https://stackedit.io/).

<!--stackedit_data:
eyJoaXN0b3J5IjpbLTMwMjUxODE1Miw1MzEzMjg5MzIsLTE0OD
I2OTUyMTksLTI0NTM1OTYyMCwtMjE2OTI4MzU1LDY4NzQ3NjYy
MiwtMTc4NDI4Mzk1NCwtMTc5NjI0NzA4NSwtMTc4NDI4Mzk1NC
wtMjAwNzcwNDQwNSwtMTM3NjY2ODQ1NywxMzE1MTQ4NTQsLTIy
ODc2ODcwNywxNTQ5NzE0MDA0LDIxOTM2NzExMywtMzkyMjM1MD
M4LDk0NDI2NjIyLC0xODI2MDY4Mzg2LDI3Nzg5NTI4NSwtMTAy
MDcwNjE3XX0=
-->