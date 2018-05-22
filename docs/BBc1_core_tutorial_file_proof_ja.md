
# BBc-1 Core チュートリアル :  file_proof を用いて

<!---
contributors:
* ks91
* oopth
* kichinosukey
--->

## 1. はじめに
BBc-1 Core では、記録の存在を証明するとともに、権限をもつ本人であることをデジタル署名で証明可能な場合に限り、その記録を更新することができます。

このチュートリアルでは、以下のことを説明しています。
* file_proof サンプルアプリケーションの使用

#### 誰にとって有益か
* BBc-1 Core を初めて動かして試してみたい方
* BBc-1 Core の基本的な機能の使い方を知りたい方

## 2. BBc-1 Core のインストールと起動
「BBc-1 Core チュートリアル: インストールガイド」( BBc1_core_tutorial_installation_ja_r2.md) を参照してください。

## 3. file_proof サンプルアプリケーションを使う
file_proof は、BBc-1 Core の機能をデモンストレートするために開発されたサンプルアプリケーションです。BBc-1 Core の機能を網羅的に用いています。

* 記録 (この場合はファイル) を保存できます
* ファイルを読み出せます
* ファイルが改ざんされていないかの確認ができます
* 保存されているファイルの内容を更新できます (保存したユーザのみ)
* ファイルの送受信ができます (受け手が受理する場合のみ)

### 3-1. 準備
bbc_core.py を動かしているのとは別のターミナルウィンドウを開きましょう。

※ インストール時に venv を使用した場合、今回 file_proof 用に立ち上げたウィンドウでも例えば ```$ source bbcenv/bin/activate``` によって仮想環境に入ってください。

BBc-1 core をインストールしたディレクトリから file_proof サンプルアプリケーションのディレクトリに移動します。
```
$ cd examples/file_proof
```

### 3-2. file_proof を使う

基本的な使い方は --help で見ることができます。
```
$ python file_proof.py --help
```

#### セットアップする
まず「鍵ペア」を生成し、それから「ドメイン」をセットアップします。
```
$ python file_proof.py keypair
$ python file_proof.py setup
```
鍵ペア (公開鍵と秘密鍵のペア) のうち、秘密鍵はユーザとしてトランザクションに署名する際に用いられます。公開鍵は署名の検証に必要となります。鍵ペアの使用は file_proof のユーザからは隠蔽されていますが、トランザクションを発生させる場合に必ず使われています (ぜひコードで確認してみてください)。

ドメインは BBc-1 におけるネットワークの単位です。

※  setup を実行しても処理が進まない場合は、bbc_core.py を起動する際に domain_key を設定してないことが原因と考えられます。立ち上げている bbc_core を停止 (Ctrl + C) した後に再度 ```$ python bbc_core.py --no_nodekey``` を実行してください。

#### ファイルを保存する
まず、保存するためのファイルをつくります。
```
$ cat > test.txt
BBC HEAVEN.
^D
$ more test.txt
BBC HEAVEN.
```
file_proof.py を用いて BBc-1 Core にファイルを保存します。
```
$ python file_proof.py store test.txt
```
(トランザクションが生成され、ユーザによるデジタル署名が施された上で BBc-1 Core に投入されます。)

#### ファイルを取得する
手元のファイルを消してから、BBc-1 Core に保存しているファイルの内容で復元してみましょう。
```
$ rm test.txt
$ python file_proof.py get test.txt
```

#### ファイルの正当性を検証する
手元のファイルが BBc-1 Core に保存されている内容と一致しているかどうかを確認します。
```
$ python file_proof.py verify test.txt
```
出力の 1行目に
```
test.txt is valid
```
が表示されます。

手元のファイルの内容を変更してから試してみましょう。
```
$ cat > test.txt
BBC HEAVY.
^D
$ more test.txt
BBC HEAVY.
$ python file_proof.py verify test.txt
```
今度は出力の1行目が
```
test.txt is invalid
```
となります。

#### ファイルを更新する
変更したファイルで BBc-1 Core に保存されている内容を更新してみましょう。その後、verify コマンドで確認してみてください。
```
$ python file_proof.py update test.txt
```
(トランザクションが生成され、ユーザによるデジタル署名が施された上で BBc-1 Core に投入されます。)
```
$ python file_proof.py verify test.txt
```

#### ファイルを送る/受け取る
もうひとつ別のターミナルウィンドウを開いて、file_proof のディレクトリに移動してから次のようにしてファイルを待ち受けてください (別のソースディレクトリ、または別のマシンで実行すると実際にファイルが送られることを体験できるでしょう)。
```
$ python file_proof.py wait -o someone
```
待ち受けているユーザの名前と ID が表示されます。

元のターミナルウィンドウから次のようにしてファイルを送ってみてください。
```
$ python file_proof.py send test.txt
```
ファイルを受け取るユーザを聞かれるので、"someone" と入力してください。

待ち受け側のターミナルウィンドウに次のようにプロンプトが表示されます。
```
--------------------------
File digest written in the transaction data: d866539f224896613df91023f0a9e226085451d6adf1dc5282cbba129d553713
File digest calculated from the received file: d866539f224896613df91023f0a9e226085451d6adf1dc5282cbba129d553713
--------------------------
====> Do you want to accept the file?
(Y/N) >>
```

"Y" または "N" で返答してください。"Y" を返答する (デジタル署名を施したメッセージを返す) とファイルが送られます (同じソースツリー上で実行している場合は変化は起きません)。

## 4. おわりに
file_proof サンプルアプリケーションでは、BBc-1 Core の基本的な使い方が網羅されています。ぜひコードをご覧になって、みなさん自身のアプリケーションの開発にお役立てください。

> Written with [StackEdit](https://stackedit.io/).
<!--stackedit_data:
eyJoaXN0b3J5IjpbMTkzODIyMzQxMiwxMDA2NTY1MjM1LDIxMz
gwMTE4NTcsMTAwNjU2NTIzNSwyMTM4MDExODU3LDEwMDY1NjUy
MzUsMjAyMTc4MTE2NiwxMzU2ODc2MTQ1LDI2Mjg0MjE0MiwxMD
YxOTQ1MjE2LC04NzY5NTg4NDAsLTI4MDEyMDUyOCwtMTE1NzM0
ODE4NiwtMTc1MTYwMzUzLDE4NjAwMzM5OTUsLTE5ODU5NzM3MT
AsLTEzNDMwODg5NDIsMTQ4MTg1OTY1OCw1ODg1MDc2MzgsMTQ4
MTA5NjU2MF19
-->