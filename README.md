## Basic Concept
Inspired by Tatsuyuki Inoue

    ( x - (±α_1 ±α_2 *i) )* ( x - (±α_3 ±α_4 *i) )*
    ( x - (±α_5 ±α_6 *i) )* ( x - (±α_7 ±α_8 *i) )*
	
	( x - (±β_1 ±β_2 *i) )* ( x - (±β_3 ±β_4 *i) )* ...

    α_1 〜 α_8： ±AABBCCDDEEZ // 平文
    | ±: AAの最上位ビットが1なら-、0なら+ // 要らない？
    | AA - EE: 平文の分割されたデータ(長さ：param_chars)
    | Z: 順番に 0 〜 7 // 復号化時に平文を再構築するため
		
    β_1 〜 β_(NUM_OF_KEYS*2): ±AABBCCDDEEZ // 鍵
    | ±: AAの最上位ビットが1なら-、0なら+
    | AA...: 鍵のSHA512の上位(PARAM_CHARS)*(NUM_OF_KEYS*2)バイト  
    |        長さが足りなくなったらhashの更にhashをとってつなげる。
	|		 平文の方と同じ長さ
    | Z: 順番に 0 ~ 7
	
といった感じに平文と鍵を表す複素数の根をもつ式を展開し、その係数のみを取ることで暗号化するブロック暗号。  
効率的な因数分解アルゴリズムは色々あるが、5次以上の方程式の解の公式は存在しないことを利用する。  
平文のみの式は4次式になるようにし、鍵を組み合わせることで5次式以上にする。  
復号化するときは鍵が根になることを利用して4次式に次数下げして、解く。  

数学的な部分のアルゴリズムとか面倒くさそうだったので[Maxima](http://maxima.sourceforge.net/)を呼び出して解いてもらう。  
自分のMac環境での`subprocess`の呼び出し方なので、他の環境なら`MAXIMA_EXEC`を変えるべし。  

## Structure of Encrypted file

    |length|param|                                              equation_1                                                    ||    equation_2 ..
    |of org|chars|                               header                      ||                body                           ||
    |data  |     |dim|nd-imglen|nd-rellen| ... |2d-rellen|1d-imglen|1d-rellen||nd-img|nd-rel| ... |2d-img|2d-rel|1d-img|1d-rel||
    |4bytes|  2  | 2 |  4      |    4    |     |     4   |    4    |     4   ||  ?   |   ?  |     |  ?   |  ?   |   ?  |   ?  ||

## BUGs and Matters of concern
1. たまにMaximaがこんなエラー吐いて落ちる。

    factor: ran out of primes.
    -- an error. To debug this try: debugmode(true);)`

  [ここ](http://comments.gmane.org/gmane.comp.mathematics.maxima.general/23175)でなんか言ってるけどよくわからん。  

2. **ゴリ押しで因数分解される可能性が十分ある。**
  一応鍵と平文の区別がつかないようになっているが、(下位8bitが平文と鍵で同じものがある）
  因数分解できる状況で同じ平文と同じ鍵に対する暗号文を知られると鍵が分かるので、完全に解読される。
  -> どれぐらい次数を上げればで計算量的安全性を確保できるか？
3. 暗号化後のデータサイズが大きい

## Benchmark
|##                              |   user|       sys|     total|      real|
|:-------------------------------|------:|---------:|---------:|---------:|
|encrypt/decrypt(p: 3, k: 1)     | 0.0500|    0.0600|    0.1100|   11.5441|
|encrypt/decrypt(p: 3, k: 2)     | 0.0500|    0.0600|    0.1100|   11.2701|
|encrypt/decrypt(p: 3, k: 3)     | 0.0500|    0.0500|    0.1000|   11.8981|
|encrypt/decrypt(p: 3, k: 4)     | 0.0700|    0.0600|    0.1300|   12.8204|
|encrypt/decrypt(p: 3, k: 5)     | 0.0800|    0.0700|    0.1500|   13.2430|
|encrypt/decrypt(p: 3, k: 6)     | 0.0800|    0.0600|    0.1400|   12.9392|
|encrypt/decrypt(p: 3, k: 7)     | 0.1000|    0.0600|    0.1600|   12.9341|
|encrypt/decrypt(p: 3, k: 8)     | 0.1000|    0.0600|    0.1600|   13.2537|
|encrypt/decrypt(p: 3, k: 9)     | 0.1300|    0.0600|    0.1900|   14.4122|
|encrypt/decrypt(p: 3, k: 10)    | 0.1500|    0.0600|    0.2100|   14.3255|
|encrypt/decrypt(p: 4, k: 1)     | 0.0300|    0.0500|    0.0800|    8.3306|
|encrypt/decrypt(p: 4, k: 2)     | 0.0400|    0.0400|    0.0800|    8.7008|
|encrypt/decrypt(p: 4, k: 3)     | 0.0400|    0.0500|    0.0900|    8.7001|
|encrypt/decrypt(p: 4, k: 4)     | 0.0600|    0.0500|    0.1100|    8.9509|
|encrypt/decrypt(p: 4, k: 5)     | 0.0600|    0.0400|    0.1000|    9.0792|
|encrypt/decrypt(p: 4, k: 6)     | 0.0800|    0.0500|    0.1300|    9.9843|
|encrypt/decrypt(p: 4, k: 7)     | 0.0900|    0.0500|    0.1400|   10.6747|
|encrypt/decrypt(p: 4, k: 8)     | 0.1000|    0.0500|    0.1500|   10.4102|
|encrypt/decrypt(p: 4, k: 9)     | 0.1100|    0.0400|    0.1500|   10.2570|
|encrypt/decrypt(p: 4, k: 10)    | 0.1200|    0.0500|    0.1700|   10.8880|
|encrypt/decrypt(p: 5, k: 1)     | 0.0400|    0.0400|    0.0800|    7.3138|
|encrypt/decrypt(p: 5, k: 2)     | 0.0400|    0.0400|    0.0800|    7.3473|
|encrypt/decrypt(p: 5, k: 3)     | 0.0500|    0.0400|    0.0900|    7.4862|
|encrypt/decrypt(p: 5, k: 4)     | 0.0500|    0.0400|    0.0900|    7.7534|
|encrypt/decrypt(p: 5, k: 5)     | 0.0600|    0.0400|    0.1000|    7.9698|
|encrypt/decrypt(p: 5, k: 6)     | 0.0700|    0.0400|    0.1100|    8.3844|
|encrypt/decrypt(p: 5, k: 7)     | 0.0800|    0.0300|    0.1100|    8.1864|
|encrypt/decrypt(p: 5, k: 8)     | 0.1000|    0.0400|    0.1400|    8.7232|
|encrypt/decrypt(p: 5, k: 9)     | 0.1100|    0.0400|    0.1500|    9.8737|
|encrypt/decrypt(p: 5, k: 10)    | 0.1500|    0.0500|    0.2000|   10.4016|
|encrypt/decrypt(p: 6, k: 1)     | 0.0300|    0.0300|    0.0600|    6.2429|
|encrypt/decrypt(p: 6, k: 2)     | 0.0400|    0.0300|    0.0700|    6.3985|
|encrypt/decrypt(p: 6, k: 3)     | 0.0400|    0.0300|    0.0700|    6.3422|
|encrypt/decrypt(p: 6, k: 4)     | 0.0500|    0.0400|    0.0900|    6.4226|
|encrypt/decrypt(p: 6, k: 5)     | 0.0600|    0.0300|    0.0900|    6.4196|
|encrypt/decrypt(p: 6, k: 6)     | 0.0800|    0.0300|    0.1100|    6.6668|
|encrypt/decrypt(p: 6, k: 7)     | 0.0900|    0.0300|    0.1200|    9.0652|
|encrypt/decrypt(p: 6, k: 8)     | 0.1000|    0.0400|    0.1400|    9.2325|
|encrypt/decrypt(p: 6, k: 9)     | 0.1200|    0.0300|    0.1500|    8.1738|
|encrypt/decrypt(p: 6, k: 10)    | 0.1300|    0.0300|    0.1600|    8.9072|
|encrypt/decrypt(p: 7, k: 1)     | 0.0300|    0.0300|    0.0600|    5.9632|
|encrypt/decrypt(p: 7, k: 2)     | 0.0400|    0.0300|    0.0700|    5.3397|
|encrypt/decrypt(p: 7, k: 3)     | 0.0400|    0.0200|    0.0600|    5.3549|
|encrypt/decrypt(p: 7, k: 4)     | 0.0500|    0.0300|    0.0800|    5.3711|
|encrypt/decrypt(p: 7, k: 5)     | 0.0600|    0.0200|    0.0800|    5.3618|
|encrypt/decrypt(p: 7, k: 6)     | 0.0700|    0.0300|    0.1000|    5.6050|
|encrypt/decrypt(p: 7, k: 7)     | 0.0700|    0.0300|    0.1000|    5.6503|
|encrypt/decrypt(p: 7, k: 8)     | 0.0900|    0.0200|    0.1100|    6.1006|
|encrypt/decrypt(p: 7, k: 9)     | 0.1000|    0.0300|    0.1300|    5.9557|
|encrypt/decrypt(p: 7, k: 10)    | 0.1200|    0.0300|    0.1500|    6.3328|
|encrypt/decrypt(p: 8, k: 1)     | 0.0300|    0.0200|    0.0500|    4.4236|
|encrypt/decrypt(p: 8, k: 2)     | 0.0400|    0.0300|    0.0700|    4.6038|
|encrypt/decrypt(p: 8, k: 3)     | 0.0300|    0.0200|    0.0500|    4.7485|
|encrypt/decrypt(p: 8, k: 4)     | 0.0400|    0.0200|    0.0600|    4.8080|
|encrypt/decrypt(p: 8, k: 5)     | 0.0700|    0.0300|    0.1000|    4.8728|
|encrypt/decrypt(p: 8, k: 6)     | 0.0700|    0.0200|    0.0900|    5.1923|
|encrypt/decrypt(p: 8, k: 7)     | 0.0900|    0.0300|    0.1200|    5.1286|
|encrypt/decrypt(p: 8, k: 8)     | 0.1000|    0.0200|    0.1200|    5.4628|
|encrypt/decrypt(p: 8, k: 9)     | 0.1100|    0.0300|    0.1400|    5.4705|
|encrypt/decrypt(p: 8, k: 10)    | 0.1400|    0.0200|    0.1600|    5.6909|
|encrypt/decrypt(p: 9, k: 1)     | 0.0200|    0.0300|    0.0500|    4.1901|
|encrypt/decrypt(p: 9, k: 2)     | 0.0300|    0.0200|    0.0500|    4.5074|
|encrypt/decrypt(p: 9, k: 3)     | 0.0400|    0.0200|    0.0600|    4.5240|
|encrypt/decrypt(p: 9, k: 4)     | 0.0500|    0.0200|    0.0700|    4.4568|
|encrypt/decrypt(p: 9, k: 5)     | 0.0600|    0.0300|    0.0900|    4.6615|
|encrypt/decrypt(p: 9, k: 6)     | 0.0800|    0.0200|    0.1000|    4.5378|
|encrypt/decrypt(p: 9, k: 7)     | 0.0800|    0.0200|    0.1000|    4.8666|
|encrypt/decrypt(p: 9, k: 8)     | 0.1000|    0.0300|    0.1300|    4.9316|
|encrypt/decrypt(p: 9, k: 9)     | 0.1200|    0.0200|    0.1400|    5.0116|
|encrypt/decrypt(p: 9, k: 10)    | 0.1400|    0.0200|    0.1600|    5.1788|
|encrypt/decrypt(p: 10, k: 1)    | 0.0300|    0.0200|    0.0500|    3.7347|
|encrypt/decrypt(p: 10, k: 2)    | 0.0300|    0.0200|    0.0500|    3.8614|
|encrypt/decrypt(p: 10, k: 3)    | 0.0400|    0.0200|    0.0600|    4.0064|
|encrypt/decrypt(p: 10, k: 4)    | 0.0500|    0.0200|    0.0700|    4.0462|
|encrypt/decrypt(p: 10, k: 5)    | 0.0600|    0.0200|    0.0800|    4.1064|
|encrypt/decrypt(p: 10, k: 6)    | 0.0700|    0.0200|    0.0900|    4.2203|
|encrypt/decrypt(p: 10, k: 7)    | 0.0800|    0.0200|    0.1000|    4.2450|
|encrypt/decrypt(p: 10, k: 8)    | 0.1100|    0.0200|    0.1300|    4.5015|
|encrypt/decrypt(p: 10, k: 9)    | 0.1300|    0.0300|    0.1600|    4.6233|
|encrypt/decrypt(p: 10, k: 10)   | 0.1500|    0.0200|    0.1700|    4.7639|

## Notes
* もともと5次方程式を利用するつもりだったが、拡張して次数が自由に変えられるので名前があってない。

a polynomial expression 多項式  
high-powered equation 高次方程式  

5次方程式  
quintic equation  

↓*次数q(ﾟдﾟ )↓sage↓*

4次方程式  
quartic equation  

1. 複二次式の場合
  二次式と同様に解ける
2. それ以外の場合
  x^3の項を消して、フェラーリの方法orデカルトの方法orオイラーの方法で3次式と2次式に
  参考:[wikipedia](http://ja.wikipedia.org/wiki/4%E6%AC%A1%E6%96%B9%E7%A8%8B%E5%BC%8F)など

↓*次数q(ﾟдﾟ )↓sage↓*

3次方程式  
cubic equation  

2次方程式  
quadratic equation  
