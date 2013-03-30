## Basic Concept
-- __Inspired by Tatsuyuki Inoue__ --

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
	
といった感じで平文と鍵を表す複素数を根にもつ式を展開し、その係数のみを取ることで暗号化するブロック暗号。  
効率的な因数分解アルゴリズムは色々あるが、5次以上の方程式の解の公式は存在しないことを利用する。  
平文のみの式は4次式になるようにし、鍵を組み合わせることで5次式以上にする。  
復号化するときは鍵が根になることを利用して4次式に次数下げしてから解く。  

数式処理は面倒くさそうだったので[Maxima](http://maxima.sourceforge.net/)を呼び出して解いてもらう。  
自分のMac環境での`subprocess`の呼び出し方なので、他の環境なら`MAXIMA_EXEC`を変えないといけないかも。  

## Strong Points
以下の2つの仕組みによって成り立っている。  
1. **５次以上の方程式の解の公式が存在しない、つまり因数分解に時間がかかることを利用。**  
2. **強引に因数分解されても、鍵と平文の区別がつかない** (下位8bitが平文と鍵で同じものができるため)  
   得られた根から、平文の断片８つの考え得る組み合わせを全て試すこともできるが、  
   鍵の個数が多い(=`num_of_keys`の値が大きい)ほど解読は困難になると言える。  
   その組み合わせの数は以下のように計算できる。  
   
   ```python
   # num_of_keys をnで表すとすると
   num_of_combinations = (n / 4 + 2)**((n % 4)*2) * (n / 4 + 1)**(8-(n % 4)*2)
   ```  
   
   ![組み合わせの数](https://github.com/pheehs/QuinticEncrypt/raw/master/growing_comb.png "組み合わせの数")  
   **要するに少し鍵の個数を増やせばめちゃくちゃ解読しづらくなる。**

## Bugs and Matters of concern
1. _たまにMaximaがこんなエラー吐いて落ちる。_  

    >factor: ran out of primes.  
    >-- an error. To debug this try: debugmode(true);)`

  [ここ](http://comments.gmane.org/gmane.comp.mathematics.maxima.general/23175)でなんか言ってるけどよくわからん。  
  
  -> そもそもMaxima使わないように数式処理の部分も実装する

2. _強引に因数分解される可能性が十分ある。_  
   -> どれぐらい次数を上げれば因数分解に非現実的な時間がかかるようになるか要検証  
      (計算量的安全性の確保)
  
3. _特殊な状況だと解読可能_  
   因数分解できた場合でも解読は難しいが、  
   **同じ平文あるいは同じ鍵に対する暗号文2つ以上を知られる場合**は、  
   鍵と平文の両方を完全に解読できる。(crack()に実装)  
   
   -> 対策思いつかない
   
4. _暗号化後のデータサイズが大きい_  
   -> 暗号後、自動的に何らかのアルゴリズムで圧縮する(オプションで追加)

## Benchmark
`"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz This is plain data."`(=72bytes)を平文として、  
`param_chars`と`num_of_keys`を変化させて暗号化・復号化にかかる時間を計測、gnuplotでグラフにしてみた。  
![ベンチマーク結果](https://github.com/pheehs/QuinticEncrypt/raw/master/benchmark_plot.png "ベンチマーク結果")  
この長さだと`param_chars`を大きくすればする程・`num_of_keys`を小さくすればする程、実行時間は短くなる事がわかる。

## Structure of Encrypted file

    |length|param|                                              equation_1                                                    ||    equation_2 ..
    |of org|chars|                               header                      ||                body                           ||
    |data  |     |dim|nd-imglen|nd-rellen| ... |2d-rellen|1d-imglen|1d-rellen||nd-img|nd-rel| ... |2d-img|2d-rel|1d-img|1d-rel||
    |4bytes|  2  | 2 |  4      |    4    |     |     4   |    4    |     4   ||  ?   |   ?  |     |  ?   |  ?   |   ?  |   ?  ||

## Notes
* もともと5次方程式を利用するつもりだったが、拡張して次数が自由に変えられるようになったので**Quintic**Encryptじゃない。

a polynomial expression 多項式  
high-powered equation 高次方程式  

5次方程式  
quintic equation  

↓_次数q(ﾟдﾟ )↓sage↓_

4次方程式  
quartic equation  

1. 複二次式の場合
  二次式と同様に解ける
2. それ以外の場合
  x^3の項を消して、フェラーリの方法orデカルトの方法orオイラーの方法で3次式と2次式に
  参考:[wikipedia](http://ja.wikipedia.org/wiki/4%E6%AC%A1%E6%96%B9%E7%A8%8B%E5%BC%8F)など

↓_次数q(ﾟдﾟ )↓sage↓_

3次方程式  
cubic equation  

2次方程式  
quadratic equation  
