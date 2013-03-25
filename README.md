## Basic Concept
    ( x - (±α_1 ±α_2 *i) )* ( x - (±α_3 ±α_4 *i) )*
    ( x - (±α_5 ±α_6 *i) )* ( x - (±α_7 ±α_8 *i) )*
	
	( x - (±β_1 ±β_2 *i) )* ( x - (±β_3 ±β_4 *i) )

α_1 〜 α_8, β_1 〜 β_4 (NUM_OF_KEYS * 2個)

α_k： ±AABBCCDDEEZ // 平文
| ±: AAの最上位ビットが1なら-、0なら+ // 要らない？
| AA - EE: データ
| Z: 組立番号  0000(0x0) - 1000(0x8)
β_k: ±AABBCCDDEEZ // 鍵
| ±: AAの最上位ビットが1なら-、0なら+
| AA...: 鍵のSHA512の上位5*(NUM_OF_KEYS*2)バイト  
         [64/10=6.4]よりNUM_OF_KEYSは最大で6まで　
		 と思いきや足りなくなったらhashの更にhashをとってつなげて、続ける。
| Z: ランダムに 0 ~ 8

## Structure of Encrypted file
|                                equation_1                              ||    equation_2 ..
|         header        ||                body                           ||
|ndlen| ... |2dlen|1dlen||nd-img,nd-rel| ... |2d-img,2d-rel|1d-img,1d-rel|| 
      ^     ^     ^     ^       ^                   ^             ^
	 NULL  NULL  NULL  NULL    SPACE              SPACE        SPACE

## Notes
a polynomial expression 多項式
high-powered equation 高次方程式

5次方程式
quintic equation

↓字数q(ﾟдﾟ )↓sage↓

4次方程式
quartic equation

1. 複二次式の場合
  二次式と同様に解ける
2. それ以外の場合
  x^3の項を消して、フェラーリの方法orデカルトの方法orオイラーの方法で3次式に
(http://www004.upp.so-net.ne.jp/s_honma/ferrari/ferrari.htm)
(http://ja.wikipedia.org/wiki/4%E6%AC%A1%E6%96%B9%E7%A8%8B%E5%BC%8F)

↓字数q(ﾟдﾟ )↓sage↓

3次方程式
cubic equation

2次方程式
quadratic equation
