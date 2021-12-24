# secp256k1
 Goで楕円曲線を実装する

# 楕円曲線


楕円曲線暗号に使う楕円曲線の式は

![\begin{align*}
{y^2 \equiv x^3 + ax + b \mod q   \mid a,b \in GF(q), 4a^3 + 27^2 \neq 0}
\end{align*}
](https://render.githubusercontent.com/render/math?math=%5Cdisplaystyle+%5Cbegin%7Balign%2A%7D%0A%7By%5E2+%5Cequiv+x%5E3+%2B+ax+%2B+b+%5Cmod+q+++%5Cmid+a%2Cb+%5Cin+GF%28q%29%2C+4a%5E3+%2B+27%5E2+%5Cneq+0%7D%0A%5Cend%7Balign%2A%7D%0A)


で定義された曲線のことです。
(厳密に言うと,)


# secp256k1


[secp256k1](http://www.secg.org/sec2-v2.pdf)は標準化された楕円曲線で、イーサリアムなどのブロックチェーンの署名アルゴリズムで使われています。
楕円曲線ではいくつかのパラメータが存在して、Secp256k1はそれらの各パラメーターが次のように決まっています。


## パラメータ


**法とする素数**


![\begin{aligned}
p &= FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE FFFFFC2F \\
&= 2^{256}-2^{32}-2^{9}-2^{8}-2^{7}-2^{6}-2^{4}-1
\end{aligned}
](https://render.githubusercontent.com/render/math?math=%5Cdisplaystyle+%5Cbegin%7Baligned%7D%0Ap+%26%3D+FFFFFFFF+FFFFFFFF+FFFFFFFF+FFFFFFFF+FFFFFFFF+FFFFFFFF+FFFFFFFE+FFFFFC2F+%5C%5C%0A%26%3D+2%5E%7B256%7D-2%5E%7B32%7D-2%5E%7B9%7D-2%5E%7B8%7D-2%5E%7B7%7D-2%5E%7B6%7D-2%5E%7B4%7D-1%0A%5Cend%7Baligned%7D%0A)


**曲線**

![\begin{aligned}
y^2 = x^3 + 7
\end{aligned}
](https://render.githubusercontent.com/render/math?math=%5Cdisplaystyle+%5Cbegin%7Baligned%7D%0Ay%5E2+%3D+x%5E3+%2B+7%0A%5Cend%7Baligned%7D%0A)


**ビットサイズ**

![\begin{aligned}
bitSize=256
\end{aligned}
](https://render.githubusercontent.com/render/math?math=%5Cdisplaystyle+%5Cbegin%7Baligned%7D%0AbitSize%3D256%0A%5Cend%7Baligned%7D%0A)


**ベースポイント**
(楕円曲線上の点)


    Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
    Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
    // 圧縮形式
    G =  0x0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
    // 非圧縮形式
    G =  0x0479BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8


## 楕円曲線暗号による公開鍵の生成


1.  楕円曲線のパラメータp,a,bと基準点G(x,y)を決める
2.  Gに自身であるGを足し、2Gを求める
3.  2)ををn回分（n：秘密鍵の値）繰り返し、値nGを得る
4.  nGを公開鍵の値とする


<br/>
<br/>


楕円曲線の原理はこんなかんじなのでこれをコードに落とし込みます。<br/>


# secp256k1をGoで実装する


まずはsecp256k1のパラメーターを定義


```go
type CurveParams struct {
	P       *big.Int 
	N       *big.Int 
	B       *big.Int 
	Gx, Gy  *big.Int 
	BitSize int      
	Name    string
}
```


```go
var (
	secp256k1 *CurveParams
	// http://www.secg.org/sec2-v2.pdf
	p, _    = new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16)
	n, _    = new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)
	b, _    = new(big.Int).SetString("0000000000000000000000000000000000000000000000000000000000000007", 16)
	gx, _   = new(big.Int).SetString("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 16)
	gy, _   = new(big.Int).SetString("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", 16)
	bitSize = 256
	name    = "secp256k1"
)
```


次にメソッドを実装


### Params()


ポインタを返すだけのメソッド


```go
func (curve *CurveParams) Params() *elliptic.CurveParams {
	return &elliptic.CurveParams{
		P:       p,
		N:       n,
		B:       b,
		Gx:      gx,
		Gy:      gy,
		BitSize: bitSize,
		Name:    name,
	}
}
```


### IsOnCurve()


与えられた点が楕円曲線上にあるかどうかを返すメソッド

![\begin{aligned}
y^2 - x^3 + b \mod p
\end{aligned}
](https://render.githubusercontent.com/render/math?math=%5Cdisplaystyle+%5Cbegin%7Baligned%7D%0Ay%5E2+-+x%5E3+%2B+b+%5Cmod+p%0A%5Cend%7Baligned%7D%0A)

が0かどうか調べればよい


```go
func (curve *CurveParams) IsOnCurve(x, y *big.Int) bool {
	y2 := new(big.Int).Exp(y, big.NewInt(2), nil)
	x3 := new(big.Int).Exp(x, big.NewInt(3), nil)
	ans := new(big.Int).Mod(y2.Sub(y2, x3.Add(x3, curve.B)), curve.P)
	return ans.Cmp(big.NewInt(0)) == 0
}
```


### Add()


与えられた2点の足し算を行う。
ヤコビアンで計算する。[この公式](https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-3.html#addition-add-2007-bl)使った。


**ヤコビアンからアフィン座標に変換するメソッド**

![\begin{aligned}
(X', Y') = (\frac{X}{Z^2}, \frac{Y}{Z^3})
\end{aligned}
](https://render.githubusercontent.com/render/math?math=%5Cdisplaystyle+%5Cbegin%7Baligned%7D%0A%28X%27%2C+Y%27%29+%3D+%28%5Cfrac%7BX%7D%7BZ%5E2%7D%2C+%5Cfrac%7BY%7D%7BZ%5E3%7D%29%0A%5Cend%7Baligned%7D%0A)


```go
func (curve *CurveParams) affineFromJacobian(x, y, z *big.Int) (xOut, yOut *big.Int) {
	if z.Sign() == 0 {
		return new(big.Int), new(big.Int)
	}
	zinv := new(big.Int).ModInverse(z, curve.P)
	zinvsq := new(big.Int).Mul(zinv, zinv)
	xOut = new(big.Int).Mul(x, zinvsq)
	xOut.Mod(xOut, curve.P)
	zinvsq.Mul(zinvsq, zinv)
	yOut = new(big.Int).Mul(y, zinvsq)
	yOut.Mod(yOut, curve.P)
	return
}
```


**アフィン座標 (x,y) に対するヤコビアンの z 値を返すメソッド**

![\begin{aligned}
(X', Y', Z') = (X, Y, 1)
\end{aligned}
](https://render.githubusercontent.com/render/math?math=%5Cdisplaystyle+%5Cbegin%7Baligned%7D%0A%28X%27%2C+Y%27%2C+Z%27%29+%3D+%28X%2C+Y%2C+1%29%0A%5Cend%7Baligned%7D%0A)


```go
func zForAffine(x, y *big.Int) *big.Int {
	z := new(big.Int)
	if x.Sign() != 0 || y.Sign() != 0 {
		z.SetInt64(1)
	}
	return z
}
```


```go
func (curve *CurveParams) addJacobian(x1, y1, z1, x2, y2, z2 *big.Int) (*big.Int, *big.Int, *big.Int) {
	x3, y3, z3 := new(big.Int), new(big.Int), new(big.Int)
	if z1.Sign() == 0 {
		x3.Set(x2)
		y3.Set(y2)
		z3.Set(z2)
		return x3, y3, z3
	}
	if z2.Sign() == 0 {
		x3.Set(x1)
		y3.Set(y1)
		z3.Set(z1)
		return x3, y3, z3
	}
	z1z1 := new(big.Int).Mul(z1, z1)
	z1z1.Mod(z1z1, curve.P)
	z2z2 := new(big.Int).Mul(z2, z2)
	z2z2.Mod(z2z2, curve.P)
	u1 := new(big.Int).Mul(x1, z2z2)
	u1.Mod(u1, curve.P)
	u2 := new(big.Int).Mul(x2, z1z1)
	u2.Mod(u2, curve.P)
	h := new(big.Int).Sub(u2, u1)
	xEqual := h.Sign() == 0
	if h.Sign() == -1 {
		h.Add(h, curve.P)
	}
	i := new(big.Int).Lsh(h, 1)
	i.Mul(i, i)
	j := new(big.Int).Mul(h, i)
	s1 := new(big.Int).Mul(y1, z2)
	s1.Mul(s1, z2z2)
	s1.Mod(s1, curve.P)
	s2 := new(big.Int).Mul(y2, z1)
	s2.Mul(s2, z1z1)
	s2.Mod(s2, curve.P)
	r := new(big.Int).Sub(s2, s1)
	if r.Sign() == -1 {
		r.Add(r, curve.P)
	}
	yEqual := r.Sign() == 0
	if xEqual && yEqual {
		return curve.doubleJacobian(x1, y1, z1)
	}
	r.Lsh(r, 1)
	v := new(big.Int).Mul(u1, i)
	x3.Set(r)
	x3.Mul(x3, x3)
	x3.Sub(x3, j)
	x3.Sub(x3, v)
	x3.Sub(x3, v)
	x3.Mod(x3, curve.P)
	y3.Set(r)
	v.Sub(v, x3)
	y3.Mul(y3, v)
	s1.Mul(s1, j)
	s1.Lsh(s1, 1)
	y3.Sub(y3, s1)
	y3.Mod(y3, curve.P)
	z3.Add(z1, z2)
	z3.Mul(z3, z3)
	z3.Sub(z3, z1z1)
	z3.Sub(z3, z2z2)
	z3.Mul(z3, h)
	z3.Mod(z3, curve.P)
	return x3, y3, z3
}
```


**Add()メソッド**


```go
func (curve *CurveParams) Add(x1, y1, x2, y2 *big.Int) (x, y *big.Int) {
	z1 := zForAffine(x1, y1)
	z2 := zForAffine(x2, y2)
	return curve.affineFromJacobian(curve.addJacobian(x1, y1, z1, x2, y2, z2))
}
```


### ScalarMult()


与えられた点を k 倍するメソッド


```go
func (curve *CurveParams) ScalarMult(Bx, By *big.Int, k []byte) (x, y *big.Int) {
	Bz := new(big.Int).SetInt64(1)
	x, y, z := new(big.Int), new(big.Int), new(big.Int)
	for _, byte := range k {
		for bitNum := 0; bitNum < 8; bitNum++ {
            x, y, z = curve.doubleJacobian(x, y, z) // 倍算
			if byte&0x80 == 0x80 { // ビットが1だったら加算
				x, y, z = curve.addJacobian(Bx, By, Bz, x, y, z)
			}
			byte <<= 1
		}
	}
	return curve.affineFromJacobian(x, y, z)
}
```


![\begin{aligned}
k = \sum_{j=1}^{n-1}k_j2^j (k_j={0,1})
\end{aligned}
](https://render.githubusercontent.com/render/math?math=%5Cdisplaystyle+%5Cbegin%7Baligned%7D%0Ak+%3D+%5Csum_%7Bj%3D1%7D%5E%7Bn-1%7Dk_j2%5Ej+%28k_j%3D%7B0%2C1%7D%29%0A%5Cend%7Baligned%7D%0A)


### ScalarBaseMult()


ベースポイント G を k 倍する


```go
func (curve *CurveParams) ScalarBaseMult(k []byte) (x, y *big.Int) {
	return curve.ScalarMult(curve.Gx, curve.Gy, k)
}
```


### Secp256k1()


```go
func init() {
	secp256k1 = &CurveParams{
		P:       p,
		N:       n,
		B:       b,
		Gx:      gx,
		Gy:      gy,
		BitSize: bitSize,
		Name:    name,
	}
}
```


```go
func Secp256k1() elliptic.Curve {
	return secp256k1
}
```



