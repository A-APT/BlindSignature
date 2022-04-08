import org.bouncycastle.jcajce.provider.asymmetric.util.EC5Util
import org.bouncycastle.math.ec.ECCurve
import org.bouncycastle.math.ec.ECMultiplier
import org.bouncycastle.math.ec.ECPoint
import java.math.BigInteger
import java.security.SecureRandom
import java.security.spec.ECFieldFp
import java.security.spec.EllipticCurve

data class KeyPair(val publicKey: ECPoint, val privateKey: BigInteger)
data class BlindedData(val a: BigInteger, val b: BigInteger, val R: ECPoint, val blindM: BigInteger)

class BlindSecp256k1 {
    // See SEC 2: Recommended Elliptic Curve Domain Parameters
    // https://www.secg.org/sec2-v2.pdf: 2.4.1 Recommended Parameters secp256k1
    val P: BigInteger = BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16)
    val N: BigInteger = BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)
    // The curve E: y2 = x3 + ax + b over Fp is defined by
    val a: BigInteger = BigInteger("0000000000000000000000000000000000000000000000000000000000000000", 16)
    val b: BigInteger = BigInteger("0000000000000000000000000000000000000000000000000000000000000007", 16)
    val Gx: BigInteger = BigInteger("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 16) // The base point G
    val Gy: BigInteger = BigInteger("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", 16) // The order n of G

    val ecCurve: ECCurve = EC5Util.convertCurve(EllipticCurve(ECFieldFp(P), a, b))
    val random = SecureRandom()
    var multiplier: ECMultiplier = ecCurve.multiplier
    var G: ECPoint = ecCurve.createPoint(Gx, Gy)

    fun generateRandomNum(): BigInteger {
        var num: BigInteger
        do {
            num = BigInteger(N.bitLength(), random).mod(N)
        } while (num.signum() == 0)
        return num
    }

    fun generateKeyPair(): KeyPair {
        val private: BigInteger = generateRandomNum()
        val public = multiplier.multiply(G, private) // curve.mul(private)
        return KeyPair(public, private)
    }

    fun newRequestParameters(): Pair<BigInteger, ECPoint> {
        val k: BigInteger = generateRandomNum()
        val R_ = multiplier.multiply(G, k) // curve.mul(k)
        return Pair(k, R_) // R' = kG
    }

    fun blind(R_: ECPoint, m: BigInteger): BlindedData {
        if (!R_.isValid) throw error("R_ is not in curve")

        val a = generateRandomNum()
        val b = generateRandomNum()
        val R = multiplier.multiply(R_, a).add(multiplier.multiply(G, b)) // curve.add(curve.mul(a, R_), curve.mul(b)) // R=aR'+bG

        val aInv = a.modInverse(N)
        val blindM: BigInteger = (aInv * R.normalize().xCoord.toBigInteger().mod(N) * m).mod(N) // TODO hash m
        return BlindedData(a, b, R, blindM)
    }

    fun blindSign(privateKey: BigInteger, k: BigInteger, blindM: BigInteger): BigInteger {
        if (blindM >= N) throw error("blinded message is not inside the finite field.")
        if (blindM.signum() == 0) throw error("blinded message can not be 0.")
        return (privateKey * blindM + k).mod(N) // s' = dm' + k
    }

    fun unblind(a: BigInteger, b: BigInteger, blindSig: BigInteger): BigInteger {
        return (a * blindSig + b).mod(N) // s = as' + b
    }

    fun verify(sig: BigInteger, R: ECPoint, m: BigInteger, publicKey: ECPoint): Boolean {
        if (!R.isValid) throw error("R_ is not in curve")
        if (!publicKey.isValid) throw error("R_ is not in curve")

        val left = multiplier.multiply(G, sig) //curve.mul(sig) // sG
        val right = R.add(multiplier.multiply(publicKey, (R.normalize().xCoord.toBigInteger().mod(N) * m).mod(N))) // TODO h(m) // R + xRh(m)G
        return left.normalize().xCoord.toBigInteger() == right.normalize().xCoord.toBigInteger()
                && left.normalize().yCoord.toBigInteger() == right.normalize().yCoord.toBigInteger()
    }

}
