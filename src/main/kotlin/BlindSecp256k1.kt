import java.math.BigInteger
import java.security.SecureRandom

data class KeyPair(val publicKey: Point, val privateKey: BigInteger)
data class BlindedData(val a: BigInteger, val b: BigInteger, val R: Point, val blindM: BigInteger)

class BlindSecp256k1 {

    val curve = EllipticCurve()
    val random = SecureRandom()

    fun generateKeyPair(): KeyPair {
        val private = BigInteger.valueOf(random.nextLong()) // BigInteger(curve.N.bitLength(), random).mod(curve.N)
        val public = curve.mul(private)
        return KeyPair(public, private)
    }

    fun newRequestParameters(): Pair<BigInteger, Point> {
        val k = BigInteger.valueOf(random.nextLong())
        val R_ = curve.mul(k)
        return Pair(k, R_) // R' = kG
    }

    fun blind(R_: Point, m: BigInteger): BlindedData {
        val a = BigInteger.valueOf(random.nextLong())
        val b = BigInteger.valueOf(random.nextLong())
        val R = curve.add(curve.mul(a, R_), curve.mul(b)) // R=aR'+bG
        val blindM: BigInteger = (R.x * m) / a // TODO hash m
        return BlindedData(a, b, R, blindM)
    }

    fun blindSign(privateKey: BigInteger, k: BigInteger, blindM: BigInteger): BigInteger {
        return (privateKey * blindM + k).mod(curve.N) // s' = dm' + k
    }

    fun unblind(a: BigInteger, b: BigInteger, blindSig: BigInteger): BigInteger {
        return (a * blindSig + b).mod(curve.N) // s = as' + b
    }

    fun verify(sig: BigInteger, R: Point, m: BigInteger): Boolean {
        val left = curve.mul(sig) // sG
        val right = curve.add(R, curve.mul(R.x * m)) // TODO h(m) // R + xRh(m)G
        return left == right
    }

}

fun main() {
    println("BlindSecp256k1")

    /// example
    val blind = BlindSecp256k1()
    val m: BigInteger               = BigInteger.valueOf(139248)
    val keyPair: KeyPair            = blind.generateKeyPair()
    val (k, R_)                     = blind.newRequestParameters()

    val blindedData: BlindedData    = blind.blind(R_, m)
    val blindSig: BigInteger        = blind.blindSign(keyPair.privateKey, k, blindedData.blindM)
    val sig: BigInteger             = blind.unblind(blindedData.a, blindedData.b, blindSig)

    val result: Boolean             = blind.verify(sig, blindedData.R, m)
    println(result)
    assert(result)
}
