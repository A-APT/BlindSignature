import org.bouncycastle.jcajce.provider.asymmetric.util.EC5Util
import org.bouncycastle.math.ec.ECCurve
import org.bouncycastle.math.ec.ECMultiplier
import org.bouncycastle.math.ec.ECPoint
import java.math.BigInteger
import java.security.SecureRandom
import java.security.spec.ECFieldFp
import kotlin.math.absoluteValue

data class KeyPair(val publicKey: ECPoint, val privateKey: BigInteger)
data class BlindedData(val a: BigInteger, val b: BigInteger, val R: ECPoint, val blindM: BigInteger)

class BlindSecp256k1 {

    val curve = EllipticCurve()
    var ecCurve: ECCurve
    val random = SecureRandom()
    var multiplier: ECMultiplier
    var G: ECPoint

    init {
        val c = java.security.spec.EllipticCurve(ECFieldFp(curve.P), curve.a, curve.b)
        ecCurve = EC5Util.convertCurve(c)
        multiplier = ecCurve.multiplier
        G = ecCurve.createPoint(curve.Gx, curve.Gy)
    }

    fun generateKeyPair(): KeyPair {
        val private = BigInteger(curve.N.bitLength(), random).mod(curve.N)
        val public = multiplier.multiply(G, private) // curve.mul(private)
        return KeyPair(public, private)
    }

    fun newRequestParameters(): Pair<BigInteger, ECPoint> {
        lateinit var k: BigInteger
        do {
            k = BigInteger(curve.N.bitLength(), random)
        } while (k >= curve.N)
        //val k = BigInteger(curve.N.bitLength(), random).mod(curve.N) //BigInteger.valueOf(random.nextLong().absoluteValue).mod(curve.N)
        val R_ = multiplier.multiply(G, k) // curve.mul(k)
        return Pair(k, R_) // R' = kG
    }

    fun blind(R_: ECPoint, m: BigInteger): BlindedData {
        if (!curve.isOnCurve(Point(R_.normalize().xCoord.toBigInteger(), R_.normalize().yCoord.toBigInteger())))
            throw error("R_ is not in curve")

        val a = BigInteger.valueOf(random.nextLong().absoluteValue).mod(curve.N)
        val b = BigInteger.valueOf(random.nextLong().absoluteValue).mod(curve.N)
        val R = multiplier.multiply(R_, a).add(multiplier.multiply(G, b)) // curve.add(curve.mul(a, R_), curve.mul(b)) // R=aR'+bG
        if (!curve.isOnCurve(Point(R.normalize().xCoord.toBigInteger(), R.normalize().yCoord.toBigInteger())))
            throw error("R is not in curve")

        val a_1 = a.modInverse(curve.N)
        val blindM: BigInteger = (a_1 * R.normalize().xCoord.toBigInteger().mod(curve.N) * m).mod(curve.N) // TODO hash m
        return BlindedData(a, b, R, blindM)
    }

    fun blindSign(privateKey: BigInteger, k: BigInteger, blindM: BigInteger): BigInteger {
        if (blindM.compareTo(curve.N) != -1) throw error("blinded message is not inside the finite field.")
        if (blindM.signum() == 0) throw error("blinded message can not be 0.")
        return (privateKey * blindM + k).mod(curve.N) // s' = dm' + k
    }

    fun unblind(a: BigInteger, b: BigInteger, blindSig: BigInteger): BigInteger {
        return (a * blindSig + b).mod(curve.N) // s = as' + b
    }

    fun verify(sig: BigInteger, R: ECPoint, m: BigInteger, publicKey: ECPoint): Boolean {
        val left = multiplier.multiply(G, sig) //curve.mul(sig) // sG
        val right = R.add(multiplier.multiply(publicKey, (R.normalize().xCoord.toBigInteger().mod(curve.N) * m).mod(curve.N))) // TODO h(m) // R + xRh(m)G
        return left.normalize().xCoord.toBigInteger() == right.normalize().xCoord.toBigInteger()
                && left.normalize().yCoord.toBigInteger() == right.normalize().yCoord.toBigInteger()
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

    val result: Boolean             = blind.verify(sig, blindedData.R, m, keyPair.publicKey)
    println(result)
    assert(result)
}
