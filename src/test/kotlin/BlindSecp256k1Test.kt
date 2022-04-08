import org.junit.jupiter.api.Test
import java.math.BigInteger
import kotlin.test.assertEquals

class BlindSecp256k1Test {

    @Test
    fun is_blindsecp256k1_works_well() {
        val blind = BlindSecp256k1()
        val m: ByteArray = "test".encodeToByteArray() // UTF-8
        val keyPair: KeyPair            = blind.generateKeyPair()
        val (k, R_)                     = blind.newRequestParameters()

        val blindedData: BlindedData    = blind.blind(R_, m)
        val blindSig: BigInteger = blind.blindSign(keyPair.privateKey, k, blindedData.blindM)
        val sig: BigInteger = blind.unblind(blindedData.a, blindedData.b, blindSig)

        val result: Boolean             = blind.verify(sig, blindedData.R, m, keyPair.publicKey)
        assertEquals(true, result)
    }

}