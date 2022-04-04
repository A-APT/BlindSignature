import org.junit.jupiter.api.Test
import java.math.BigInteger
import kotlin.test.assertEquals

class EllipticCurveTest {

    // EllipticCurve: secp256k1
    private val curve: EllipticCurve = EllipticCurve()
    private val G: Point = Point(curve.Gx, curve.Gy)

    @Test
    fun is_isOnCurve_works_ok() {
        assertEquals(true, curve.isOnCurve(G))
        assertEquals(false, curve.isOnCurve(Point(BigInteger.TEN, BigInteger.TEN)))
    }

    @Test
    fun is_add_works_on_doubling() {
        val G2 = curve.add(G, G) // 2G
        assertEquals(true, curve.isOnCurve(G2))
    }

    @Test
    fun is_add_works_on_addition() {
        val G2 = curve.add(G, G) // 2G=G+G
        val G3 = curve.add(G, G2) // 3G=G+G+G
        assertEquals(true, curve.isOnCurve(G3))
    }

    @Test
    fun is_mul_works_ok_on_3G() {
        val G2 = curve.add(G, G) // 2G=G+G
        val G3 = curve.add(G, G2) // 3G=G+G+G
        val result = curve.mul(BigInteger.valueOf(3)) // 3G
        assertEquals(G3.x, result.x)
        assertEquals(G3.y, result.y)
    }

    @Test
    fun is_mul_works_ok_on_4G() {
        val G2 = curve.add(G, G) // 2G=G+G
        val G3 = curve.add(G, G2) // 3G=G+G+G
        val G4 = curve.add(G, G3) // 4G=G+G+G+G
        val result = curve.mul(BigInteger.valueOf(4), G) // 4G
        assertEquals(G4.x, result.x)
        assertEquals(G4.y, result.y)
    }

}
