import java.math.BigInteger

data class Point(var x: BigInteger, var y: BigInteger)

class EllipticCurve( // init parameters with Recommended Parameters secp256k1
    // See SEC 2: Recommended Elliptic Curve Domain Parameters
    // https://www.secg.org/sec2-v2.pdf: 2.4.1 Recommended Parameters secp256k1
    var P: BigInteger = BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16),
    var N: BigInteger = BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16),
    // The curve E: y2 = x3 + ax + b over Fp is defined by
    var a: BigInteger = BigInteger("0000000000000000000000000000000000000000000000000000000000000000", 16),
    var b: BigInteger = BigInteger("0000000000000000000000000000000000000000000000000000000000000007", 16),
    var Gx: BigInteger = BigInteger("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 16), // The base point G
    var Gy: BigInteger = BigInteger("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", 16), // The order n of G
    var BitSize: Int = 256,
) {

    // NOTE: able to use operators instead of function calls when use BigInteger from Kotlin
    // : + instead of add(), - instead of subtract(), etc.

    fun isOnCurve(point: Point): Boolean {
        // y2 = x3 + ax + b
        val y2 = (point.y * point.y).mod(P)
        val x3 = (point.x * point.x * point.x + a * point.x + b).mod(P)
        return y2.compareTo(x3) == 0
    }

    fun add(p1: Point, p2: Point): Point {
        // If one point is at infinity, return the other point.
        // Adding the point at infinity to any point will preserve the other point.
        // signum() returns 0 if the number is 0
        if (p1.x.signum() == 0 && p1.y.signum() == 0) return p2
        if (p2.x.signum() == 0 && p2.y.signum() == 0) return p1

        // calculate using Jacobian
        val z = BigInteger.ONE
        // if point1 == point2, do doubling
        if (p1.x.compareTo(p2.x) == 0 && p1.y.compareTo(p2.y) == 0) {
            val result: Pair<Point, BigInteger> = doubleJacobian(p1, z)
            return affineFromJacobian(result.first, result.second)
        } else {
            val result: Pair<Point, BigInteger> = addJacobian(p1, z, p2, z)
            return affineFromJacobian(result.first, result.second)
        }
    }

    // reverses the Jacobian transform
    private fun affineFromJacobian(point: Point, z: BigInteger): Point {
        if (z.signum() == 0) { // nothing to do
            return point
        }

        val zInv = z.modInverse(P)
        val zInvSq = zInv * zInv
        val resultX: BigInteger = (point.x * zInvSq).mod(P)
        val resultY: BigInteger = (point.y * zInvSq * zInv).mod(P)

        return Point(resultX, resultY)
    }

    private fun addJacobian(p1: Point, z1: BigInteger, p2: Point, z2: BigInteger): Pair<Point, BigInteger> {
        // See http://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-0.html#addition-add-2007-bl

        val z1z1 = (z1 * z1).mod(P)
        val z2z2 = (z2 * z2).mod(P)

        val u1 = (p1.x * z2z2).mod(P)
        val u2 = (p2.x * z1z1).mod(P)

        var h = u2 - u1
        if (h.signum() == -1) h += P // make positive
        var i = h.shiftLeft(1)
        i *= i // I = (2*H)2
        val j = h * i // H*I

        val s1 = (p1.y * z2 * z2z2).mod(P)
        val s2 = (p2.y * z1 * z1z1).mod(P)
        var r = s2.subtract(s1)
        if (r.signum() == -1) r += P // make positive
        r = r.shiftLeft(1) // r = 2*(S2-S1)
        val v = u1 * i

        val x3 = (r * r - j - v - v).mod(P) // X3=r2-j-2*V
        val y3 = (r * (v - x3) - s1 * j * BigInteger.TWO).mod(P) // Y3 = r*(V-X3)-2*S1*J

        var z3 = z1 + z2
        z3 = z3 * z3 - z1z1
        if (z3.signum() == -1) z3 = z3.add(P) // make positive
        z3 -= z2z2
        if (z3.signum() == -1) z3 = z3.add(P) // make positive
        z3 = (z3 * h).mod(P) // Z3 = ((Z1+Z2)2-Z1Z1-Z2Z2)*H

        return Pair(Point(x3, y3), z3)
    }

    private fun doubleJacobian(p1: Point, z: BigInteger): Pair<Point, BigInteger> {
        // See http://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-0.html#doubling-dbl-2009-l

        val a = p1.x * p1.x // x2
        val b = p1.y * p1.y // y2
        val c = b * b       // B2
        var d = p1.x + b
        d = (d * d - a - c) * BigInteger.TWO // D = 2*((X1+B)2-A-C)
        val e = BigInteger.valueOf(3) * a // 3*A
        val f = e * e // E2

        val x3 = (f - d * BigInteger.TWO).mod(P) // X3 = F-2*D
        val y3 = (e * (d - x3) - BigInteger.valueOf(8) * c).mod(P) // Y3 = E*(D-X3)-8*C
        val z3 = (BigInteger.TWO * p1.y * z).mod(P) // Z3 = 2*Y1*Z1

        return Pair(Point(x3, y3), z3)
    }

    // calculate kG = G + G + ... + G (k times)
    fun mul(k: BigInteger): Point {
        return mul(k, Point(Gx, Gy))
    }

    fun mul(k: BigInteger, point: Point): Point {
        val bigLength: Int = k.bitLength()
        var result: Point = Point(BigInteger.ZERO, BigInteger.ZERO)
        for (i in bigLength-1 downTo 0) {
            result = add(result, result)
            if (k.testBit(i)) result = add(result, point)
        }
        return result
    }

}
