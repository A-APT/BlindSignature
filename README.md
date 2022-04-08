## BlindSignature-Kotlin
Blind Signature over `Secp256k1`, based on this paper
> *"[New Blind Signature Schemes Based on the (Elliptic Curve) Discrete Logarithm Problem](https://sci-hub.st/10.1109/iccke.2013.6682844)"* by Hamid Mala & Nafiseh Nezhadansari.

**WARNING**: this repo is experimental, do not use in production.

## How to
Add it in your root build.gradle at the end of repositories:

	allprojects {
		repositories {
			...
			maven { url 'https://jitpack.io' }
		}
	}
Step 2. Add the dependency

	dependencies {
	        implementation 'com.github.A-APT:BlindSignature:Tag'
	}
  
## Usage
See *[test code](https://github.com/A-APT/BlindSignature/blob/32089320ee1dc6aa45df996c7f84f8d62a184a5a/src/test/kotlin/BlindSecp256k1Test.kt)* for usage
