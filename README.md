## BlindSignature-Kotlin
Blind Signature over `Secp256k1`, based on this paper
> *"[New Blind Signature Schemes Based on the (Elliptic Curve) Discrete Logarithm Problem](https://sci-hub.st/10.1109/iccke.2013.6682844)"* by Hamid Mala & Nafiseh Nezhadansari.

**WARNING**: this repo is experimental, do not use in production.

## How to
Add it in your root build.gradle at the end of repositories:

	allprojects {	// * not on buildscript
		repositories {
			...
			maven { url 'https://jitpack.io' } 		// for build.gradle
			maven { url = uri("https://jitpack.io") } 	// for build.gradle.kts
		}
	}
Step 2. Add the dependency

	dependencies {
	        implementation 'com.github.A-APT:BlindSignature:Tag'	 // for build.gradle
		implementation("com.github.A-APT:BlindSignature:Tag")	 // for build.gradle.kts
	}
  
## Usage
See *[test code](https://github.com/A-APT/BlindSignature/blob/5e9816ef3405f35c407cb5bb0e0d486ec95fc6ea/src/test/kotlin/com/aapt/BlindSecp256k1Test.kt)* for usage
