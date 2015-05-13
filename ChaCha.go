package main

import "fmt"

// ChaCha20 algorithm and test vector from https://tools.ietf.org/html/draft-agl-tls-chacha20poly1305-04

func quarterround(a, b, c, d uint32) (ra, rb, rc, rd uint32) {

	// quarter-round function performs 4 additions, 4 XORs and 4 bitwise left rotations between 4 choosen uint32 value
	a += b
	d ^= a
	d = d<<16 | d>>16 // this is a bitwise left rotation

	c += d
	b ^= c
	b = b<<12 | b>>20 // this is a bitwise left rotation

	a += b
	d ^= a
	d = d<<8 | d>>24 // this is a bitwise left rotation

	c += d
	b ^= c
	b = b<<7 | b>>25 // this is a bitwise left rotation

	return a, b, c, d
}

func ChaChaInit(chachaGrid *[16]uint32, key *[32]byte, nonce *[8]byte) {
	var i, j uint

	// ChaCha20 uses a 4 x 4 grid of uint32:
	//
	//   +------------+------------+------------+------------+
	//   | const    0 | constant 1 | constant 2 | constant 3 |
	//   | 0x61707865 | 0x3320646e | 0x79622d32 | 0x6b206574 |
	//   +------------+------------+------------+------------+
	//   | key      4 | key      5 | key      6 | key      7 |
	//   +------------+------------+------------+------------+
	//   | key      8 | key      9 | key     10 | key     11 |
	//   +------------+------------+------------+------------+
	//   | block   12 | block   13 | nonce   14 | nonce   15 |
	//   +------------+------------+------------+------------+
	//
	// The first four input words are constants: (0x61707865, 0x3320646e, 0x79622d32, 0x6b206574).
	//
	// Input words 4 through 11 are taken from the 256-bit key by reading the bytes in little-endian order, in 4-byte chunks.
	//
	// Input words 12 and 13 are a block counter, with word 12 overflowing into word 13. The block counter words are initially zero.
	//
	// Lastly, words 14 and 15 are taken from an 8-byte nonce, again by reading the bytes in little-endian order, in 4-byte chunks.

	// constants
	chachaGrid[0] = 0x61707865
	chachaGrid[1] = 0x3320646e
	chachaGrid[2] = 0x79622d32
	chachaGrid[3] = 0x6b206574

	// 256 bits key as 8 Little Endian uint32
	for j = 0; j < 8; j++ {
		chachaGrid[j+4] = 0
		for i = 0; i < 4; i++ {
			chachaGrid[j+4] += uint32(key[j*4+i]) << (8 * i)
		}
	}

	// block counter
	chachaGrid[12] = 0
	chachaGrid[13] = 0

	// nonce as 2 consecutives Little Endian uint32
	for j = 0; j < 2; j++ {
		chachaGrid[j+14] = 0
		for i = 0; i < 4; i++ {
			chachaGrid[j+14] += uint32(nonce[j*4+i]) << (8 * i)
		}
	}
}

func ChaCha20(keystream *[64]byte, chachaGrid *[16]uint32) {
	var x [16]uint32
	var j uint32

	// chacha use a 4 x 4 grid of uint32:
	//
	//   +-----+-----+-----+-----+
	//   | x0  | x1  | x2  | x3  |
	//   +-----+-----+-----+-----+
	//   | x4  | x5  | x6  | x7  |
	//   +-----+-----+-----+-----+
	//   | x8  | x9  | x10 | x11 |
	//   +-----+-----+-----+-----+
	//   | x12 | x13 | x14 | x15 |
	//   +-----+-----+-----+-----+
	for i := 0; i < 16; i++ {
		x[i] = chachaGrid[i]
	}

	// ChaCha20 consists of 20 rounds, alternating between "column" rounds and "diagonal" rounds.
	// Each round applies the "quarterround" function four times, to a different set of words each time.
	for i := 0; i < 10; i++ {

		// QUARTER-ROUND on column 1:
		//
		//   +-----+-----+-----+-----+
		//   | x0  |     |     |     |
		//   +-----+-----+-----+-----+
		//   | x4  |     |     |     |
		//   +-----+-----+-----+-----+
		//   | x8  |     |     |     |
		//   +-----+-----+-----+-----+
		//   | x12 |     |     |     |
		//   +-----+-----+-----+-----+
		//
		x[0], x[4], x[8], x[12] = quarterround(x[0], x[4], x[8], x[12])

		// QUARTER-ROUND on column 2:
		//
		//   +-----+-----+-----+-----+
		//   |     | x1  |     |     |
		//   +-----+-----+-----+-----+
		//   |     | x5  |     |     |
		//   +-----+-----+-----+-----+
		//   |     | x9  |     |     |
		//   +-----+-----+-----+-----+
		//   |     | x13 |     |     |
		//   +-----+-----+-----+-----+
		//
		x[1], x[5], x[9], x[13] = quarterround(x[1], x[5], x[9], x[13])

		// QUARTER-ROUND on column 3:
		//
		//   +-----+-----+-----+-----+
		//   |     |     | x2  |     |
		//   +-----+-----+-----+-----+
		//   |     |     | x6  |     |
		//   +-----+-----+-----+-----+
		//   |     |     | x10 |     |
		//   +-----+-----+-----+-----+
		//   |     |     | x14 |     |
		//   +-----+-----+-----+-----+
		//
		x[2], x[6], x[10], x[14] = quarterround(x[2], x[6], x[10], x[14])

		// QUARTER-ROUND on column 4:
		//
		//   +-----+-----+-----+-----+
		//   |     |     |     | x3  |
		//   +-----+-----+-----+-----+
		//   |     |     |     | x7  |
		//   +-----+-----+-----+-----+
		//   |     |     |     | x11 |
		//   +-----+-----+-----+-----+
		//   |     |     |     | x15 |
		//   +-----+-----+-----+-----+
		//
		x[3], x[7], x[11], x[15] = quarterround(x[3], x[7], x[11], x[15])

		// QUARTER-ROUND on diagonal 1:
		//
		//   +-----+-----+-----+-----+
		//   | x0  |     |     |     |
		//   +-----+-----+-----+-----+
		//   |     | x5  |     |     |
		//   +-----+-----+-----+-----+
		//   |     |     | x10 |     |
		//   +-----+-----+-----+-----+
		//   |     |     |     | x15 |
		//   +-----+-----+-----+-----+
		//
		x[0], x[5], x[10], x[15] = quarterround(x[0], x[5], x[10], x[15])

		// QUARTER-ROUND on diagonal 2:
		//
		//   +-----+-----+-----+-----+
		//   |     | x1  |     |     |
		//   +-----+-----+-----+-----+
		//   |     |     | x6  |     |
		//   +-----+-----+-----+-----+
		//   |     |     |     | x11 |
		//   +-----+-----+-----+-----+
		//   | x12 |     |     |     |
		//   +-----+-----+-----+-----+
		//
		x[1], x[6], x[11], x[12] = quarterround(x[1], x[6], x[11], x[12])

		// QUARTER-ROUND on diagonal 3:
		//
		//   +-----+-----+-----+-----+
		//   |     |     | x2  |     |
		//   +-----+-----+-----+-----+
		//   |     |     |     | x7  |
		//   +-----+-----+-----+-----+
		//   | x8  |     |     |     |
		//   +-----+-----+-----+-----+
		//   |     | x13 |     |     |
		//   +-----+-----+-----+-----+
		//
		x[2], x[7], x[8], x[13] = quarterround(x[2], x[7], x[8], x[13])

		// QUARTER-ROUND on diagonal 4:
		//
		//   +-----+-----+-----+-----+
		//   |     |     |     | x3  |
		//   +-----+-----+-----+-----+
		//   | x4  |     |     |     |
		//   +-----+-----+-----+-----+
		//   |     | x9  |     |     |
		//   +-----+-----+-----+-----+
		//   |     |     | x14 |     |
		//   +-----+-----+-----+-----+
		//
		x[3], x[4], x[9], x[14] = quarterround(x[3], x[4], x[9], x[14])
	}

	// After 20 rounds of the above processing, the original 16 input words are added to the 16 words to form the 16 output words.
	for i := 0; i < 16; i++ {
		x[i] += chachaGrid[i]
	}

	// The 64 output bytes are generated from the 16 output words by serialising them in little-endian order and concatenating the results.
	for i := 0; i < 64; i += 4 {
		j = x[i>>2]
		keystream[i] = byte(j)
		keystream[i+1] = byte(j >> 8)
		keystream[i+2] = byte(j >> 16)
		keystream[i+3] = byte(j >> 24)
	}

	// Input words 12 and 13 are a block counter, with word 12 overflowing into word 13.
	chachaGrid[12]++
	if chachaGrid[12] == 0 {
		chachaGrid[13]++
	}
}

func main() {
	var chachaGrid [16]uint32
	var keystream [64]byte

	var key [32]byte
	var nonce [8]byte

	// ChaCha20 Test vectors from https://tools.ietf.org/html/draft-agl-tls-chacha20poly1305-04

	ChaChaInit(&chachaGrid, &key, &nonce)
	ChaCha20(&keystream, &chachaGrid)
	fmt.Printf("\nkey        : %x\nnonce      : %x\nkey-stream : %x\n", key, nonce, keystream)
	fmt.Printf("Waiting val: 76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7da41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669b2ee6586\n")

	key[31] = 1
	ChaChaInit(&chachaGrid, &key, &nonce)
	ChaCha20(&keystream, &chachaGrid)
	fmt.Printf("\nkey        : %x\nnonce      : %x\nkey-stream : %x\n", key, nonce, keystream)
	fmt.Printf("Waiting val: 4540f05a9f1fb296d7736e7b208e3c96eb4fe1834688d2604f450952ed432d41bbe2a0b6ea7566d2a5d1e7e20d42af2c53d792b1c43fea817e9ad275ae546963\n")

	key[31] = 0
	nonce[7] = 1
	ChaChaInit(&chachaGrid, &key, &nonce)
	ChaCha20(&keystream, &chachaGrid)
	fmt.Printf("\nkey        : %x\nnonce      : %x\nkey-stream : %x\n", key, nonce, keystream)
	fmt.Printf("Waiting val: de9cba7bf3d69ef5e786dc63973f653a0b49e015adbff7134fcb7df137821031e85a050278a7084527214f73efc7fa5b5277062eb7a0433e445f41e31afab757\n")

	nonce[7] = 0
	nonce[0] = 1
	ChaChaInit(&chachaGrid, &key, &nonce)
	ChaCha20(&keystream, &chachaGrid)
	fmt.Printf("\nkey        : %x\nnonce      : %x\nkey-stream : %x\n", key, nonce, keystream)
	fmt.Printf("Waiting val: ef3fdfd6c61578fbf5cf35bd3dd33b8009631634d21e42ac33960bd138e50d32111e4caf237ee53ca8ad6426194a88545ddc497a0b466e7d6bbdb0041b2f586b\n")

	key = [32]byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0X09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0X19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f}
	nonce = [8]byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07}
	ChaChaInit(&chachaGrid, &key, &nonce)
	ChaCha20(&keystream, &chachaGrid)
	fmt.Printf("\nkey        : %x\nnonce      : %x\nkey-stream : %x\n", key, nonce, keystream)
	ChaCha20(&keystream, &chachaGrid)
	fmt.Printf("             %x\n", keystream)
	ChaCha20(&keystream, &chachaGrid)
	fmt.Printf("             %x\n", keystream)
	ChaCha20(&keystream, &chachaGrid)
	fmt.Printf("             %x\n", keystream)
	fmt.Printf("Waiting val: f798a189f195e66982105ffb640bb7757f579da31602fc93ec01ac56f85ac3c134a4547b733b46413042c9440049176905d3be59ea1c53f15916155c2be8241a\n")
	fmt.Printf("             38008b9a26bc35941e2444177c8ade6689de95264986d95889fb60e84629c9bd9a5acb1cc118be563eb9b3a4a472f82e09a7e778492b562ef7130e88dfe031c7\n")
	fmt.Printf("             9db9d4f7c7a899151b9a475032b63fc385245fe054e3dd5a97a5f576fe064025d3ce042c566ab2c507b138db853e3d6959660996546cc9c4a6eafdc777c040d7\n")
	fmt.Printf("             0eaf46f76dad3979e5c5360c3317166a1c894c94a371876a94df7628fe4eaaf2ccb27d5aaae0ad7ad0f9d4b6ad3b54098746d4524d38407a6deb3ab78fab78c9\n")
}
