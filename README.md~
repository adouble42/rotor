rotor is an experimental NTRU hybrid public key encryption application designed with a very large security margin in mind<br>
NTRU private keys are protected in a stream encrypted with SHAKE-256 behind a memory hardened key derivation function designed to make brute force attacks financially prohibitive.<br>
plaintext is read, and two stream keys are established and saved in NTRU blocks. the plaintext is then read in 170 byte blocks and XOR'd against a SHAKE-256 mask, encrypted with NTRU, and the second stream key is used to encrypt the NTRU blocks with 256 bit Salsa20.<br>
the Salsa20 key is not merely the contents of it's NTRU block, it is the contents of the block, mixed with the NTRU ciphertext of the block, which is then reduced to a 32 byte Salsa20 key for the next block using SHAKE-256. during the initial key derivation an 8 bit nonce is determined using SHAKE and used throughout the rest of decryption.<br>
if one were inconvenienced by the 10x increase in plaintext size, one could remove the NTRU layer beyond the header blocks. personally, i like it the way it is. a solid insurance policy.<br>
this code is regularly built and tested on freebsd, and os x. linux builds may require some modification. enjoy<br><br>


#DicksOutForHarambe