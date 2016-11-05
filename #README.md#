rotor is an experimental NTRU hybrid public key encryption application designed with a very large security margin in mind<br>
NTRU private keys are protected in a stream encrypted with SHAKE-256 behind a memory hardened key derivation function designed to make brute force attacks financially prohibitive.<br>
plaintext is read, and two stream keys are established and saved in NTRU blocks. the plaintext is then read in 170 byte blocks and XOR'd against a SHAKE-256 mask, encrypted with NTRU, and the second stream key is used to encrypt the NTRU blocks with 256 bit Salsa20.<br>
for the Salsa20 stream, during the initial key derivation an 8 bit nonce is determined using SHAKE and used throughout the rest of decryption.<br>
if one were inconvenienced by the 10x increase in plaintext size, one could remove the NTRU layer beyond the header blocks. personally, i like it the way it is. a solid insurance policy, properly used.<br>
it should be noted that rotor is experimental software actively being developed and should be treated as such. there are no guarantees. my confidence is high based on the theory of what i set out to build being sound, but it's tempered by my potential to screw something up and come up short. time will tell, if my confidence is justified. for now, i bet on me. <br>
this code is regularly built and tested on freebsd, and os x. linux builds may require some modification. enjoy<br><br>


#DicksOutForHarambe