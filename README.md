![screen shot 2016-11-06 at 8 49 01 
am](https://cloud.githubusercontent.com/assets/22229007/20038229/f349cd52-a3fd-11e6-86a4-817bca094284.png)

<br>it's easier to hide something small in plain sight, isn't it?<br>
and the body is a lot more of a digital brick without the header 
attached...<br>
here's an example (click this issue, download the image): <br>
![test](https://cloud.githubusercontent.com/assets/22229007/20038869/ce8fabf2-a408-11e6-98bb-9a4d23569ed1.jpg)
<br>
save it in "rotor/src/testing.jpg", the name doesn't matter, really<br>
now get yourself a good old fashioned steganography tool, jphide and 
seek:<br>
https://github.com/h3xx/jphs<br>
go in to the "rotor/src" directory and run "jpseek testing.jpg 
test.enc.key"<br>
the password is "test.enc.key", since we're really just hiding that 
there's another file here, not the contents<br>
that should elicit a file called "test.enc.key" which is the NTRU 
encrypted header that goes to "test.enc". now run "rotor --infile 
test.enc --dec --ext"<br>
the password to the enclosed keypair is "t3strotor". look in the file you 
just decrypted, "test", it should be a copy of rotor.c.<br>
the advantage here is, without that header, you'd have a file, test.enc, 
that is a headerless blob of three combined ciphers - Salsa20, NTRU and 
then SHAKE 256. without that header, pretty hopeless even should you have 
the private key. and the header is small enough, i hid it in that jpg and 
left it on github for you in the issues. there's plenty of other ways to 
use that feature, this is just one.<br>

