 
 var elliptic = require('elliptic'); // tested with version 6.5.6
 var eddsa = elliptic.eddsa;
 
 var ed25519 = new eddsa('ed25519');
 var key = ed25519.keyFromPublic('7d4d0e7f6153a69b6242b522abbee685fda4420f8834b108c3bdae369ef549fa', 'hex');
 
 // [tcId 37] appending 0 byte to signature
 var msg = '54657374';
 var sig =  '7c38e026f29e14aabd059a0f2db8b0cd783040609a8be684db12f82a27774ab07a9155711ecfaf7f99f277bad0c6ae7e39d4eef676573336a5c51eb6f946b30d00';
 console.log(key.verify(msg, sig));
 
 // [tcId 38] removing 0 byte from signature
 msg = '546573743137';
 sig =  '93de3ca252426c95f735cb9edd92e83321ac62372d5aa5b379786bae111ab6b17251330e8f9a7c30d6993137c596007d7b001409287535ac4804e662bc58a3';
 console.log(key.verify(msg, sig));
