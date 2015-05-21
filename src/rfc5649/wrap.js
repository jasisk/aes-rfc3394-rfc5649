import { createCipheriv } from 'crypto';
import assert from 'assert';

const AIV_CONSTANT = new Buffer('A65959A6', 'hex');


export default function wrap(plaintext, kek) {
    assert(Buffer.isBuffer(plaintext), 'plaintext must be a Buffer');
    assert(Buffer.isBuffer(kek), 'kek must be a Buffer');
    
    let aiv = createAIV(plaintext);
    let paddedText = padText(plaintext);

    if (plaintext.length <= 8) {
        let algorithm, cipher, ciphertext;
        let constructed = Buffer.concat([aiv, paddedText]);
        algorithm = `aes-${kek.length * 8}-ecb`;
        
        cipher = createCipheriv(algorithm, kek, '');
        cipher.setAutoPadding(false);
        ciphertext = Buffer.concat([cipher.update(constructed), cipher.final()]);
        
        return ciphertext;
    } else {
        // RFC3394(aiv, paddedText);
    }
}


function padText(plaintext) {
    // pad to nearest 64b block
    let size = (plaintext.length + 7) & ~7;
    let padded = new Buffer(size).fill(0);
    plaintext.copy(padded);
    
    return padded;
}

function createAIV(plaintext) {
    let aiv = new Buffer(8);

    AIV_CONSTANT.copy(aiv);
    aiv.writeUInt32BE(plaintext.length, 4);
    
    return aiv;
}
