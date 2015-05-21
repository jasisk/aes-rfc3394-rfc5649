import { createDecipheriv } from 'crypto';
import assert from 'assert';

const AIV_CONSTANT = new Buffer('A65959A6', 'hex');


export default function unwrap(ciphertext, kek) {
    assert(Buffer.isBuffer(ciphertext), 'ciphertext must be a Buffer');
    assert(Buffer.isBuffer(kek), 'kek must be a Buffer');

    let inlen, components, key, plaintext;
    

    inlen = ciphertext.length;
    
    // ciphertext must be n>=2 64-bit (16B) blocks
    if (inlen % 8 || inlen < 16) {
        throw new Error('malformed ciphertext');
    }
     
    if (inlen === 16) {
        let algorithm, decipher;

        // decrypt as single AES block (ECB) with kek
        algorithm = `aes-${kek.length * 8}-ecb`;
        decipher = createDecipheriv(algorithm, kek, '');
        decipher.setAutoPadding(false);
        plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    } else {
        // RFC3394(ciphertext, kek)
    }
    
    components = getComponents(plaintext);

    if (!(validAIV(components))) {
        throw new Error('invalid AIV');
    }

    key = components.paddedKey.slice(0, components.mli);
    return key;
}


function getComponents(plaintext) {
    let aiv, paddedKey, constant, mli;

    aiv = plaintext.slice(0, 8); // first 64B
    paddedKey = plaintext.slice(8);
    constant = aiv.slice(0,4); // MSB(32, aiv)
    mli = aiv.readUInt32BE(4); // LSB(32, aiv) (Big-Endian)
    
    return {
        aiv,
        paddedKey,
        constant,
        mli
    }; 
}


function validAIV({aiv, paddedKey, constant, mli}) {
    let n, b, padding;

    // Step 1: validate constant
    if (!(constant.equals(AIV_CONSTANT))) {
        return false;
    }
    
    // Step 2: validate MLI
    n = paddedKey.length / 8;
    if ((mli <= 8 * (n-1)) || (mli > 8 * n)) {
        return false;
    }
    
    // Step 3: check padding
    b = (8 * n) - mli;
    padding = paddedKey.slice(mli, mli + b);

    if (!(padding.equals(new Buffer(b).fill(0)))) {
        return false;
    }
    
    return true;
}
