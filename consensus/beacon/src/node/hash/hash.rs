use aes::{cipher::{generic_array::GenericArray, KeyInit, BlockEncrypt}, Aes128Enc};

pub struct HashState{
    pub aes0: Aes128Enc,
    pub aes1: Aes128Enc,
    pub aes2: Aes128Enc
}

impl HashState{
    pub fn new(key0: [u8;16],key1: [u8;16], key2: [u8;16])-> HashState{
        let key0 = GenericArray::from(key0);
        let key1 = GenericArray::from(key1);
        let key2 = GenericArray::from(key2);
        
        let aes_state = HashState{
            aes0: Aes128Enc::new(&key0),
            aes1: Aes128Enc::new(&key1),
            aes2: Aes128Enc::new(&key2)
        };
        aes_state
    }

    pub fn hash_two(&self, one: [u8;32],two:[u8;32])->[u8;32]{
        let mut x_11 = [0u8;16];
        let mut x_12 = [0u8;16];
        for i in 0..16{
            x_11[i] = one[i]+2*two[i];
            x_12[i] = one[16+i]+2*two[16+i];
        }
        let blk_11 = GenericArray::from(x_11);
        let blk_12 = GenericArray::from(x_12);
        self.aes0.encrypt_blocks(&mut [blk_11,blk_12]);

        let mut x_21 = [0u8;16];
        let mut x_22 = [0u8;16];
        for i in 0..16{
            x_21[i] = 2*one[i]+2*two[i]+blk_11[i];
            x_22[i] = 2*one[16+i]+2*two[16+i]+blk_12[i];
        }
        let blk_21 = GenericArray::from(x_21);
        let blk_22 = GenericArray::from(x_22);
        self.aes1.encrypt_blocks(&mut [blk_21,blk_22]);

        let mut x_31 = [0u8;16];
        let mut x_32 = [0u8;16];
        
        for i in 0..16{
            x_31[i] = 2*one[i]+two[i]+blk_21[i];
            x_32[i] = 2*one[16+i]+two[16+i]+blk_22[i];
        }
        let blk_31 = GenericArray::from(x_31);
        let blk_32 = GenericArray::from(x_32);
        self.aes2.encrypt_blocks(&mut [blk_31,blk_32]);

        let mut w_1 = [0u8;32];
        for i in 0..16{
            w_1[i] = one[i]+blk_11[i]+blk_21[i]+2*blk_31[i];
        }
        for i in 0..16{
            w_1[16+i] = one[16+i]+blk_12[i]+blk_22[i]+2*blk_32[i];
        }
        return w_1;
    }
}