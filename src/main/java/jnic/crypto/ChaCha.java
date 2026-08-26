package jnic.crypto;

import java.util.Random;

/** Build-side ChaCha20 keystream XOR (RFC 8439), used to encrypt string literals. */
public final class ChaCha {

    private static final int[] SIGMA = {0x61707865, 0x3320646e, 0x79622d32, 0x6b206574};

    /** In-place XOR of data with the ChaCha20 keystream starting at {@code counter}. */
    public static void xor(byte[] key32, int counter, byte[] nonce12, byte[] data, int off, int len) {
        int[] st = new int[16];
        System.arraycopy(SIGMA, 0, st, 0, 4);
        for (int i = 0; i < 8; i++) st[4 + i] = le(key32, i * 4);
        st[12] = counter;
        for (int i = 0; i < 3; i++) st[13 + i] = le(nonce12, i * 4);
        int p = off, end = off + len;
        while (p < end) {
            int[] x = st.clone();
            for (int r = 0; r < 10; r++) {
                qr(x, 0, 4, 8, 12); qr(x, 1, 5, 9, 13); qr(x, 2, 6, 10, 14); qr(x, 3, 7, 11, 15);
                qr(x, 0, 5, 10, 15); qr(x, 1, 6, 11, 12); qr(x, 2, 7, 8, 13); qr(x, 3, 4, 9, 14);
            }
            int n = Math.min(64, end - p);
            for (int i = 0; i < n; i++) {
                int word = x[i >> 2] + st[i >> 2];
                int kb = (word >>> ((i & 3) * 8)) & 0xFF;
                data[p + i] ^= (byte) kb;
            }
            st[12]++;
            p += n;
        }
    }

    private static void qr(int[] x, int a, int b, int c, int d) {
        x[a] += x[b]; x[d] ^= x[a]; x[d] = Integer.rotateLeft(x[d], 16);
        x[c] += x[d]; x[b] ^= x[c]; x[b] = Integer.rotateLeft(x[b], 12);
        x[a] += x[b]; x[d] ^= x[a]; x[d] = Integer.rotateLeft(x[d], 8);
        x[c] += x[d]; x[b] ^= x[c]; x[b] = Integer.rotateLeft(x[b], 7);
    }

    private static int le(byte[] b, int o) {
        return (b[o] & 0xFF) | ((b[o + 1] & 0xFF) << 8) | ((b[o + 2] & 0xFF) << 16) | ((b[o + 3] & 0xFF) << 24);
    }

    private ChaCha() {}
}
