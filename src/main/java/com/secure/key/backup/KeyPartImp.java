package com.secure.key.backup;

import java.io.UnsupportedEncodingException;

/**
 * This is a key or a key part of the user.
 */
public class KeyPartImp implements KeyPart {
    private static final String UTF_8 = "UTF-8";

    protected byte[] mKey;
    protected long mTimestamp;
    protected boolean mIsForeign;

    public KeyPartImp() {

    }

    public KeyPartImp(byte[] key, long timestamp, boolean isForeign) {
        mKey = key;
        mTimestamp = timestamp;
        mIsForeign = isForeign;
    }

    public byte[] getEncoded() {
        return mKey;
    }

    public long getTimestamp() {
        return mTimestamp;
    }

    @Override
    public boolean isForeign() {
        return mIsForeign;
    }

    @Override
    public String getKeyPart() {
        try {
            return new String(mKey, UTF_8);
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        return null;
    }
}
