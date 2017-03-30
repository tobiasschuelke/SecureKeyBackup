package com.secure.key.backup;

import java.io.UnsupportedEncodingException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;

public class BackupImp implements Backup {
    private static final String UTF_8 = "UTF-8";

    protected String mName;
    protected long mTimestamp;
    protected PublicKey mPublicKey;
    protected PrivateKey mPrivateKey;
    protected byte[] mData;
    protected byte[] mEncryptedData;

    void setPublicKey(PublicKey publicKey) {
        mPublicKey = publicKey;
    }

    public void setPublicKey(byte[] publicKey) {
        mPublicKey = Encryption.getPublicKey(publicKey);
    }

    public void setPrivateKey(byte[] privateKey) {
        mPrivateKey = Encryption.getPrivateKey(privateKey);
    }

    @Override
    public String getName() {
        return mName;
    }

    @Override
    public void setName(String name) {
        mName = name;
    }

    @Override
    public void encrypt(String data) {
        try {
            mData = data.getBytes(UTF_8);
            mEncryptedData = Encryption.encrypt(mPublicKey, mData);
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
    }

    @Override
    public void decrypt(String encryptedData) {
        decrypt(Base64.getDecoder().decode(encryptedData));
    }

    protected void decrypt(byte[] encryptedData) {
        mEncryptedData = encryptedData;

        mData = Encryption.decrypt(mPrivateKey, encryptedData);
    }

    @Override
    public String getDecryptedData() {
        try {
            return new String(mData, UTF_8);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    @Override
    public String getEncryptedData() {
        return Base64.getEncoder().encodeToString(mEncryptedData);
    }

    public long getTimestamp() {
        return mTimestamp;
    }

    public void setTimestamp(long timestamp) {
        mTimestamp = timestamp;
    }
}
