package com.secure.key.backup;

import java.io.UnsupportedEncodingException;
import java.security.Key;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.List;

/**
 * Implementation of {@link Container} interface.
 */
public class ContainerImp implements Container {
    protected static final String UTF_8 = "UTF-8";

    protected String mName = null;
    protected int mMinimumRecoverKeys = -1;
    protected int mTotalParts;
    protected long mTimestamp;

    protected PublicKey mPublicKey;

    @Override
    public void setName(String name) {
        mName = name;
    }

    @Override
    public void setMinimumRecoverParts(int minimum) {
        mMinimumRecoverKeys = minimum;
    }

    @Override
    public void setTotalParts(int total) {
        mTotalParts = total;
    }

    @Override
    public KeyPart[] splitPrivateKey() {
        mTimestamp = System.currentTimeMillis();

        Key[] keys = Encryption.generateKeys();
        byte[] privateKey = keys[0].getEncoded();
        setPublicKey(keys[1]);

        String[] shamirParts = Shamir.split(privateKey, mTotalParts, mMinimumRecoverKeys);
        KeyPart[] keyParts = new KeyPart[shamirParts.length];

        int i = 0;
        for (String shamirPart : shamirParts) {
            try {
                keyParts[i++] = new KeyPartImp(shamirPart.getBytes(UTF_8), mTimestamp, false);
            } catch (UnsupportedEncodingException e) {
                e.printStackTrace();
            }
        }

        return keyParts;
    }

    @Override
    public String restoreBackup(KeyPart[] keyParts, String encryptedBackup) {
        byte[] privateKeyBytes = restorePrivateKey((KeyPartImp[]) keyParts);;

        BackupImp backup = new BackupImp();
        backup.setPrivateKey(privateKeyBytes);
        backup.decrypt(encryptedBackup);

        return backup.getDecryptedData();
    }

    @Override
    public Backup newBackup() {
        BackupImp backup = new BackupImp();
        backup.setPublicKey(mPublicKey);

        return backup;
    }

    protected byte[] restorePrivateKey(KeyPartImp[] keyParts) {
        List<String> parts = new ArrayList<>();
        for(KeyPart key : keyParts) {
            parts.add(key.getKeyPart());
        }

        return Shamir.join(parts);
    }

    protected void setPublicKey(Key key) {
        mPublicKey = (PublicKey) key;
    }

    @Override
    public PublicKey getPublicKey() {
        return mPublicKey;
    }

    @Override
    public String getName() {
        return mName;
    }

    @Override
    public int getMinimumRecoverParts() {
        return mMinimumRecoverKeys;
    }

    @Override
    public int getTotalRecoverParts() {
        return mTotalParts;
    }
}
