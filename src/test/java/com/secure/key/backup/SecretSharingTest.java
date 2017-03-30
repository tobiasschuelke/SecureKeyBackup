package com.secure.key.backup;

import org.junit.Assert;
import org.junit.Test;

public class SecretSharingTest {

    @Test
    public void backupRestoreSuccessfully() {
        String secretOriginal = "My password";

        Container container = SecretSharing.newContainer();
        container.setMinimumRecoverParts(5);
        container.setTotalParts(10);
        KeyPart[] keyParts = container.splitPrivateKey();

        Backup backup = container.newBackup();

        backup.encrypt(secretOriginal);
        String encryptedBackup = backup.getEncryptedData();

        // backup and container created
        // distribute key parts, save encrypted backup and minimum/total key part numbers
        //
        // next step: restore backup

        String secretRestored = container.restoreBackup(keyParts, encryptedBackup);

        Assert.assertEquals(secretOriginal, secretRestored);
    }
}
