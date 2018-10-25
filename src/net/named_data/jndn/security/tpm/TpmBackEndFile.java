/**
 * Copyright (C) 2017-2018 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From ndn-cxx security https://github.com/named-data/ndn-cxx/blob/master/src/security/tpm/back-end-file.hpp
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 * A copy of the GNU Lesser General Public License is in the file COPYING.
 */

package net.named_data.jndn.security.tpm;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.ByteBuffer;
import net.named_data.jndn.Name;
import net.named_data.jndn.security.KeyParams;
import net.named_data.jndn.util.Blob;
import net.named_data.jndn.util.Common;

/**
 * TpmBackEndFile extends TpmBackEnd to implement a TPM back-end using
 * on-disk file storage. In this TPM, each private key is stored in a separate
 * file with permission 0400, i.e., owner read-only.  The key is stored in
 * PKCS #1 format in base64 encoding.
 */
public class TpmBackEndFile extends TpmBackEnd {
  /**
   * A TpmBackEndFile.Error extends TpmBackEnd.Error and represents a
   * non-semantic error in backend TPM file processing.
   * Note that even though this is called "Error" to be consistent with the
   * other libraries, it extends the Java Exception class, not Error.
   */
  public static class Error extends TpmBackEnd.Error {
    public Error(String message)
    {
      super(message);
    }
  }

  /**
   * Create a TpmBackEndFile to store files in the default location
   * HOME/.ndn/ndnsec-key-file where HOME is System.getProperty("user.home").
   * This creates the directory if it doesn't exist.
   */
  public TpmBackEndFile()
  {
    keyStorePath_ = new File
      (getDefaultDirecoryPath(Common.getHomeDirectory()));
    keyStorePath_.mkdirs();
  }

  /**
   * Create a TpmBackEndFile to use the given path to store files.
   * @param locationPath The full path of the directory to store private keys.
   * This creates the directory if it doesn't exist. For example, you can get
   * the default directory path from an Android files directory with
   * getDefaultDirecoryPath(context.getFilesDir()) .
   */
  public TpmBackEndFile(String locationPath)
  {
    keyStorePath_ = new File(locationPath);
    keyStorePath_.mkdirs();
  }

  /**
   * Get the default directory path for private keys based on the files root.
   * For example if filesRoot is "/data/data/org.example/files", this returns
   * "/data/data/org.example/files/.ndn/ndnsec-tpm-file".
   * @param filesRoot The root file directory. An Android app can use
   * context.getFilesDir()
   * @return The default directory path.
   */
  public static String
  getDefaultDirecoryPath(File filesRoot)
  {
    return getDefaultDirecoryPath(filesRoot.getAbsolutePath());
  }

  /**
   * Get the default directory path for private keys based on the files root.
   * @param filesRoot The root file directory.
   * @return The default directory path.
   */
  public static String
  getDefaultDirecoryPath(String filesRoot)
  {
    // NOTE: Use File because java.nio.file.Path is not available before Java 7.
    return new File
      (new File(new File(filesRoot), ".ndn"), "ndnsec-key-file").getAbsolutePath();
  }

  public static String
  getScheme() { return "tpm-file"; }

  /**
   * Check if the key with name keyName exists in the TPM.
   * @param keyName The name of the key.
   * @return True if the key exists.
   */
  protected boolean
  doHasKey(Name keyName) throws TpmBackEnd.Error
  {
    if (!toFilePath(keyName).exists())
      return false;

    try {
      loadKey(keyName);
      return true;
    } catch (TpmBackEnd.Error ex) {
      return false;
    }
  }

  /**
   * Get the handle of the key with name keyName.
   * @param keyName The name of the key.
   * @return The handle of the key, or null if the key does not exist.
   */
  protected TpmKeyHandle
  doGetKeyHandle(Name keyName) throws TpmBackEnd.Error
  {
    if (!doHasKey(keyName))
      return null;

    return new TpmKeyHandleMemory(loadKey(keyName));
  }

  /**
   * Create a key for identityName according to params. The created key is
   * named as: /{identityName}/[keyId]/KEY . The key name is set in the returned
   * TpmKeyHandle.
   * @param identityName The name if the identity.
   * @param params The KeyParams for creating the key.
   * @return The handle of the created key.
   * @throws TpmBackEnd.Error if the key cannot be created.
   */
  protected TpmKeyHandle
  doCreateKey(Name identityName, KeyParams params) throws TpmBackEnd.Error
  {
    TpmPrivateKey key;
    try {
      key = TpmPrivateKey.generatePrivateKey(params);
    } catch (TpmPrivateKey.Error ex) {
      throw new TpmBackEnd.Error("Error in TpmPrivateKey.generatePrivateKey: " + ex);
    }
    TpmKeyHandle keyHandle = new TpmKeyHandleMemory(key);

    setKeyName(keyHandle, identityName, params);

    saveKey(keyHandle.getKeyName(), key);
    return keyHandle;
  }

  /**
   * Delete the key with name keyName. If the key doesn't exist, do nothing.
   * @param keyName The name of the key to delete.
   * @throws TpmBackEnd.Error if the deletion fails.
   */
  protected void
  doDeleteKey(Name keyName) throws TpmBackEnd.Error
  {
    toFilePath(keyName).delete();
  }

  /**
   * Get the encoded private key with name keyName in PKCS #8 format, possibly
   * password-encrypted.
   * @param keyName The name of the key in the TPM.
   * @param password The password for encrypting the private key, which should
   * have characters in the range of 1 to 127. If the password is supplied, use
   * it to return a PKCS #8 EncryptedPrivateKeyInfo. If the password is null,
   * return an unencrypted PKCS #8 PrivateKeyInfo.
   * @return The encoded private key.
   * @throws TpmBackEnd.Error if the key does not exist or if the key cannot be
   * exported, e.g., insufficient privileges.
   */
  protected Blob
  doExportKey(Name keyName, ByteBuffer password) throws TpmBackEnd.Error
  {
    TpmPrivateKey key;
    try {
      key = loadKey(keyName);
    } catch (TpmBackEnd.Error ex) {
      throw new TpmBackEnd.Error("Cannot export private key: " + ex);
    }

    try {
      if (password != null)
        return key.toEncryptedPkcs8(password);
      else
        return key.toPkcs8();
    } catch (TpmPrivateKey.Error ex) {
      // We don't expect this since we just decoded it.
      throw new TpmBackEnd.Error("Error PKCS#8 encoding private key: " + ex);
    }
  }

  /**
   * Import an encoded private key with name keyName in PKCS #8 format, possibly
   * password-encrypted.
   * @param keyName The name of the key to use in the TPM.
   * @param pkcs8 The input byte buffer. If the password is supplied, this is a
   * PKCS #8 EncryptedPrivateKeyInfo. If the password is null, this is an
   * unencrypted PKCS #8 PrivateKeyInfo.
   * @param password The password for decrypting the private key, which should
   * have characters in the range of 1 to 127. If the password is supplied, use
   * it to decrypt the PKCS #8 EncryptedPrivateKeyInfo. If the password is null,
   * import an unencrypted PKCS #8 PrivateKeyInfo.
   * @throws TpmBackEnd.Error for an error importing the key.
   */
  protected void
  doImportKey
    (Name keyName, ByteBuffer pkcs8, ByteBuffer password) throws TpmBackEnd.Error
  {
    TpmPrivateKey key = new TpmPrivateKey();
    try {
      if (password  != null)
        key.loadEncryptedPkcs8(pkcs8, password);
      else
        key.loadPkcs8(pkcs8);
    } catch (TpmPrivateKey.Error ex) {
      throw new TpmBackEnd.Error("Cannot import private key: " + ex);
    }

    saveKey(keyName, key);
  }

  /**
   * Load the private key with name keyName from the key file directory.
   * @param keyName The name of the key.
   * @return The key loaded into a TpmPrivateKey.
   */
  TpmPrivateKey
  loadKey(Name keyName) throws TpmBackEnd.Error
  {
    TpmPrivateKey key = new TpmPrivateKey();
    StringBuilder base64 = new StringBuilder();
    try {
      BufferedReader reader = new BufferedReader
        (new FileReader(toFilePath(keyName).getAbsolutePath()));
      // Use "try/finally instead of "try-with-resources" or "using"
      // which are not supported before Java 7.
      try {
        String line = null;
        while ((line = reader.readLine()) != null)
          base64.append(line);
      } finally {
        reader.close();
      }
    }
    catch(FileNotFoundException ex) {
      throw new TpmBackEnd.Error("Error reading private key file: " + ex);
    }
    catch(IOException ex) {
      throw new TpmBackEnd.Error("Error reading private key file: " + ex);
    }

    byte[] pkcs = Common.base64Decode(base64.toString());

    try {
      key.loadPkcs1(ByteBuffer.wrap(pkcs), null);
    } catch (TpmPrivateKey.Error ex) {
      throw new TpmBackEnd.Error("Error decoding private key file: " + ex);
    }
    return key;
  }

  /**
   * Save the private key using keyName into the key file directory.
   * @param keyName The name of the key.
   * @param key The private key to save.
   */
  private void
  saveKey(Name keyName, TpmPrivateKey key) throws TpmBackEnd.Error
  {
    String filePath = toFilePath(keyName).getAbsolutePath();
    String base64;
    try {
      base64 = Common.base64Encode(key.toPkcs1().getImmutableArray(), true);
    } catch (TpmPrivateKey.Error ex) {
      throw new TpmBackEnd.Error("Error encoding private key file: " + ex);
    }

    try {
      BufferedWriter writer = new BufferedWriter(new FileWriter(filePath));
      // Use "try/finally instead of "try-with-resources" or "using"
      // which are not supported before Java 7.
      try {
        writer.write(base64, 0, base64.length());
        writer.flush();
      }
      finally{
        writer.close();
      }
    }
    catch (IOException ex) {
      throw new TpmBackEnd.Error("Error writing private key file: " + ex);
    }
  }

  /**
   * Get the file path for the keyName, which is keyStorePath_ + "/" +
   * hex(sha256(keyName-wire-encoding)) + ".privkey" .
   * @param keyName The name of the key.
   * @return The file path for the key.
   */
  private File
  toFilePath(Name keyName)
  {
    Blob keyEncoding = keyName.wireEncode();
    byte[] digest = Common.digestSha256(keyEncoding.buf());

    return new File(keyStorePath_, new Blob(digest, false).toHex() + ".privkey");
  }

  private File keyStorePath_;
}
