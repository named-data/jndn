/**
 * Copyright (C) 2015-2018 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From code in ndn-cxx by Yingdi Yu <yingdi@cs.ucla.edu>
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

package net.named_data.jndn.security.identity;

import android.database.sqlite.SQLiteDatabase;
import android.database.Cursor;
import android.content.ContentValues;
import java.io.File;
import java.sql.Timestamp;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import net.named_data.jndn.KeyLocator;
import net.named_data.jndn.Name;
import net.named_data.jndn.encoding.EncodingException;
import net.named_data.jndn.security.KeyType;
import net.named_data.jndn.util.Blob;
import net.named_data.jndn.security.SecurityException;
import net.named_data.jndn.security.certificate.IdentityCertificate;

/**
 * AndroidSqlite3IdentityStorage extends IdentityStorage to implement basic
 * storage of identity, public keys and certificates using the
 * android.database.sqlite API.
 */
public class AndroidSqlite3IdentityStorage extends Sqlite3IdentityStorageBase {
  /**
   * Create a new AndroidSqlite3IdentityStorage to use the given full path of
   * the SQLite3 file. This constructor takes the full path instead of just a
   * directory to be more flexible. You can get the default file path from an
   * Android files directory with getDefaultFilePath(context.getFilesDir()).
   * @param databaseFilePath The path of the SQLite file.
   *
   */
  public AndroidSqlite3IdentityStorage(String databaseFilePath)
  {
    construct(databaseFilePath);
  }

  /**
   * Get the default database file path based on the files root. This creates
   * the directory of the default database if it doesn't exist. For example if
   * filesRoot is "/data/data/org.example/files", this returns
   * "/data/data/org.example/files/.ndn/ndnsec-public-info.db".
   * @param filesRoot The root file directory. An Android app can use
   * context.getFilesDir()
   * @return The default file path.
   */
  public static String
  getDefaultFilePath(File filesRoot)
  {
    return getDefaultFilePath(filesRoot.getAbsolutePath());
  }

  /**
   * Get the default database file path based on the files root. This creates
   * the directory of the default database if it doesn't exist.
   * @param filesRoot The root file directory.
   * @return The default file path.
   */
  public static String
  getDefaultFilePath(String filesRoot)
  {
    // NOTE: Use File because java.nio.file.Path is not available before Java 7.
    File identityDir = new File(filesRoot, ".ndn");
    identityDir.mkdirs();
    return new File(identityDir, "ndnsec-public-info.db").getAbsolutePath();
  }

  private void
  construct(String databaseFilePath)
  {
    database_ = SQLiteDatabase.openDatabase
      (databaseFilePath, null,
       SQLiteDatabase.OPEN_READWRITE | SQLiteDatabase.CREATE_IF_NECESSARY);

    // Check if the TpmInfo table exists.
    Cursor cursor = database_.rawQuery(SELECT_MASTER_TPM_INFO_TABLE, null);
    boolean tpmInfoTableExists = false;
    if (cursor.moveToNext())
      tpmInfoTableExists = true;
    cursor.close();

    if (!tpmInfoTableExists)
      database_.execSQL(INIT_TPM_INFO_TABLE);

    // Check if the ID table exists.
    cursor = database_.rawQuery(SELECT_MASTER_ID_TABLE, null);
    boolean idTableExists = false;
    if (cursor.moveToNext())
      idTableExists = true;
    cursor.close();

    if (!idTableExists) {
      database_.execSQL(INIT_ID_TABLE1);
      database_.execSQL(INIT_ID_TABLE2);
    }

    // Check if the Key table exists.
    cursor = database_.rawQuery(SELECT_MASTER_KEY_TABLE, null);
    idTableExists = false;
    if (cursor.moveToNext())
      idTableExists = true;
    cursor.close();

    if (!idTableExists) {
      database_.execSQL(INIT_KEY_TABLE1);
      database_.execSQL(INIT_KEY_TABLE2);
    }

    // Check if the Certificate table exists.
    cursor = database_.rawQuery(SELECT_MASTER_CERT_TABLE, null);
    idTableExists = false;
    if (cursor.moveToNext())
      idTableExists = true;
    cursor.close();

    if (!idTableExists) {
      database_.execSQL(INIT_CERT_TABLE1);
      database_.execSQL(INIT_CERT_TABLE2);
      database_.execSQL(INIT_CERT_TABLE3);
    }
  }

  /**
   * Check if the specified identity already exists.
   * @param identityName The identity name.
   * @return True if the identity exists, otherwise false.
   */
  public final boolean
  doesIdentityExist(Name identityName) throws SecurityException
  {
    Cursor cursor = database_.rawQuery
      (SELECT_doesIdentityExist, new String[] { identityName.toUri() });

    try {
      if (cursor.moveToNext())
        return cursor.getInt(0) > 0;
      else
        return false;
    } finally {
      cursor.close();
    }
  }

  /**
   * Add a new identity. Do nothing if the identity already exists.
   * @param identityName The identity name to be added.
   */
  public final void
  addIdentity(Name identityName) throws SecurityException
  {
    if (doesIdentityExist(identityName))
      return;

    ContentValues values = new ContentValues();
    values.put("identity_name", identityName.toUri());
    if (database_.insert("Identity", null, values) < 0)
      throw new SecurityException
        ("AndroidSqlite3IdentityStorage.addIdentity: SQLite error for insert");
  }

  /**
   * Revoke the identity.
   * @return True if the identity was revoked, false if not.
   */
  public final boolean
  revokeIdentity()
  {
    //TODO:
    return false;
  }

  /**
   * Check if the specified key already exists.
   * @param keyName The name of the key.
   * @return true if the key exists, otherwise false.
   */
  public final boolean
  doesKeyExist(Name keyName) throws SecurityException
  {
    String keyId = keyName.get(-1).toEscapedString();
    Name identityName = keyName.getPrefix(-1);

    Cursor cursor = database_.rawQuery
      (SELECT_doesKeyExist, new String[] { identityName.toUri(), keyId });

    try {
      if (cursor.moveToNext())
        return cursor.getInt(0) > 0;
      else
        return false;
    } finally {
      cursor.close();
    }
  }

  /**
   * Add a public key to the identity storage. Also call addIdentity to ensure
   * that the identityName for the key exists. However, if the key already
   * exists, do nothing.
   * @param keyName The name of the public key to be added.
   * @param keyType Type of the public key to be added.
   * @param publicKeyDer A blob of the public key DER to be added.
   */
  public final void
  addKey(Name keyName, KeyType keyType, Blob publicKeyDer) throws SecurityException
  {
    if (keyName.size() == 0)
      return;

    if (doesKeyExist(keyName))
      return;

    String keyId = keyName.get(-1).toEscapedString();
    Name identityName = keyName.getPrefix(-1);

    addIdentity(identityName);

    ContentValues values = new ContentValues();
    values.put("identity_name", identityName.toUri());
    values.put("key_identifier", keyId);
    values.put("key_type", keyType.getNumericType());
    values.put("public_key", publicKeyDer.getImmutableArray());
    if (database_.insert("Key", null, values) < 0)
      throw new SecurityException
          ("AndroidSqlite3IdentityStorage.addKey: SQLite error for insert");
  }

  /**
   * Get the public key DER blob from the identity storage.
   * @param keyName The name of the requested public key.
   * @return The DER Blob.
   * @throws SecurityException if the key doesn't exist.
   */
  public final Blob
  getKey(Name keyName) throws SecurityException
  {
    if (keyName.size() == 0)
      throw new SecurityException
        ("AndroidSqlite3IdentityStorage.getKey: Empty keyName");

    String keyId = keyName.get(-1).toEscapedString();
    Name identityName = keyName.getPrefix(-1);

    Cursor cursor = database_.rawQuery
      (SELECT_getKey, new String[] { identityName.toUri(), keyId });
    try {
      if (cursor.moveToNext())
        return new Blob(cursor.getBlob(0));
      else
        throw new SecurityException
          ("AndroidSqlite3IdentityStorage.getKey: The key does not exist");
    } finally {
      cursor.close();
    }
  }

  /**
   * In table Key, set 'active' to isActive for the keyName.
   * @param keyName The name of the key.
   * @param isActive The value for the 'active' field.
   */
  protected void
  updateKeyStatus(Name keyName, boolean isActive) throws SecurityException
  {
    String keyId = keyName.get(-1).toEscapedString();
    Name identityName = keyName.getPrefix(-1);

    ContentValues values = new ContentValues();
    values.put("active", isActive ? 1 : 0);
    database_.update
      ("Key", values, WHERE_updateKeyStatus,
       new String[] { identityName.toUri(), keyId });
  }

  /**
   * Check if the specified certificate already exists.
   * @param certificateName The name of the certificate.
   * @return True if the certificate exists, otherwise false.
   */
  public final boolean
  doesCertificateExist(Name certificateName) throws SecurityException
  {
    Cursor cursor = database_.rawQuery
      (SELECT_doesCertificateExist, new String[] { certificateName.toUri() });

    try {
      if (cursor.moveToNext())
        return cursor.getInt(0) > 0;
      else
        return false;
    } finally {
      cursor.close();
    }
  }

  /**
   * Add a certificate to the identity storage. Also call addKey to ensure that
   * the certificate key exists. If the certificate is already installed, don't
   * replace it.
   * @param certificate The certificate to be added.  This makes a copy of the
   * certificate.
   */
  public final void
  addCertificate(IdentityCertificate certificate) throws SecurityException
  {
    Name certificateName = certificate.getName();
    Name keyName = certificate.getPublicKeyName();

    addKey(keyName, certificate.getPublicKeyInfo().getKeyType(),
           certificate.getPublicKeyInfo().getKeyDer());

    if (doesCertificateExist(certificateName))
      return;

    // Insert the certificate.
    ContentValues values = new ContentValues();
    values.put("cert_name", certificateName.toUri());
    Name signerName = KeyLocator.getFromSignature
      (certificate.getSignature()).getKeyName();
    values.put("cert_issuer", signerName.toUri());
    String keyId = keyName.get(-1).toEscapedString();
    Name identity = keyName.getPrefix(-1);
    values.put("identity_name", identity.toUri());
    values.put("key_identifier", keyId);
    values.put
      ("not_before",
       dateFormat_.format(new Timestamp((long)certificate.getNotBefore())));
    values.put
      ("not_after",
       dateFormat_.format(new Timestamp((long) certificate.getNotAfter())));
    // wireEncode returns the cached encoding if available.
    values.put("certificate_data", certificate.wireEncode().getImmutableArray());

    if (database_.insert("Certificate", null, values) < 0)
      throw new SecurityException
          ("AndroidSqlite3IdentityStorage.addCertificate: SQLite error for insert");
  }

  /**
   * Get a certificate from the identity storage.
   * @param certificateName The name of the requested certificate.
   * @return The requested certificate.
   * @throws SecurityException if the certificate doesn't exist.
   */
  public final IdentityCertificate
  getCertificate(Name certificateName) throws SecurityException
  {
    if (doesCertificateExist(certificateName)) {
      Cursor cursor = database_.rawQuery
        (SELECT_getCertificate, new String[] { certificateName.toUri() });

      IdentityCertificate certificate = new IdentityCertificate();
      try {
        if (cursor.moveToNext()) {
          try {
            certificate.wireDecode(new Blob(cursor.getBlob(0)));
          } catch (EncodingException ex) {
            throw new SecurityException
              ("AndroidSqlite3IdentityStorage: Error decoding certificate data: " + ex);
          }
        }
        else
          throw new SecurityException
            ("AndroidSqlite3IdentityStorage.getKey: The certificate does not exist");
      } finally {
        cursor.close();
      }

      return certificate;
    }
    else
      return new IdentityCertificate();
  }

  /**
   * Get the TPM locator associated with this storage.
   * @return The TPM locator.
   * @throws SecurityException if the TPM locator doesn't exist.
   */
  public final String
  getTpmLocator() throws SecurityException
  {
    Cursor cursor = database_.rawQuery(SELECT_getTpmLocator, null);

    try {
      if (cursor.moveToNext())
        return cursor.getString(0);
      else
        throw new SecurityException
          ("AndroidSqlite3IdentityStorage.getTpmLocator: TPM info does not exist");
    } finally {
      cursor.close();
    }
  }

  /*****************************************
   *           Get/Set Default             *
   *****************************************/

  /**
   * Get the default identity.
   * @return The name of default identity.
   * @throws SecurityException if the default identity is not set.
   */
  public final Name
  getDefaultIdentity() throws SecurityException
  {
    Cursor cursor = database_.rawQuery(SELECT_getDefaultIdentity, null);

    try {
      if (cursor.moveToNext())
        return new Name(cursor.getString(0));
      else
        throw new SecurityException
          ("AndroidSqlite3IdentityStorage.getDefaultIdentity: The default identity is not defined");
    } finally {
      cursor.close();
    }
  }

  /**
   * Get the default key name for the specified identity.
   * @param identityName The identity name.
   * @return The default key name.
   * @throws SecurityException if the default key name for the identity is not set.
   */
  public final Name
  getDefaultKeyNameForIdentity(Name identityName) throws SecurityException
  {
    Cursor cursor = database_.rawQuery
      (SELECT_getDefaultKeyNameForIdentity,
       new String[] { identityName.toUri() });

    try {
      if (cursor.moveToNext())
        return new Name(identityName).append(cursor.getString(0));
      else
        throw new SecurityException
          ("AndroidSqlite3IdentityStorage.getDefaultKeyNameForIdentity: The default key for the identity is not defined");
    } finally {
      cursor.close();
    }
  }

  /**
   * Get the default certificate name for the specified key.
   * @param keyName The key name.
   * @return The default certificate name.
   * @throws SecurityException if the default certificate name for the key name
   * is not set.
   */
  public final Name
  getDefaultCertificateNameForKey(Name keyName) throws SecurityException
  {
    String keyId = keyName.get(-1).toEscapedString();
    Name identityName = keyName.getPrefix(-1);

    Cursor cursor = database_.rawQuery
      (SELECT_getDefaultCertificateNameForKey,
       new String[] { identityName.toUri(), keyId });

    try {
      if (cursor.moveToNext())
        return new Name(cursor.getString(0));
      else
        throw new SecurityException
          ("AndroidSqlite3IdentityStorage.getDefaultCertificateNameForKey: The default certificate for the key name is not defined");
    } finally {
      cursor.close();
    }
  }

  /**
   * Append all the identity names to the nameList.
   * @param nameList Append result names to nameList.
   * @param isDefault If true, add only the default identity name. If false, add
   * only the non-default identity names.
   */
  public void
  getAllIdentities(ArrayList nameList, boolean isDefault)
    throws SecurityException
  {
    String sql = isDefault ? SELECT_getAllIdentities_default_true
        : SELECT_getAllIdentities_default_false;
    Cursor cursor = database_.rawQuery(sql, new String[0]);

    try {
      while (cursor.moveToNext())
        nameList.add(new Name(cursor.getString(0)));
    } finally {
      cursor.close();
    }
  }

  /**
   * Append all the key names of a particular identity to the nameList.
   * @param identityName The identity name to search for.
   * @param nameList Append result names to nameList.
   * @param isDefault If true, add only the default key name. If false, add only
   * the non-default key names.
   */
  public void
  getAllKeyNamesOfIdentity
    (Name identityName, ArrayList nameList, boolean isDefault) throws SecurityException
  {
    String sql = isDefault ? SELECT_getAllKeyNamesOfIdentity_default_true
      : SELECT_getAllKeyNamesOfIdentity_default_false;
    Cursor cursor = database_.rawQuery(sql, new String[] { identityName.toUri() });

    try {
      while (cursor.moveToNext())
        nameList.add
          (new Name(identityName).append(cursor.getString(0)));
    } finally {
      cursor.close();
    }
  }

  /**
   * Append all the certificate names of a particular key name to the nameList.
   * @param keyName The key name to search for.
   * @param nameList Append result names to nameList.
   * @param isDefault If true, add only the default key name. If false, add only
   * the non-default key names.
   */
  public void
  getAllCertificateNamesOfKey
    (Name keyName, ArrayList nameList, boolean isDefault) throws SecurityException
  {
    String sql = isDefault ? SELECT_getAllCertificateNamesOfKey_default_true
        : SELECT_getAllCertificateNamesOfKey_default_false;
    Cursor cursor = database_.rawQuery
      (sql, new String[] { keyName.getPrefix(-1).toUri(),
                           keyName.get(-1).toEscapedString() });

    try {
      while (cursor.moveToNext())
        nameList.add(new Name(cursor.getString(0)));
    } finally {
      cursor.close();
    }
  }

  /**
   * Set the default identity.  If the identityName does not exist, then clear
   * the default identity so that getDefaultIdentity() throws an exception.
   * @param identityName The default identity name.
   */
  public final void
  setDefaultIdentity(Name identityName) throws SecurityException
  {
    // Reset the previous default identity.
    ContentValues values = new ContentValues();
    values.put("default_identity", 0);
    database_.update
      ("Identity", values, WHERE_setDefaultIdentity_reset, null);

    // Set the current default identity.
    values = new ContentValues();
    values.put("default_identity", 1);
    database_.update
      ("Identity", values, WHERE_setDefaultIdentity_set,
       new String[] { identityName.toUri() });
  }

  /**
   * Set a key as the default key of an identity. The identity name is inferred
   * from keyName.
   * @param keyName The name of the key.
   * @param identityNameCheck The identity name to check that the keyName
   * contains the same identity name. If an empty name, it is ignored.
   */
  public final void
  setDefaultKeyNameForIdentity(Name keyName, Name identityNameCheck)
    throws SecurityException
  {
    checkSetDefaultKeyNameForIdentity(keyName, identityNameCheck);

    String keyId = keyName.get(-1).toEscapedString();
    Name identityName = keyName.getPrefix(-1);

    // Reset the previous default Key.
    ContentValues values = new ContentValues();
    values.put("default_key", 0);
    database_.update
      ("Key", values, WHERE_setDefaultKeyNameForIdentity_reset,
       new String[] { identityName.toUri() });

    // Set the current default Key.
    values = new ContentValues();
    values.put("default_key", 1);
    database_.update
      ("Key", values, WHERE_setDefaultKeyNameForIdentity_set,
       new String[] { identityName.toUri(), keyId });
  }

  /**
   * Set the default key name for the specified identity.
   * @param keyName The key name.
   * @param certificateName The certificate name.
   */
  public final void
  setDefaultCertificateNameForKey(Name keyName, Name certificateName)
    throws SecurityException
  {
    String keyId = keyName.get(-1).toEscapedString();
    Name identityName = keyName.getPrefix(-1);

    // Reset the previous default Certificate.
    ContentValues values = new ContentValues();
    values.put("default_cert", 0);
    database_.update
      ("Certificate", values, WHERE_setDefaultCertificateNameForKey_reset,
       new String[] { identityName.toUri(), keyId });

    // Set the current default Certificate.
    values = new ContentValues();
    values.put("default_cert", 1);
    database_.update
      ("Certificate", values, WHERE_setDefaultCertificateNameForKey_set,
       new String[] { identityName.toUri(), keyId, certificateName.toUri() });
  }

  /*****************************************
   *            Delete Methods             *
   *****************************************/

  /**
   * Delete a certificate.
   * @param certificateName The certificate name.
   */
  public void
  deleteCertificateInfo(Name certificateName) throws SecurityException
  {
    if (certificateName.size() == 0)
      return;

    database_.delete
      ("Certificate", WHERE_deleteCertificateInfo,
       new String[] { certificateName.toUri() });
  }

  /**
   * Delete a public key and related certificates.
   * @param keyName The key name.
   */
  public void
  deletePublicKeyInfo(Name keyName) throws SecurityException
  {
    if (keyName.size() == 0)
      return;

    String keyId = keyName.get(-1).toEscapedString();
    Name identityName = keyName.getPrefix(-1);

    database_.delete
      ("Certificate", WHERE_deletePublicKeyInfo,
       new String[] { identityName.toUri(), keyId });
    database_.delete
      ("Key", WHERE_deletePublicKeyInfo,
       new String[] { identityName.toUri(), keyId });
  }

  /**
   * Delete an identity and related public keys and certificates.
   * @param identityName The identity name.
   */
  public void
  deleteIdentityInfo(Name identityName) throws SecurityException
  {
    String identity = identityName.toUri();

    database_.delete
      ("Certificate", WHERE_deleteIdentityInfo, new String[] { identity });
    database_.delete
      ("Key", WHERE_deleteIdentityInfo, new String[] { identity });
    database_.delete
      ("Identity", WHERE_deleteIdentityInfo, new String[] { identity });
  }

  private SQLiteDatabase database_;
  private static final SimpleDateFormat dateFormat_ =
    new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
}
