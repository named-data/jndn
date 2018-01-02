/**
 * Copyright (C) 2017-2018 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
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

package net.named_data.jndn.security.pib;

import android.database.sqlite.SQLiteDatabase;
import android.database.Cursor;
import android.content.ContentValues;
import android.database.sqlite.SQLiteStatement;
import android.database.sqlite.SQLiteDoneException;
import java.io.File;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.HashSet;
import net.named_data.jndn.Name;
import net.named_data.jndn.encoding.EncodingException;
import net.named_data.jndn.security.v2.CertificateV2;
import net.named_data.jndn.util.Blob;

/**
 * AndroidSqlite3Pib extends PibImpl and is used by the Pib class as an
 * implementation of a PIB using the android.database.sqlite API. All the
 * contents in the PIB are stored in an SQLite3 database file. This provides
 * more persistent storage than PibMemory.
 */
public class AndroidSqlite3Pib extends PibSqlite3Base {
  /**
   * Create a new AndroidSqlite3Pib to work with an SQLite3 file. This assumes
   * that the database directory does not contain a PIB database of an older
   * version.
   * @param databaseDirectoryPath The directory where the database file is
   * located. If the directory does not exist, create it. An Android app can use
   * context.getFilesDir() .
   * @param databaseFilename The name if the database file in the
   * databaseDirectoryPath.
   * @throws PibImpl.Error if initialization fails.
   */
  public AndroidSqlite3Pib
    (String databaseDirectoryPath, String databaseFilename) throws PibImpl.Error
  {
    construct(databaseDirectoryPath, databaseFilename);
  }

  /**
   * Create a new AndroidSqlite3Pib to work with an SQLite3 file. This assumes
   * that the database directory does not contain a PIB database of an older
   * version. Use "pib.db" for the databaseFilename in the databaseDirectoryPath.
   * @param databaseDirectoryPath The directory where the database file is
   * located. If the directory does not exist, create it. An Android app can use
   * context.getFilesDir() .
   * @throws PibImpl.Error if initialization fails.
   */
  public AndroidSqlite3Pib(String databaseDirectoryPath) throws PibImpl.Error
  {
    construct(databaseDirectoryPath, "pib.db");
  }

  private void
  construct(String databaseDirectoryPath, String databaseFilename)
    throws PibImpl.Error
  {
    new File(databaseDirectoryPath).mkdirs();

    File databaseFilePath = new File(databaseDirectoryPath, databaseFilename);
    database_ = SQLiteDatabase.openDatabase
      (databaseFilePath.getAbsolutePath(), null,
       SQLiteDatabase.OPEN_READWRITE | SQLiteDatabase.CREATE_IF_NECESSARY);

    // Initialize the PIB tables.
    database_.execSQL(INITIALIZATION1);
    database_.execSQL(INITIALIZATION2);
    database_.execSQL(INITIALIZATION3);
    database_.execSQL(INITIALIZATION4);
    database_.execSQL(INITIALIZATION5);
    database_.execSQL(INITIALIZATION6);
    database_.execSQL(INITIALIZATION7);
  }

  public static String
  getScheme() { return "pib-sqlite3"; }

  // TpmLocator management.

  /**
   * Set the corresponding TPM information to tpmLocator. This method does not
   * reset the contents of the PIB.
   * @param tpmLocator The TPM locator string.
   * @throws PibImpl.Error for a non-semantic (database access) error.
   */
  public void
  setTpmLocator(String tpmLocator) throws PibImpl.Error
  {
    if (getTpmLocator().equals("")) {
      // The tpmLocator does not exist. Insert it directly.
      ContentValues values = new ContentValues();
      values.put("tpm_locator", tpmLocator);
      if (database_.insert("tpmInfo", null, values) < 0)
        throw new PibImpl.Error("AndroidSqlite3Pib: SQLite error");
    }
    else {
      // Update the existing tpmLocator.
      ContentValues values = new ContentValues();
      values.put("tpm_locator", tpmLocator);
      database_.update("tpmInfo", values, null, null);
    }
  }

  /**
   * Get the TPM Locator.
   * @return The TPM locator string.
   * @throws PibImpl.Error for a non-semantic (database access) error.
   */
  public String
  getTpmLocator() throws PibImpl.Error
  {
    Cursor cursor = database_.rawQuery(SELECT_getTpmLocator, null);

    try {
      if (cursor.moveToNext())
        return cursor.getString(0);
      else
        return "";
    } finally {
      cursor.close();
    }
  }

  // Identity management.

  /**
   * Check for the existence of an identity.
   * @param identityName The name of the identity.
   * @return True if the identity exists, otherwise false.
   * @throws PibImpl.Error for a non-semantic (database access) error.
   */
  public boolean
  hasIdentity(Name identityName) throws PibImpl.Error
  {
    // Use a statement because it allows binding a blob for the query.
    SQLiteStatement statement = database_.compileStatement(SELECT_hasIdentity);
    try {
      statement.bindBlob(1, identityName.wireEncode().getImmutableArray());
      try {
        statement.simpleQueryForLong();
        return true;
      } catch (SQLiteDoneException ex) {
        // No match.
        return false;
      }
    } finally {
      statement.close();
    }
  }

  /**
   * Add the identity. If the identity already exists, do nothing. If no default
   * identity has been set, set the added identity as the default.
   * @param identityName The name of the identity to add. This copies the name.
   * @throws PibImpl.Error for a non-semantic (database access) error.
   */
  public void
  addIdentity(Name identityName) throws PibImpl.Error
  {
    if (!hasIdentity(identityName)) {
      ContentValues values = new ContentValues();
      values.put("identity", identityName.wireEncode().getImmutableArray());
      if (database_.insert("identities", null, values) < 0)
        throw new PibImpl.Error("AndroidSqlite3Pib: SQLite error");
    }

    if (!hasDefaultIdentity())
      setDefaultIdentity(identityName);
  }

  /**
   * Remove the identity and its related keys and certificates. If the default
   * identity is being removed, no default identity will be selected.  If the
   * identity does not exist, do nothing.
   * @param identityName The name of the identity to remove.
   * @throws PibImpl.Error for a non-semantic (database access) error.
   */
  public void
  removeIdentity(Name identityName) throws PibImpl.Error
  {
    byte[] identityBytes = identityName.wireEncode().getImmutableArray();

    // We don't use triggers, so manually delete from keys and certificates.
    // First get the key ids.
    ArrayList<Integer> keyIds = new ArrayList<Integer>();

    // Use a hex literal instead of the ending '?' since rawQuery doesn't allow
    // binding a blob.
    Cursor cursor = database_.rawQuery
      (SELECT_removeIdentity.substring(0, SELECT_removeIdentity.length() - 1) +
       "x'" + identityName.wireEncode().toHex() + "'", null);

    try {
      while (cursor.moveToNext())
        keyIds.add(cursor.getInt(0));
    } finally {
      cursor.close();
    }

    for (int keyId : keyIds)
      database_.execSQL
        (DELETE_removeIdentity_certificates, new Object[] { keyId });

    for (int keyId : keyIds)
      database_.execSQL
        (DELETE_removeIdentity_keys, new Object[] { keyId });

    // Now, delete from identities.
    database_.execSQL
      (DELETE_removeIdentity_identity, new Object[] { identityBytes });
  }

  /**
   * Erase all certificates, keys, and identities.
   * @throws PibImpl.Error for a non-semantic (database access) error.
   */
  public void
  clearIdentities() throws PibImpl.Error
  {
    // We don't use triggers, so manually delete from keys and certificates.
    database_.execSQL(DELETE_clearIdentities_certificates, new Object[0]);
    database_.execSQL(DELETE_clearIdentities_keys, new Object[0]);

    // Now, delete from identities.
    database_.execSQL(DELETE_clearIdentities_identities, new Object[0]);
  }

  /**
   * Get the names of all the identities.
   * @return The set of identity names. The Name objects are fresh copies.
   * @throws PibImpl.Error for a non-semantic (database access) error.
   */
  public HashSet<Name>
  getIdentities() throws PibImpl.Error
  {
    HashSet<Name> identityNames = new HashSet<Name>();

    Cursor cursor = database_.rawQuery(SELECT_getIdentities, null);

    try {
      while (cursor.moveToNext()) {
        Name name = new Name();
        try {
          name.wireDecode(new Blob(cursor.getBlob(0)));
        } catch (EncodingException ex) {
          throw new PibImpl.Error("PibSqlite3: Error decoding name: " + ex);
        }
        identityNames.add(name);
      }
    } finally {
      cursor.close();
    }

    return identityNames;
  }

  /**
   * Set the identity with the identityName as the default identity. If the
   * identity with identityName does not exist, then it will be created.
   * @param identityName The name for the default identity. This copies the name.
   * @throws PibImpl.Error for a non-semantic (database access) error.
   */
  public void
  setDefaultIdentity(Name identityName) throws PibImpl.Error
  {
    byte[] identityBytes = identityName.wireEncode().getImmutableArray();

    if (!hasIdentity(identityName)) {
      ContentValues values = new ContentValues();
      values.put("identity", identityBytes);
      if (database_.insert("identities", null, values) < 0)
        throw new PibImpl.Error("AndroidSqlite3Pib: SQLite error");
    }

    // We don't use a trigger, so manually reset the previous default identity.
    database_.execSQL(UPDATE_setDefaultIdentity_reset, new Object[0]);

    // Now set the current default identity.
    // Use a statement because it allows binding a blob for the where clause.
    SQLiteStatement statement = database_.compileStatement
      (UPDATE_setDefaultIdentity_set);
    try {
      statement.bindBlob(1, identityBytes);
      if (statement.executeUpdateDelete() <= 0)
        throw new PibImpl.Error("AndroidSqlite3Pib: SQLite error");
    } finally {
      statement.close();
    }
  }

  /**
   * Get the default identity.
   * @return The name of the default identity, as a fresh copy.
   * @throws Pib.Error for no default identity.
   * @throws PibImpl.Error for a non-semantic (database access) error.
   */
  public Name
  getDefaultIdentity() throws Pib.Error, PibImpl.Error
  {
    Cursor cursor = database_.rawQuery(SELECT_getDefaultIdentity, null);

    Name name = new Name();
    try {
      if (cursor.moveToNext()) {
        try {
          name.wireDecode(new Blob(cursor.getBlob(0)));
        } catch (EncodingException ex) {
          throw new PibImpl.Error("PibSqlite3: Error decoding name: " + ex);
        }
      }
      else
        throw new Pib.Error("No default identity");
    } finally {
      cursor.close();
    }

    return name;
  }

  // Key management.

  /**
   * Check for the existence of a key with keyName.
   * @param keyName The name of the key.
   * @return True if the key exists, otherwise false. Return false if the
   * identity does not exist.
   * @throws PibImpl.Error for a non-semantic (database access) error.
   */
  public boolean
  hasKey(Name keyName) throws PibImpl.Error
  {
    // Use a statement because it allows binding a blob for the query.
    SQLiteStatement statement = database_.compileStatement(SELECT_hasKey);
    try {
      statement.bindBlob(1, keyName.wireEncode().getImmutableArray());
      try {
        statement.simpleQueryForLong();
        return true;
      } catch (SQLiteDoneException ex) {
        // No match.
        return false;
      }
    } finally {
      statement.close();
    }
  }

  /**
   * Add the key. If a key with the same name already exists, overwrite the key.
   * If the identity does not exist, it will be created. If no default key for
   * the identity has been set, then set the added key as the default for the
   * identity.  If no default identity has been set, identity becomes the
   * default.
   * @param identityName The name of the identity that the key belongs to. This
   * copies the name.
   * @param keyName The name of the key. This copies the name.
   * @param key The public key bits. This copies the array.
   * @throws PibImpl.Error for a non-semantic (database access) error.
   */
  public void
  addKey(Name identityName, Name keyName, ByteBuffer key) throws PibImpl.Error
  {
    // Ensure the identity exists.
    addIdentity(identityName);

    if (!hasKey(keyName)) {
      // Use a statement because it allows binding a blob for the where clause.
      SQLiteStatement statement = database_.compileStatement(INSERT_addKey);
      try {
        statement.bindBlob(1, identityName.wireEncode().getImmutableArray());
        statement.bindBlob(2, keyName.wireEncode().getImmutableArray());
        statement.bindBlob(3, new Blob(key, false).getImmutableArray());
        if (statement.executeUpdateDelete() <= 0)
          throw new PibImpl.Error("AndroidSqlite3Pib: SQLite error");
      } finally {
        statement.close();
      }
    }
    else {
      // Use a statement because it allows binding a blob for the where clause.
      SQLiteStatement statement = database_.compileStatement(UPDATE_addKey);
      try {
        statement.bindBlob(1, new Blob(key, false).getImmutableArray());
        statement.bindBlob(2, keyName.wireEncode().getImmutableArray());
        if (statement.executeUpdateDelete() <= 0)
          throw new PibImpl.Error("AndroidSqlite3Pib: SQLite error");
      } finally {
        statement.close();
      }
    }

    if (!hasDefaultKeyOfIdentity(identityName)) {
      try {
        setDefaultKeyOfIdentity(identityName, keyName);
      } catch (Pib.Error ex) {
        throw new PibImpl.Error("PibSqlite3: Error setting the default key: " + ex);
      }
    }
  }

  /**
   * Remove the key with keyName and its related certificates. If the key does
   * not exist, do nothing.
   * @param keyName The name of the key.
   * @throws PibImpl.Error for a non-semantic (database access) error.
   */
  public void
  removeKey(Name keyName) throws PibImpl.Error
  {
    byte[] keyNameBytes = keyName.wireEncode().getImmutableArray();

    // We don't use triggers, so manually delete from certificates.
    database_.execSQL
      (DELETE_removeKey_certificates, new Object[] { keyNameBytes });

    // Now, delete from keys.
    database_.execSQL
      (DELETE_removeKey_keys, new Object[] { keyNameBytes });
  }

  /**
   * Get the key bits of a key with name keyName.
   * @param keyName The name of the key.
   * @return The key bits.
   * @throws Pib.Error if the key does not exist.
   * @throws PibImpl.Error for a non-semantic (database access) error.
   */
  public Blob
  getKeyBits(Name keyName) throws Pib.Error, PibImpl.Error
  {
    // First use a statement to get the key ID because the statement allows
    // binding a blob for the query.
    long keyId;
    SQLiteStatement statement = database_.compileStatement
      ("SELECT keys.id " + FROM_WHERE_getKeyBits);
    try {
      statement.bindBlob(1, keyName.wireEncode().getImmutableArray());
      try {
        keyId = statement.simpleQueryForLong();
      } catch (SQLiteDoneException ex) {
        throw new Pib.Error("Key `" + keyName.toUri() + "` does not exist");
      }
    } finally {
      statement.close();
    }

    // Now use the keyId to get the key.
    Cursor cursor = database_.rawQuery("SELECT key_bits FROM keys WHERE id=?",
       new String[] { Long.toString(keyId) });
    try {
      if (cursor.moveToNext())
        return new Blob(cursor.getBlob(0));
      else
        // We don't expect this since we got the keyId.
        throw new Pib.Error("Key `" + keyName.toUri() + "` does not exist");
    } finally {
      cursor.close();
    }
  }

  /**
   * Get all the key names of the identity with the name identityName. The
   * returned key names can be used to create a KeyContainer. With a key name
   * and a backend implementation, one can create a Key front end instance.
   * @param identityName The name of the identity.
   * @return The set of key names. The Name objects are fresh copies. If the
   * identity does not exist, return an empty set.
   * @throws PibImpl.Error for a non-semantic (database access) error.
   */
  public HashSet<Name>
  getKeysOfIdentity(Name identityName) throws PibImpl.Error
  {
    HashSet<Name> keyNames = new HashSet<Name>();

    // Use a hex literal instead of the ending '?' since rawQuery doesn't allow
    // binding a blob.
    Cursor cursor = database_.rawQuery
      (SELECT_getKeysOfIdentity.substring(0, SELECT_getKeysOfIdentity.length() - 1) +
       "x'" + identityName.wireEncode().toHex() + "'", null);

    try {
      while (cursor.moveToNext()) {
        Name name = new Name();
        try {
          name.wireDecode(new Blob(cursor.getBlob(0)));
        } catch (EncodingException ex) {
          throw new PibImpl.Error("PibSqlite3: Error decoding name: " + ex);
        }
        keyNames.add(name);
      }
    } finally {
      cursor.close();
    }

    return keyNames;
  }

  /**
   * Set the key with keyName as the default key for the identity with name
   * identityName.
   * @param identityName The name of the identity. This copies the name.
   * @param keyName The name of the key. This copies the name.
   * @throws Pib.Error if the key does not exist.
   * @throws PibImpl.Error for a non-semantic (database access) error.
   */
  public void
  setDefaultKeyOfIdentity(Name identityName, Name keyName)
    throws Pib.Error, PibImpl.Error
  {
    if (!hasKey(keyName))
      throw new Pib.Error("Key `" + keyName.toUri() + "` does not exist");

    // We don't use a trigger, so manually reset the previous default key.
    database_.execSQL(UPDATE_setDefaultKeyOfIdentity_reset, new Object[0]);

    // Now set the current default key.
    // Use a statement because it allows binding a blob for the where clause.
    SQLiteStatement statement = database_.compileStatement
      (UPDATE_setDefaultKeyOfIdentity_set);
    try {
      statement.bindBlob(1, keyName.wireEncode().getImmutableArray());
      if (statement.executeUpdateDelete() <= 0)
        throw new PibImpl.Error("AndroidSqlite3Pib: SQLite error");
    } finally {
      statement.close();
    }
  }

  /**
   * Get the name of the default key for the identity with name identityName.
   * @param identityName The name of the identity.
   * @return The name of the default key, as a fresh copy.
   * @throws Pib.Error if there is no default key or if the identity does not
   * exist.
   * @throws PibImpl.Error for a non-semantic (database access) error.
   */
  public Name
  getDefaultKeyOfIdentity(Name identityName) throws Pib.Error, PibImpl.Error
  {
    if (!hasIdentity(identityName))
      throw new Pib.Error
        ("Identity `" + identityName.toUri() + "` does not exist");

    // First use a statement to get the key ID because the statement allows
    // binding a blob for the query.
    long keyId;
    SQLiteStatement statement = database_.compileStatement
      ("SELECT keys.id " + FROM_WHERE_getDefaultKeyOfIdentity);
    try {
      statement.bindBlob(1, identityName.wireEncode().getImmutableArray());
      try {
        keyId = statement.simpleQueryForLong();
      } catch (SQLiteDoneException ex) {
        throw new Pib.Error
          ("No default key for identity `" + identityName.toUri() + "`");
      }
    } finally {
      statement.close();
    }

    // Now use the keyId to get the key name.
    Cursor cursor = database_.rawQuery("SELECT key_name FROM keys WHERE id=?",
       new String[] { Long.toString(keyId) });
    try {
      if (cursor.moveToNext()) {
        Name name = new Name();
        try {
          name.wireDecode(new Blob(cursor.getBlob(0)));
        } catch (EncodingException ex) {
          throw new PibImpl.Error("PibSqlite3: Error decoding name: " + ex);
        }
        return name;
      }
      else
        // We don't expect this since we got the keyId.
        throw new Pib.Error
          ("No default key for identity `" + identityName.toUri() + "`");
    } finally {
      cursor.close();
    }
  }

  // Certificate management.

  /**
   * Check for the existence of a certificate with name certificateName.
   * @param certificateName The name of the certificate.
   * @return True if the certificate exists, otherwise false.
   * @throws PibImpl.Error for a non-semantic (database access) error.
   */
  public boolean
  hasCertificate(Name certificateName) throws PibImpl.Error
  {
    // Use a statement because it allows binding a blob for the query.
    SQLiteStatement statement = database_.compileStatement(SELECT_hasCertificate);
    try {
      statement.bindBlob(1, certificateName.wireEncode().getImmutableArray());
      try {
        statement.simpleQueryForLong();
        return true;
      } catch (SQLiteDoneException ex) {
        // No match.
        return false;
      }
    } finally {
      statement.close();
    }
  }

  /**
   * Add the certificate. If a certificate with the same name (without implicit
   * digest) already exists, then overwrite the certificate. If the key or
   * identity does not exist, they will be created. If no default certificate
   * for the key has been set, then set the added certificate as the default for
   * the key. If no default key was set for the identity, it will be set as the
   * default key for the identity. If no default identity was selected, the
   * certificate's identity becomes the default.
   * @param certificate The certificate to add. This copies the object.
   * @throws PibImpl.Error for a non-semantic (database access) error.
   */
  public void
  addCertificate(CertificateV2 certificate) throws PibImpl.Error
  {
    // Ensure the key exists.
    Blob content = certificate.getContent();
    addKey(certificate.getIdentity(), certificate.getKeyName(), content.buf());

    if (!hasCertificate(certificate.getName())) {
      // Use a statement because it allows binding a blob for the where clause.
      SQLiteStatement statement = database_.compileStatement
        (INSERT_addCertificate);
      try {
        statement.bindBlob(1, certificate.getKeyName().wireEncode().getImmutableArray());
        statement.bindBlob(2, certificate.getName().wireEncode().getImmutableArray());
        statement.bindBlob(3, certificate.wireEncode().getImmutableArray());
        if (statement.executeUpdateDelete() <= 0)
          throw new PibImpl.Error("AndroidSqlite3Pib: SQLite error");
      } finally {
        statement.close();
      }
    }
    else {
      // Use a statement because it allows binding a blob for the where clause.
      SQLiteStatement statement = database_.compileStatement
        (UPDATE_addCertificate);
      try {
        statement.bindBlob(1, certificate.wireEncode().getImmutableArray());
        statement.bindBlob(2, certificate.getName().wireEncode().getImmutableArray());
        if (statement.executeUpdateDelete() <= 0)
          throw new PibImpl.Error("AndroidSqlite3Pib: SQLite error");
      } finally {
        statement.close();
      }
    }

    if (!hasDefaultCertificateOfKey(certificate.getKeyName())) {
      try {
        setDefaultCertificateOfKey(certificate.getKeyName(), certificate.getName());
      } catch (Pib.Error ex) {
        throw new PibImpl.Error
          ("PibSqlite3: Error setting the default certificate: " + ex);
      }
    }
  }

  /**
   * Remove the certificate with name certificateName. If the certificate does
   * not exist, do nothing.
   * @param certificateName The name of the certificate.
   * @throws PibImpl.Error for a non-semantic (database access) error.
   */
  public void
  removeCertificate(Name certificateName) throws PibImpl.Error
  {
    database_.execSQL
      (DELETE_removeCertificate,
       new Object[] { certificateName.wireEncode().getImmutableArray() });
  }

  /**
   * Get the certificate with name certificateName.
   * @param certificateName The name of the certificate.
   * @return A copy of the certificate.
   * @throws Pib.Error if the certificate does not exist.
   * @throws PibImpl.Error for a non-semantic (database access) error.
   */
  public CertificateV2
  getCertificate(Name certificateName) throws Pib.Error, PibImpl.Error
  {
    // First use a statement to get the certificate ID because the statement
    // allows binding a blob for the query.
    long certificateId;
    SQLiteStatement statement = database_.compileStatement
      ("SELECT certificates.id FROM certificates WHERE certificate_name=?");
    try {
      statement.bindBlob(1,certificateName.wireEncode().getImmutableArray());
      try {
        certificateId = statement.simpleQueryForLong();
      } catch (SQLiteDoneException ex) {
        throw new Pib.Error
          ("Certificate `" + certificateName.toUri() + "` does not exit");
      }
    } finally {
      statement.close();
    }

    // Now use the certificateId to get the certicicate.
    Cursor cursor = database_.rawQuery
      ("SELECT certificate_data FROM certificates WHERE id=?",
       new String[] { Long.toString(certificateId) });
    try {
      if (cursor.moveToNext()) {
        CertificateV2 certificate = new CertificateV2();
        try {
          certificate.wireDecode(new Blob(cursor.getBlob(0)));
        } catch (EncodingException ex) {
          throw new PibImpl.Error("PibSqlite3: Error decoding certificate: " + ex);
        }
        return certificate;
      }
      else
        // We don't expect this since we got the certificateId.
        throw new Pib.Error
          ("Certificate `" + certificateName.toUri() + "` does not exit");
    } finally {
      cursor.close();
    }
  }

  /**
   * Get a list of certificate names of the key with id keyName. The returned
   * certificate names can be used to create a PibCertificateContainer. With a
   * certificate name and a backend implementation, one can obtain the
   * certificate.
   * @param keyName The name of the key.
   * @return The set of certificate names. The Name objects are fresh copies. If
   * the key does not exist, return an empty set.
   * @throws PibImpl.Error for a non-semantic (database access) error.
   */
  public HashSet<Name>
  getCertificatesOfKey(Name keyName) throws PibImpl.Error
  {
    HashSet<Name> certNames = new HashSet<Name>();

    // Use a hex literal instead of the ending '?' since rawQuery doesn't allow
    // binding a blob.
    Cursor cursor = database_.rawQuery
      (SELECT_getCertificatesOfKey.substring(0, SELECT_getCertificatesOfKey.length() - 1) +
       "x'" + keyName.wireEncode().toHex() + "'", null);

    try {
      while (cursor.moveToNext()) {
        Name name = new Name();
        try {
          name.wireDecode(new Blob(cursor.getBlob(0)));
        } catch (EncodingException ex) {
          throw new PibImpl.Error("PibSqlite3: Error decoding name: " + ex);
        }
        certNames.add(name);
      }
    } finally {
      cursor.close();
    }

    return certNames;
  }

  /**
   * Set the cert with name certificateName as the default for the key with
   * keyName.
   * @param keyName The name of the key.
   * @param certificateName The name of the certificate. This copies the name.
   * @throws Pib.Error if the certificate with name certificateName does not
   * exist.
   * @throws PibImpl.Error for a non-semantic (database access) error.
   */
  public void
  setDefaultCertificateOfKey(Name keyName, Name certificateName)
    throws Pib.Error, PibImpl.Error
  {
    if (!hasCertificate(certificateName))
      throw new Pib.Error
        ("Certificate `" + certificateName.toUri() + "` does not exist");

    // We don't use a trigger, so manually reset the previous default certificate.
    database_.execSQL(UPDATE_setDefaultCertificateOfKey_reset, new Object[0]);

    // Now set the current default certificate.
    // Use a statement because it allows binding a blob for the where clause.
    SQLiteStatement statement = database_.compileStatement
      (UPDATE_setDefaultCertificateOfKey_set);
    try {
      statement.bindBlob(1, certificateName.wireEncode().getImmutableArray());
      if (statement.executeUpdateDelete() <= 0)
        throw new PibImpl.Error("AndroidSqlite3Pib: SQLite error");
    } finally {
      statement.close();
    }
  }

  /**
   * Get the default certificate for the key with eyName.
   * @param keyName The name of the key.
   * @return A copy of the default certificate.
   * @throws Pib.Error if the default certificate does not exist.
   * @throws PibImpl.Error for a non-semantic (database access) error.
   */
  public CertificateV2
  getDefaultCertificateOfKey(Name keyName) throws Pib.Error, PibImpl.Error
  {
    // First use a statement to get the certificate ID because the statement allows
    // binding a blob for the query.
    long certificateId;
    SQLiteStatement statement = database_.compileStatement
      ("SELECT certificates.id " + FROM_WHERE_getDefaultCertificateOfKey);
    try {
      statement.bindBlob(1, keyName.wireEncode().getImmutableArray());
      try {
        certificateId = statement.simpleQueryForLong();
      } catch (SQLiteDoneException ex) {
        throw new Pib.Error
          ("No default certificate for key `" + keyName.toUri() + "`");
      }
    } finally {
      statement.close();
    }

    // Now use the certificateId to get the key name.
    Cursor cursor = database_.rawQuery
      ("SELECT certificate_data FROM certificates WHERE id=?",
       new String[] { Long.toString(certificateId) });
    try {
      if (cursor.moveToNext()) {
        CertificateV2 certificate = new CertificateV2();
        try {
          certificate.wireDecode(new Blob(cursor.getBlob(0)));
        } catch (EncodingException ex) {
          throw new PibImpl.Error("PibSqlite3: Error decoding certificate: " + ex);
        }
        return certificate;
      }
      else
        // We don't expect this since we got the certificateId.
        throw new Pib.Error
          ("No default certificate for key `" + keyName.toUri() + "`");
    } finally {
      cursor.close();
    }
  }

  private boolean
  hasDefaultIdentity() throws PibImpl.Error
  {
    // Use a statement because it allows binding a blob for the query.
    SQLiteStatement statement = database_.compileStatement
      (SELECT_hasDefaultIdentity);
    try {
      try {
        statement.simpleQueryForLong();
        return true;
      } catch (SQLiteDoneException ex) {
        // No match.
        return false;
      }
    } finally {
      statement.close();
    }
  }

  private boolean
  hasDefaultKeyOfIdentity(Name identityName) throws PibImpl.Error
  {
    // Use a statement because it allows binding a blob for the query.
    SQLiteStatement statement = database_.compileStatement
      (SELECT_hasDefaultKeyOfIdentity);
    try {
      statement.bindBlob(1, identityName.wireEncode().getImmutableArray());
      try {
        statement.simpleQueryForLong();
        return true;
      } catch (SQLiteDoneException ex) {
        // No match.
        return false;
      }
    } finally {
      statement.close();
    }
  }

  private boolean
  hasDefaultCertificateOfKey(Name keyName) throws PibImpl.Error
  {
    // Use a statement because it allows binding a blob for the query.
    SQLiteStatement statement = database_.compileStatement
      (SELECT_hasDefaultCertificateOfKey);
    try {
      statement.bindBlob(1, keyName.wireEncode().getImmutableArray());
      try {
        statement.simpleQueryForLong();
        return true;
      } catch (SQLiteDoneException ex) {
        // No match.
        return false;
      }
    } finally {
      statement.close();
    }
  }

  private SQLiteDatabase database_;
}
