/**
 * Copyright (C) 2017-2018 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From ndn-cxx security https://github.com/named-data/ndn-cxx/blob/master/src/security/pib/pib-sqlite3.cpp
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

import java.io.File;
import java.nio.ByteBuffer;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.logging.Level;
import java.util.logging.Logger;
import net.named_data.jndn.Name;
import net.named_data.jndn.encoding.EncodingException;
import net.named_data.jndn.security.v2.CertificateV2;
import net.named_data.jndn.util.Blob;
import net.named_data.jndn.util.Common;

/**
 * PibSqlite3 extends PibImpl and is used by the Pib class as an implementation
 * of a PIB based on an SQLite3 database. All the contents in the PIB are stored
 * in an SQLite3 database file. This provides more persistent storage than
 * PibMemory. (On Android, use AndroidSqlite3Pib instead.)
 */
public class PibSqlite3 extends PibSqlite3Base {
  /**
   * Create a new PibSqlite3 to work with an SQLite3 file. This assumes that the
   * database directory does not contain a PIB database of an older version.
   * @param databaseDirectoryPath The directory where the database file is
   * located. If the directory does not exist, create it.
   * @param databaseFilename The name if the database file in the
   * databaseDirectoryPath.
   * @throws PibImpl.Error if initialization fails.
   */
  public PibSqlite3(String databaseDirectoryPath, String databaseFilename)
    throws PibImpl.Error
  {
    construct(databaseDirectoryPath, databaseFilename);
  }

  /**
   * Create a new PibSqlite3 to work with an SQLite3 file. This assumes that the
   * database directory does not contain a PIB database of an older version.
   * Use "pib.db" for the databaseFilename in the databaseDirectoryPath.
   * @param databaseDirectoryPath The directory where the database file is
   * located. If the directory does not exist, create it.
   * @throws PibImpl.Error if initialization fails.
   */
  public PibSqlite3(String databaseDirectoryPath) throws PibImpl.Error
  {
    construct(databaseDirectoryPath, "pib.db");
  }

  /**
   * Create a new PibSqlite3 to work with an SQLite3 file. This assumes that the
   * database directory does not contain a PIB database of an older version.
   * Use $HOME/.ndn/pib.db as the database file path. If the directory does not
   * exist, create it.
   * @throws PibImpl.Error if initialization fails.
   */
  public PibSqlite3() throws PibImpl.Error
  {
    construct("", "pib.db");
  }

  private void
  construct(String databaseDirectoryPathIn, String databaseFilename)
    throws PibImpl.Error
  {
    File databaseDirectoryPath;
    if (!databaseDirectoryPathIn.equals(""))
      databaseDirectoryPath = new File(databaseDirectoryPathIn);
    else
      databaseDirectoryPath = getDefaultDatabaseDirectoryPath();

    databaseDirectoryPath.mkdirs();

    File databaseFilePath = new File(databaseDirectoryPath, databaseFilename);

    try {
      Class.forName("org.sqlite.JDBC");
    } catch (ClassNotFoundException ex) {
      // We don't expect this to happen.
      Logger.getLogger(PibSqlite3.class.getName()).log(Level.SEVERE, null, ex);
      return;
    }

    try {
      database_ = DriverManager.getConnection("jdbc:sqlite:" + databaseFilePath);

      Statement statement = database_.createStatement();
      // Use "try/finally instead of "try-with-resources" or "using" which are
      // not supported before Java 7.
      try {
        // Initialize the PIB tables.
        statement.executeUpdate(INITIALIZATION1);
        statement.executeUpdate(INITIALIZATION2);
        statement.executeUpdate(INITIALIZATION3);
        statement.executeUpdate(INITIALIZATION4);
        statement.executeUpdate(INITIALIZATION5);
        statement.executeUpdate(INITIALIZATION6);
        statement.executeUpdate(INITIALIZATION7);
      } finally {
        statement.close();
      }
    } catch (SQLException exception) {
      throw new PibImpl.Error("PibSqlite3: SQLite error: " + exception);
    }
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
    try {
      if (getTpmLocator().equals("")) {
        // The tpmLocator does not exist. Insert it directly.
        PreparedStatement statement = database_.prepareStatement
          ("INSERT INTO tpmInfo (tpm_locator) values (?)");
        statement.setString(1, tpmLocator);
        try {
          statement.executeUpdate();
        } finally {
          statement.close();
        }
      }
      else {
        // Update the existing tpmLocator.
        PreparedStatement statement = database_.prepareStatement
          ("UPDATE tpmInfo SET tpm_locator=?");
        statement.setString(1, tpmLocator);
        try {
          statement.executeUpdate();
        } finally {
          statement.close();
        }
      }
    } catch (SQLException exception) {
      throw new PibImpl.Error("PibSqlite3: SQLite error: " + exception);
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
    try {
      PreparedStatement statement = database_.prepareStatement
        (SELECT_getTpmLocator);
      try {
        ResultSet result = statement.executeQuery();

        if (result.next())
          return result.getString(1);
        else
          return "";
      } finally {
        statement.close();
      }
    } catch (SQLException exception) {
      throw new PibImpl.Error("PibSqlite3: SQLite error: " + exception);
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
    try {
      PreparedStatement statement = database_.prepareStatement
        (SELECT_hasIdentity);
      statement.setBytes(1, identityName.wireEncode().getImmutableArray());
      try {
        ResultSet result = statement.executeQuery();
        return result.next();
      } finally {
        statement.close();
      }
    } catch (SQLException exception) {
      throw new PibImpl.Error("PibSqlite3: SQLite error: " + exception);
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
      try {
        PreparedStatement statement = database_.prepareStatement
          ("INSERT INTO identities (identity) values (?)");
        statement.setBytes(1, identityName.wireEncode().getImmutableArray());
        try {
          statement.executeUpdate();
        } finally {
          statement.close();
        }
      } catch (SQLException exception) {
        throw new PibImpl.Error("PibSqlite3: SQLite error: " + exception);
      }
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

    try {
      // We don't use triggers, so manually delete from keys and certificates.
      // First get the key ids.
      ArrayList<Integer> keyIds = new ArrayList<Integer>();

      PreparedStatement statement = database_.prepareStatement
        (SELECT_removeIdentity);
      statement.setBytes(1, identityBytes);

      try {
        ResultSet result = statement.executeQuery();

        while (result.next())
          keyIds.add(result.getInt(1));
      } finally {
        statement.close();
      }

      for (int keyId : keyIds) {
        statement = database_.prepareStatement
          (DELETE_removeIdentity_certificates);
        statement.setInt(1, keyId);
        try {
          statement.executeUpdate();
        } finally {
          statement.close();
        }
      }

      for (int keyId : keyIds) {
        statement = database_.prepareStatement(DELETE_removeIdentity_keys);
        statement.setInt(1, keyId);
        try {
          statement.executeUpdate();
        } finally {
          statement.close();
        }
      }

      // Now, delete from identities.
      statement = database_.prepareStatement(DELETE_removeIdentity_identity);
      statement.setBytes(1, identityBytes);
      try {
        statement.executeUpdate();
      } finally {
        statement.close();
      }
    } catch (SQLException exception) {
      throw new PibImpl.Error("PibSqlite3: SQLite error: " + exception);
    }
  }

  /**
   * Erase all certificates, keys, and identities.
   * @throws PibImpl.Error for a non-semantic (database access) error.
   */
  public void
  clearIdentities() throws PibImpl.Error
  {
    try {
      // We don't use triggers, so manually delete from keys and certificates.
      Statement statement = database_.createStatement();
      statement.executeUpdate(DELETE_clearIdentities_certificates);
      statement.executeUpdate(DELETE_clearIdentities_keys);

      // Now, delete from identities.
      statement.executeUpdate(DELETE_clearIdentities_identities);
    } catch (SQLException exception) {
      throw new PibImpl.Error("PibSqlite3: SQLite error: " + exception);
    }
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

    try {
      PreparedStatement statement = database_.prepareStatement
        (SELECT_getIdentities);

      try {
        ResultSet result = statement.executeQuery();

        while (result.next()) {
          Name name = new Name();
          try {
            name.wireDecode(new Blob(result.getBytes(1)));
          } catch (EncodingException ex) {
            throw new PibImpl.Error("PibSqlite3: Error decoding name: " + ex);
          }
          identityNames.add(name);
        }
      } finally {
        statement.close();
      }
    } catch (SQLException exception) {
      throw new PibImpl.Error("PibSqlite3: SQLite error: " + exception);
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
    try {
      byte[] identityBytes = identityName.wireEncode().getImmutableArray();

      PreparedStatement statement;
      if (!hasIdentity(identityName)) {
        statement = database_.prepareStatement
          ("INSERT INTO identities (identity) values (?)");
        statement.setBytes(1, identityBytes);
        try {
          statement.executeUpdate();
        } finally {
          statement.close();
        }
      }

      // We don't use a trigger, so manually reset the previous default identity.
      statement = database_.prepareStatement(UPDATE_setDefaultIdentity_reset);
      try {
        statement.executeUpdate();
      } finally {
        statement.close();
      }

      // Now set the current default identity.
      statement = database_.prepareStatement(UPDATE_setDefaultIdentity_set);
      statement.setBytes(1, identityBytes);
      try {
        statement.executeUpdate();
      } finally {
        statement.close();
      }
    } catch (SQLException exception) {
      throw new PibImpl.Error("PibSqlite3: SQLite error: " + exception);
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
    try {
      Statement statement = database_.createStatement();
      try {
        ResultSet result = statement.executeQuery(SELECT_getDefaultIdentity);

        if (result.next()) {
          Name name = new Name();
          try {
            name.wireDecode(new Blob(result.getBytes(1)));
          } catch (EncodingException ex) {
            throw new PibImpl.Error("PibSqlite3: Error decoding name: " + ex);
          }
          return name;
        }
        else
          throw new Pib.Error("No default identity");
      } finally {
        statement.close();
      }
    } catch (SQLException exception) {
      throw new PibImpl.Error("PibSqlite3: SQLite error: " + exception);
    }
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
    try {
      PreparedStatement statement = database_.prepareStatement(SELECT_hasKey);
      statement.setBytes(1, keyName.wireEncode().getImmutableArray());
      try {
        ResultSet result = statement.executeQuery();
        return result.next();
      } finally {
        statement.close();
      }
    } catch (SQLException exception) {
      throw new PibImpl.Error("PibSqlite3: SQLite error: " + exception);
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
      try {
        PreparedStatement statement = database_.prepareStatement(INSERT_addKey);
        statement.setBytes(1, identityName.wireEncode().getImmutableArray());
        statement.setBytes(2, keyName.wireEncode().getImmutableArray());
        statement.setBytes(3, new Blob(key, false).getImmutableArray());

        try {
          statement.executeUpdate();
        } finally {
          statement.close();
        }
      } catch (SQLException exception) {
        throw new PibImpl.Error("PibSqlite3: SQLite error: " + exception);
      }
    }
    else {
      try {
        PreparedStatement statement = database_.prepareStatement(UPDATE_addKey);
        statement.setBytes(1, new Blob(key, false).getImmutableArray());
        statement.setBytes(2, keyName.wireEncode().getImmutableArray());

        try {
          statement.executeUpdate();
        } finally {
          statement.close();
        }
      } catch (SQLException exception) {
        throw new PibImpl.Error("PibSqlite3: SQLite error: " + exception);
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

    try {
      // We don't use triggers, so manually delete from certificates.
      PreparedStatement statement = database_.prepareStatement
        (DELETE_removeKey_certificates);
      statement.setBytes(1, keyNameBytes);
      try {
        statement.executeUpdate();
      } finally {
        statement.close();
      }

      // Now, delete from keys.
      statement = database_.prepareStatement(DELETE_removeKey_keys);
      statement.setBytes(1, keyNameBytes);
      try {
        statement.executeUpdate();
      } finally {
        statement.close();
      }
    } catch (SQLException exception) {
      throw new PibImpl.Error("PibSqlite3: SQLite error: " + exception);
    }
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
    try {
      PreparedStatement statement = database_.prepareStatement
        ("SELECT key_bits " + FROM_WHERE_getKeyBits);
      statement.setBytes(1, keyName.wireEncode().getImmutableArray());

      try {
        ResultSet result = statement.executeQuery();

        if (result.next())
          return new Blob(result.getBytes(1), false);
        else
          throw new Pib.Error("Key `" + keyName.toUri() + "` does not exist");
      } finally {
        statement.close();
      }
    } catch (SQLException exception) {
      throw new PibImpl.Error("PibSqlite3: SQLite error: " + exception);
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

    try {
      PreparedStatement statement = database_.prepareStatement
        (SELECT_getKeysOfIdentity);
      statement.setBytes(1, identityName.wireEncode().getImmutableArray());

      try {
        ResultSet result = statement.executeQuery();

        while (result.next()) {
          Name name = new Name();
          try {
            name.wireDecode(new Blob(result.getBytes(1)));
          } catch (EncodingException ex) {
            throw new PibImpl.Error("PibSqlite3: Error decoding name: " + ex);
          }
          keyNames.add(name);
        }
      } finally {
        statement.close();
      }
    } catch (SQLException exception) {
      throw new PibImpl.Error("PibSqlite3: SQLite error: " + exception);
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

    try {
      // We don't use a trigger, so manually reset the previous default key.
      PreparedStatement statement = database_.prepareStatement
        (UPDATE_setDefaultKeyOfIdentity_reset);
      try {
        statement.executeUpdate();
      } finally {
        statement.close();
      }

      // Now set the current default key.
      statement = database_.prepareStatement
        (UPDATE_setDefaultKeyOfIdentity_set);
      statement.setBytes(1, keyName.wireEncode().getImmutableArray());
      try {
        statement.executeUpdate();
      } finally {
        statement.close();
      }
    } catch (SQLException exception) {
      throw new PibImpl.Error("PibSqlite3: SQLite error: " + exception);
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

    try {
      PreparedStatement statement = database_.prepareStatement
        ("SELECT key_name " + FROM_WHERE_getDefaultKeyOfIdentity);
      statement.setBytes(1, identityName.wireEncode().getImmutableArray());

      try {
        ResultSet result = statement.executeQuery();

        if (result.next()) {
          Name name = new Name();
          try {
            name.wireDecode(new Blob(result.getBytes(1)));
          } catch (EncodingException ex) {
            throw new PibImpl.Error("PibSqlite3: Error decoding name: " + ex);
          }
          return name;
        }
        else
          throw new Pib.Error
            ("No default key for identity `" + identityName.toUri() + "`");
      } finally {
        statement.close();
      }
    } catch (SQLException exception) {
      throw new PibImpl.Error("PibSqlite3: SQLite error: " + exception);
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
    try {
      PreparedStatement statement = database_.prepareStatement
        (SELECT_hasCertificate);
      statement.setBytes(1, certificateName.wireEncode().getImmutableArray());
      try {
        ResultSet result = statement.executeQuery();
        return result.next();
      } finally {
        statement.close();
      }
    } catch (SQLException exception) {
      throw new PibImpl.Error("PibSqlite3: SQLite error: " + exception);
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
      try {
        PreparedStatement statement = database_.prepareStatement
          (INSERT_addCertificate);
        statement.setBytes(1, certificate.getKeyName().wireEncode().getImmutableArray());
        statement.setBytes(2, certificate.getName().wireEncode().getImmutableArray());
        statement.setBytes(3, certificate.wireEncode().getImmutableArray());

        try {
          statement.executeUpdate();
        } finally {
          statement.close();
        }
      } catch (SQLException exception) {
        throw new PibImpl.Error("PibSqlite3: SQLite error: " + exception);
      }
    }
    else {
      try {
        PreparedStatement statement = database_.prepareStatement
          (UPDATE_addCertificate);
        statement.setBytes(1, certificate.wireEncode().getImmutableArray());
        statement.setBytes(2, certificate.getName().wireEncode().getImmutableArray());

        try {
          statement.executeUpdate();
        } finally {
          statement.close();
        }
      } catch (SQLException exception) {
        throw new PibImpl.Error("PibSqlite3: SQLite error: " + exception);
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
    try {
      PreparedStatement statement = database_.prepareStatement
        (DELETE_removeCertificate);
      statement.setBytes(1, certificateName.wireEncode().getImmutableArray());
      try {
        statement.executeUpdate();
      } finally {
        statement.close();
      }
    } catch (SQLException exception) {
      throw new PibImpl.Error("PibSqlite3: SQLite error: " + exception);
    }
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
    try {
      PreparedStatement statement = database_.prepareStatement
        ("SELECT certificate_data FROM certificates WHERE certificate_name=?");
      statement.setBytes(1, certificateName.wireEncode().getImmutableArray());

      try {
        ResultSet result = statement.executeQuery();

        if (result.next()) {
          CertificateV2 certificate = new CertificateV2();
          try {
            certificate.wireDecode(new Blob(result.getBytes(1)));
          } catch (EncodingException ex) {
            throw new PibImpl.Error("PibSqlite3: Error decoding certificate: " + ex);
          }
          return certificate;
        }
        else
          throw new Pib.Error
            ("Certificate `" + certificateName.toUri() + "` does not exit");
      } finally {
        statement.close();
      }
    } catch (SQLException exception) {
      throw new PibImpl.Error("PibSqlite3: SQLite error: " + exception);
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

    try {
      PreparedStatement statement = database_.prepareStatement
        (SELECT_getCertificatesOfKey);
      statement.setBytes(1, keyName.wireEncode().getImmutableArray());

      try {
        ResultSet result = statement.executeQuery();

        while (result.next()) {
          Name name = new Name();
          try {
            name.wireDecode(new Blob(result.getBytes(1)));
          } catch (EncodingException ex) {
            throw new PibImpl.Error("PibSqlite3: Error decoding name: " + ex);
          }
          certNames.add(name);
        }
      } finally {
        statement.close();
      }
    } catch (SQLException exception) {
      throw new PibImpl.Error("PibSqlite3: SQLite error: " + exception);
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

    try {
      // We don't use a trigger, so manually reset the previous default certificate.
      PreparedStatement statement = database_.prepareStatement
        (UPDATE_setDefaultCertificateOfKey_reset);
      try {
        statement.executeUpdate();
      } finally {
        statement.close();
      }

      // Now set the current default certificate.
      statement = database_.prepareStatement
        (UPDATE_setDefaultCertificateOfKey_set);
      statement.setBytes(1, certificateName.wireEncode().getImmutableArray());
      try {
        statement.executeUpdate();
      } finally {
        statement.close();
      }
    } catch (SQLException exception) {
      throw new PibImpl.Error("PibSqlite3: SQLite error: " + exception);
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
    try {
      PreparedStatement statement = database_.prepareStatement
        ("SELECT certificate_data " + FROM_WHERE_getDefaultCertificateOfKey);
      statement.setBytes(1, keyName.wireEncode().getImmutableArray());

      try {
        ResultSet result = statement.executeQuery();

        if (result.next()) {
          CertificateV2 certificate = new CertificateV2();
          try {
            certificate.wireDecode(new Blob(result.getBytes(1)));
          } catch (EncodingException ex) {
            throw new PibImpl.Error("PibSqlite3: Error decoding certificate: " + ex);
          }
          return certificate;
        }
        else
          throw new Pib.Error
            ("No default certificate for key `" + keyName.toUri() + "`");
      } finally {
        statement.close();
      }
    } catch (SQLException exception) {
      throw new PibImpl.Error("PibSqlite3: SQLite error: " + exception);
    }
  }

  /**
   * Get the default that the constructor uses if databaseDirectoryPath is
   * omitted. This does not try to create the directory.
   * @return The default database directory path.
   */
  public static File
  getDefaultDatabaseDirectoryPath()
  {
    return new File(Common.getHomeDirectory(), ".ndn");
  }

  /**
   * Get the default database file path that the constructor uses if
   * databaseDirectoryPath and databaseFilename are omitted.
   * @return The default database file path.
   */
  public static File
  getDefaultDatabaseFilePath()
  {
    return new File(getDefaultDatabaseDirectoryPath(), "pib.db");
  }

  private boolean
  hasDefaultIdentity() throws PibImpl.Error
  {
    try {
      Statement statement = database_.createStatement();
      try {
        ResultSet result = statement.executeQuery(SELECT_hasDefaultIdentity);
        return result.next();
      } finally {
        statement.close();
      }
    } catch (SQLException exception) {
      throw new PibImpl.Error("PibSqlite3: SQLite error: " + exception);
    }
  }

  private boolean
  hasDefaultKeyOfIdentity(Name identityName) throws PibImpl.Error
  {
    try {
      PreparedStatement statement = database_.prepareStatement
        (SELECT_hasDefaultKeyOfIdentity);
      statement.setBytes(1, identityName.wireEncode().getImmutableArray());
      try {
        ResultSet result = statement.executeQuery();
        return result.next();
      } finally {
        statement.close();
      }
    } catch (SQLException exception) {
      throw new PibImpl.Error("PibSqlite3: SQLite error: " + exception);
    }
  }

  private boolean
  hasDefaultCertificateOfKey(Name keyName) throws PibImpl.Error
  {
    try {
      PreparedStatement statement = database_.prepareStatement
        (SELECT_hasDefaultCertificateOfKey);
      statement.setBytes(1, keyName.wireEncode().getImmutableArray());
      try {
        ResultSet result = statement.executeQuery();
        return result.next();
      } finally {
        statement.close();
      }
    } catch (SQLException exception) {
      throw new PibImpl.Error("PibSqlite3: SQLite error: " + exception);
    }
  }

  private Connection database_ = null;
}
