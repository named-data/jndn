/**
 * Copyright (C) 2014-2018 Regents of the University of California.
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

import java.io.File;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.logging.Level;
import java.util.logging.Logger;
import net.named_data.jndn.KeyLocator;
import net.named_data.jndn.Name;
import net.named_data.jndn.encoding.EncodingException;
import net.named_data.jndn.security.KeyType;
import net.named_data.jndn.security.SecurityException;
import net.named_data.jndn.security.certificate.IdentityCertificate;
import net.named_data.jndn.util.Blob;
import net.named_data.jndn.util.Common;

/**
 * BasicIdentityStorage extends IdentityStorage to implement basic storage of
 * identity, public keys and certificates using the org.sqlite.JDBC SQLite
 * provider.
 */
public class BasicIdentityStorage extends Sqlite3IdentityStorageBase {
  /**
   * Create a new BasicIdentityStorage to use the SQLite3 file in the
   * default location.
   */
  public BasicIdentityStorage() throws SecurityException
  {
    File identityDir = getDefaultDatabaseDirectoryPath();
    identityDir.mkdirs();
    File databasePath = new File(identityDir, "ndnsec-public-info.db");
    construct(databasePath.getAbsolutePath());
  }

  /**
   * Create a new BasicIdentityStorage to use the given SQLite3 file.
   * @param databaseFilePath The path of the SQLite file.
   */
  public BasicIdentityStorage(String databaseFilePath) throws SecurityException
  {
    construct(databaseFilePath);
  }

  private void
  construct(String databaseFilePath) throws SecurityException
  {
    try {
      Class.forName("org.sqlite.JDBC");
    } catch (ClassNotFoundException ex) {
      // We don't expect this to happen.
      Logger.getLogger(BasicIdentityStorage.class.getName()).log(Level.SEVERE, null, ex);
      return;
    }

    try {
      database_ = DriverManager.getConnection("jdbc:sqlite:" + databaseFilePath);

      Statement statement = database_.createStatement();
      // Use "try/finally instead of "try-with-resources" or "using" which are not supported before Java 7.
      try {
        // Check if the TpmInfo table exists.
        ResultSet result = statement.executeQuery(SELECT_MASTER_TPM_INFO_TABLE);
        boolean tpmInfoTableExists = false;
        if (result.next())
          tpmInfoTableExists = true;
        result.close();

        if (!tpmInfoTableExists)
          statement.executeUpdate(INIT_TPM_INFO_TABLE);

        // Check if the ID table exists.
        result = statement.executeQuery(SELECT_MASTER_ID_TABLE);
        boolean idTableExists = false;
        if (result.next())
          idTableExists = true;
        result.close();

        if (!idTableExists) {
          statement.executeUpdate(INIT_ID_TABLE1);
          statement.executeUpdate(INIT_ID_TABLE2);
        }

        // Check if the Key table exists.
        result = statement.executeQuery(SELECT_MASTER_KEY_TABLE);
        idTableExists = false;
        if (result.next())
          idTableExists = true;
        result.close();

        if (!idTableExists) {
          statement.executeUpdate(INIT_KEY_TABLE1);
          statement.executeUpdate(INIT_KEY_TABLE2);
        }

        // Check if the Certificate table exists.
        result = statement.executeQuery(SELECT_MASTER_CERT_TABLE);
        idTableExists = false;
        if (result.next())
          idTableExists = true;
        result.close();

        if (!idTableExists) {
          statement.executeUpdate(INIT_CERT_TABLE1);
          statement.executeUpdate(INIT_CERT_TABLE2);
          statement.executeUpdate(INIT_CERT_TABLE3);
        }
      } finally {
        statement.close();
      }
    } catch (SQLException exception) {
      throw new SecurityException("BasicIdentityStorage: SQLite error: " + exception);
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
    try {
      PreparedStatement statement = database_.prepareStatement
        (SELECT_doesIdentityExist);
      statement.setString(1, identityName.toUri());

      try {
        ResultSet result = statement.executeQuery();

        if (result.next())
          return result.getInt(1) > 0;
        else
          return false;
      } finally {
        statement.close();
      }
    } catch (SQLException exception) {
      throw new SecurityException("BasicIdentityStorage: SQLite error: " + exception);
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

    try {
      PreparedStatement statement = database_.prepareStatement
        ("INSERT INTO Identity (identity_name) values (?)");
      statement.setString(1, identityName.toUri());

      try {
        statement.executeUpdate();
      } finally {
        statement.close();
      }
    } catch (SQLException exception) {
      throw new SecurityException("BasicIdentityStorage: SQLite error: " + exception);
    }
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

    try {
      PreparedStatement statement = database_.prepareStatement
        (SELECT_doesKeyExist);
      statement.setString(1, identityName.toUri());
      statement.setString(2, keyId);

      try {
        ResultSet result = statement.executeQuery();

        if (result.next())
          return result.getInt(1) > 0;
        else
          return false;
      } finally {
        statement.close();
      }
    } catch (SQLException exception) {
      throw new SecurityException("BasicIdentityStorage: SQLite error: " + exception);
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

    try {
      PreparedStatement statement = database_.prepareStatement
        ("INSERT INTO Key (identity_name, key_identifier, key_type, public_key) values (?, ?, ?, ?)");
      statement.setString(1, identityName.toUri());
      statement.setString(2, keyId);
      statement.setInt(3, keyType.getNumericType());
      statement.setBytes(4, publicKeyDer.getImmutableArray());

      try {
        statement.executeUpdate();
      } finally {
        statement.close();
      }
    } catch (SQLException exception) {
      throw new SecurityException("BasicIdentityStorage: SQLite error: " + exception);
    }
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
      throw new SecurityException("BasicIdentityStorage.getKey: Empty keyName");

    String keyId = keyName.get(-1).toEscapedString();
    Name identityName = keyName.getPrefix(-1);

    try {
      PreparedStatement statement = database_.prepareStatement(SELECT_getKey);
      statement.setString(1, identityName.toUri());
      statement.setString(2, keyId);

      try {
        ResultSet result = statement.executeQuery();

        if (result.next())
          return new Blob(result.getBytes("public_key"), false);
        else
          throw new SecurityException
            ("BasicIdentityStorage.getKey: The key does not exist");
      } finally {
        statement.close();
      }
    } catch (SQLException exception) {
      throw new SecurityException("BasicIdentityStorage: SQLite error: " + exception);
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

    try {
      PreparedStatement statement = database_.prepareStatement
        ("UPDATE Key SET active=? WHERE " + WHERE_updateKeyStatus);
      statement.setInt(1, (isActive ? 1 : 0));
      statement.setString(2, identityName.toUri());
      statement.setString(3, keyId);

      try {
        statement.executeUpdate();
      } finally {
        statement.close();
      }
    } catch (SQLException exception) {
      throw new SecurityException("BasicIdentityStorage: SQLite error: " + exception);
    }
  }

  /**
   * Check if the specified certificate already exists.
   * @param certificateName The name of the certificate.
   * @return True if the certificate exists, otherwise false.
   */
  public final boolean
  doesCertificateExist(Name certificateName) throws SecurityException
  {
    try {
      PreparedStatement statement = database_.prepareStatement
        (SELECT_doesCertificateExist);
      statement.setString(1, certificateName.toUri());

      try {
        ResultSet result = statement.executeQuery();

        if (result.next())
          return result.getInt(1) > 0;
        else
          return false;
      } finally {
        statement.close();
      }
    } catch (SQLException exception) {
      throw new SecurityException("BasicIdentityStorage: SQLite error: " + exception);
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
    try {
      PreparedStatement statement = database_.prepareStatement
        ("INSERT INTO Certificate (cert_name, cert_issuer, identity_name, key_identifier, not_before, not_after, certificate_data) " +
         "values (?, ?, ?, ?, datetime(?, 'unixepoch'), datetime(?, 'unixepoch'), ?)");
      statement.setString(1, certificateName.toUri());

      Name signerName = KeyLocator.getFromSignature
        (certificate.getSignature()).getKeyName();
      statement.setString(2, signerName.toUri());

      String keyId = keyName.get(-1).toEscapedString();
      Name identity = keyName.getPrefix(-1);
      statement.setString(3, identity.toUri());
      statement.setString(4, keyId);

      // Convert from milliseconds to seconds since 1/1/1970.
      statement.setLong(5, (long)(Math.floor(certificate.getNotBefore() / 1000.0)));
      statement.setLong(6, (long)(Math.floor(certificate.getNotAfter() / 1000.0)));

      // wireEncode returns the cached encoding if available.
      statement.setBytes(7, certificate.wireEncode().getImmutableArray());

      try {
        statement.executeUpdate();
      } finally {
        statement.close();
      }
    } catch (SQLException exception) {
      throw new SecurityException("BasicIdentityStorage: SQLite error: " + exception);
    }
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
    try {
      PreparedStatement statement;
      statement = database_.prepareStatement(SELECT_getCertificate);
      statement.setString(1, certificateName.toUri());

      IdentityCertificate certificate = new IdentityCertificate();
      try {
        ResultSet result = statement.executeQuery();

        if (result.next()) {
          try {
            certificate.wireDecode(new Blob(result.getBytes("certificate_data"), false));
          } catch (EncodingException ex) {
            throw new SecurityException
              ("BasicIdentityStorage: Error decoding certificate data: " + ex);
          }
        }
        else
          throw new SecurityException
            ("BasicIdentityStorage.getKey: The key certificate not exist");
      } finally {
        statement.close();
      }

      return certificate;
    } catch (SQLException exception) {
      throw new SecurityException("BasicIdentityStorage: SQLite error: " + exception);
    }
  }

  /**
   * Get the TPM locator associated with this storage.
   * @return The TPM locator.
   * @throws SecurityException if the TPM locator doesn't exist.
   */
  public final String
  getTpmLocator() throws SecurityException
  {
    try {
      Statement statement = database_.createStatement();
      try {
        ResultSet result = statement.executeQuery(SELECT_getTpmLocator);

        if (result.next())
          return result.getString("tpm_locator");
        else
          throw new SecurityException
            ("BasicIdentityStorage.getTpmLocator: TPM info does not exist");
      } finally {
        statement.close();
      }
    } catch (SQLException exception) {
      throw new SecurityException("BasicIdentityStorage: SQLite error: " + exception);
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
    try {
      Statement statement = database_.createStatement();
      try {
        ResultSet result = statement.executeQuery(SELECT_getDefaultIdentity);

        if (result.next())
          return new Name(result.getString("identity_name"));
        else
          throw new SecurityException
            ("BasicIdentityStorage.getDefaultIdentity: The default identity is not defined");
      } finally {
        statement.close();
      }
    } catch (SQLException exception) {
      throw new SecurityException("BasicIdentityStorage: SQLite error: " + exception);
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
    try {
      PreparedStatement statement = database_.prepareStatement
        (SELECT_getDefaultKeyNameForIdentity);
      statement.setString(1, identityName.toUri());

      try {
        ResultSet result = statement.executeQuery();

        if (result.next())
          return new Name(identityName).append(result.getString("key_identifier"));
        else
          throw new SecurityException
            ("BasicIdentityStorage.getDefaultKeyNameForIdentity: The default key for the identity is not defined");
      } finally {
        statement.close();
      }
    } catch (SQLException exception) {
      throw new SecurityException("BasicIdentityStorage: SQLite error: " + exception);
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

    try {
      PreparedStatement statement = database_.prepareStatement
        (SELECT_getDefaultCertificateNameForKey);
      statement.setString(1, identityName.toUri());
      statement.setString(2, keyId);

      try {
        ResultSet result = statement.executeQuery();

        if (result.next())
          return new Name(result.getString("cert_name"));
        else
          throw new SecurityException
            ("BasicIdentityStorage.getDefaultCertificateNameForKey: The default certificate for the key name is not defined");
      } finally {
        statement.close();
      }
    } catch (SQLException exception) {
      throw new SecurityException("BasicIdentityStorage: SQLite error: " + exception);
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
    try {
      String sql = isDefault ? SELECT_getAllIdentities_default_true
        : SELECT_getAllIdentities_default_false;
      PreparedStatement statement = database_.prepareStatement(sql);

      try {
        ResultSet result = statement.executeQuery();

        while (result.next())
          nameList.add(new Name(result.getString("identity_name")));
      } finally {
        statement.close();
      }
    } catch (SQLException exception) {
      throw new SecurityException("BasicIdentityStorage: SQLite error: " + exception);
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
    try {
      String sql = isDefault ? SELECT_getAllKeyNamesOfIdentity_default_true
        : SELECT_getAllKeyNamesOfIdentity_default_false;
      PreparedStatement statement = database_.prepareStatement(sql);
      statement.setString(1, identityName.toUri());

      try {
        ResultSet result = statement.executeQuery();

        while (result.next())
          nameList.add
            (new Name(identityName).append(result.getString("key_identifier")));
      } finally {
        statement.close();
      }
    } catch (SQLException exception) {
      throw new SecurityException("BasicIdentityStorage: SQLite error: " + exception);
    }
  }

  /**
   * Append all the certificate names of a particular key name to the nameList.
   * @param keyName The key name to search for.
   * @param nameList Append result names to nameList.
   * @param isDefault If true, add only the default certificate name. If false,
   * add only the non-default certificate names.
   */
  public void
  getAllCertificateNamesOfKey
    (Name keyName, ArrayList nameList, boolean isDefault) throws SecurityException
  {
    try {
      String sql = isDefault ? SELECT_getAllCertificateNamesOfKey_default_true
        : SELECT_getAllCertificateNamesOfKey_default_false;
      PreparedStatement statement = database_.prepareStatement(sql);
      statement.setString(1, keyName.getPrefix(-1).toUri());
      statement.setString(2, keyName.get(-1).toEscapedString());

      try {
        ResultSet result = statement.executeQuery();

        while (result.next())
          nameList.add(new Name(result.getString("cert_name")));
      } finally {
        statement.close();
      }
    } catch (SQLException exception) {
      throw new SecurityException("BasicIdentityStorage: SQLite error: " + exception);
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
    try {
      // Reset the previous default identity.
      PreparedStatement statement = database_.prepareStatement
        ("UPDATE Identity SET default_identity=0 WHERE " + WHERE_setDefaultIdentity_reset);
      try {
        statement.executeUpdate();
      } finally {
        statement.close();
      }

      // Set the current default identity.
      statement = database_.prepareStatement
        ("UPDATE Identity SET default_identity=1 WHERE " + WHERE_setDefaultIdentity_set);
      statement.setString(1, identityName.toUri());
      try {
        statement.executeUpdate();
      } finally {
        statement.close();
      }
    } catch (SQLException exception) {
      throw new SecurityException("BasicIdentityStorage: SQLite error: " + exception);
    }
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

    try {
      // Reset the previous default Key.
      PreparedStatement statement = database_.prepareStatement
        ("UPDATE Key SET default_key=0 WHERE " + WHERE_setDefaultKeyNameForIdentity_reset);
      statement.setString(1, identityName.toUri());
      try {
        statement.executeUpdate();
      } finally {
        statement.close();
      }

      // Set the current default Key.
      statement = database_.prepareStatement
        ("UPDATE Key SET default_key=1 WHERE " + WHERE_setDefaultKeyNameForIdentity_set);
      statement.setString(1, identityName.toUri());
      statement.setString(2, keyId);
      try {
        statement.executeUpdate();
      } finally {
        statement.close();
      }
    } catch (SQLException exception) {
      throw new SecurityException("BasicIdentityStorage: SQLite error: " + exception);
    }
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

    try {
      // Reset the previous default Certificate.
      PreparedStatement statement = database_.prepareStatement
        ("UPDATE Certificate SET default_cert=0 WHERE " + WHERE_setDefaultCertificateNameForKey_reset);
      statement.setString(1, identityName.toUri());
      statement.setString(2, keyId);
      try {
        statement.executeUpdate();
      } finally {
        statement.close();
      }

      // Set the current default Certificate.
      statement = database_.prepareStatement
        ("UPDATE Certificate SET default_cert=1 WHERE " + WHERE_setDefaultCertificateNameForKey_set);
      statement.setString(1, identityName.toUri());
      statement.setString(2, keyId);
      statement.setString(3, certificateName.toUri());
      try {
        statement.executeUpdate();
      } finally {
        statement.close();
      }
    } catch (SQLException exception) {
      throw new SecurityException("BasicIdentityStorage: SQLite error: " + exception);
    }
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

    try {
      PreparedStatement statement = database_.prepareStatement
        ("DELETE FROM Certificate WHERE " + WHERE_deleteCertificateInfo);
      statement.setString(1, certificateName.toUri());

      try {
        statement.executeUpdate();
      } finally {
        statement.close();
      }
    } catch (SQLException exception) {
      throw new SecurityException("BasicIdentityStorage: SQLite error: " + exception);
    }
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

    try {
      PreparedStatement statement = database_.prepareStatement
        ("DELETE FROM Certificate WHERE " + WHERE_deletePublicKeyInfo);
      statement.setString(1, identityName.toUri());
      statement.setString(2, keyId);

      try {
        statement.executeUpdate();
      } finally {
        statement.close();
      }

      statement = database_.prepareStatement
        ("DELETE FROM Key WHERE " + WHERE_deletePublicKeyInfo);
      statement.setString(1, identityName.toUri());
      statement.setString(2, keyId);

      try {
        statement.executeUpdate();
      } finally {
        statement.close();
      }
    } catch (SQLException exception) {
      throw new SecurityException("BasicIdentityStorage: SQLite error: " + exception);
    }
  }

  /**
   * Delete an identity and related public keys and certificates.
   * @param identityName The identity name.
   */
  public void
  deleteIdentityInfo(Name identityName) throws SecurityException
  {
    String identity = identityName.toUri();

    try {
      PreparedStatement statement = database_.prepareStatement
        ("DELETE FROM Certificate WHERE " + WHERE_deleteIdentityInfo);
      statement.setString(1, identity);

      try {
        statement.executeUpdate();
      } finally {
        statement.close();
      }

      statement = database_.prepareStatement
        ("DELETE FROM Key WHERE " + WHERE_deleteIdentityInfo);
      statement.setString(1, identity);

      try {
        statement.executeUpdate();
      } finally {
        statement.close();
      }

      statement = database_.prepareStatement
        ("DELETE FROM Identity WHERE " + WHERE_deleteIdentityInfo);
      statement.setString(1, identity);

      try {
        statement.executeUpdate();
      } finally {
        statement.close();
      }
    } catch (SQLException exception) {
      throw new SecurityException("BasicIdentityStorage: SQLite error: " + exception);
    }
  }

  /**
   * Get the default directory that the constructor uses if databaseFilePath is
   * omitted. This does not try to create the directory.
   * @return The default database directory path.
   */
  public static File
  getDefaultDatabaseDirectoryPath()
  {
    // NOTE: Use File because java.nio.file.Path is not available before Java 7.
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
    return new File(getDefaultDatabaseDirectoryPath(), "ndnsec-public-info.db");
  }

  Connection database_ = null;
}
