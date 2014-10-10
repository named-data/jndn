/**
 * Copyright (C) 2014 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From code in NDN-CPP by Yingdi Yu <yingdi@cs.ucla.edu>
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

import java.nio.file.Path;
import java.nio.file.Paths;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.logging.Level;
import java.util.logging.Logger;
import net.named_data.jndn.Data;
import net.named_data.jndn.Name;
import net.named_data.jndn.security.KeyType;
import net.named_data.jndn.security.SecurityException;
import net.named_data.jndn.security.certificate.IdentityCertificate;
import net.named_data.jndn.util.Blob;

/**
 * BasicIdentityStorage extends IdentityStorage to implement a basic storage of
 * identity, public keys and certificates using SQLite.
 */
public class BasicIdentityStorage extends IdentityStorage {
  public BasicIdentityStorage() throws SecurityException
  {
    try {
      Class.forName("org.sqlite.JDBC");
    } catch (ClassNotFoundException ex) {
      // We don't expect this to happen.
      Logger.getLogger(BasicIdentityStorage.class.getName()).log(Level.SEVERE, null, ex);
      return;
    }

    Path identityDir = Paths.get(System.getProperty("user.home", "."), ".ndn");
    identityDir.toFile().mkdirs();

    try {
      Path databasePath = identityDir.resolve("ndnsec-public-info.db");
      database_ = DriverManager.getConnection("jdbc:sqlite:" + databasePath);

      Statement statement = database_.createStatement();
      // Use "try/finally instead of "try-with-resources" or "using" which are not supported before Java 7.
      try {
        //Check if the ID table exists.
        ResultSet result = statement.executeQuery
          ("SELECT name FROM sqlite_master WHERE type='table' And name='Identity'");
        boolean idTableExists = false;
        if (result.next())
          idTableExists = true;
        result.close();

        if (!idTableExists)
          statement.executeUpdate(INIT_ID_TABLE);

        //Check if the Key table exists.
        result = statement.executeQuery
          ("SELECT name FROM sqlite_master WHERE type='table' And name='Key'");
        idTableExists = false;
        if (result.next())
          idTableExists = true;
        result.close();

        if (!idTableExists)
          statement.executeUpdate(INIT_KEY_TABLE);

        //Check if the Certificate table exists.
        result = statement.executeQuery
          ("SELECT name FROM sqlite_master WHERE type='table' And name='Certificate'");
        idTableExists = false;
        if (result.next())
          idTableExists = true;
        result.close();

        if (!idTableExists)
          statement.executeUpdate(INIT_CERT_TABLE);
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
  doesIdentityExist(Name identityName)
  {
    throw new UnsupportedOperationException
      ("BasicIdentityStorage.doesIdentityExist is not implemented");
  }

  /**
   * Add a new identity. An exception will be thrown if the identity already
   * exists.
   * @param identityName The identity name to be added.
   * @throws SecurityException if the identityName is already added.
   */
  public final void
  addIdentity(Name identityName) throws SecurityException
  {
    throw new UnsupportedOperationException
      ("BasicIdentityStorage.addIdentity is not implemented");
  }

  /**
   * Revoke the identity.
   * @return True if the identity was revoked, false if not.
   */
  public final boolean
  revokeIdentity()
  {
    throw new UnsupportedOperationException
      ("BasicIdentityStorage.revokeIdentity is not implemented");
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
    Name identityName = keyName.getSubName(0, keyName.size() - 1);

    try {
      PreparedStatement statement = database_.prepareStatement
        ("SELECT count(*) FROM Key WHERE identity_name=? AND key_identifier=?");
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
   * Add a public key to the identity storage.
   * @param keyName The name of the public key to be added.
   * @param keyType Type of the public key to be added.
   * @param publicKeyDer A blob of the public key DER to be added.
   * @throws SecurityException if a key with the keyName already exists.
   */
  public final void
  addKey(Name keyName, KeyType keyType, Blob publicKeyDer) throws SecurityException
  {
    throw new UnsupportedOperationException
      ("BasicIdentityStorage.addKey is not implemented");
  }

  /**
   * Get the public key DER blob from the identity storage.
   * @param keyName The name of the requested public key.
   * @return The DER Blob.  If not found, return a Blob with a null pointer.
   */
  public final Blob
  getKey(Name keyName) throws SecurityException
  {
    if (!doesKeyExist(keyName))
      return new Blob();

    String keyId = keyName.get(-1).toEscapedString();
    Name identityName = keyName.getSubName(0, keyName.size() - 1);

    try {
      PreparedStatement statement = database_.prepareStatement
        ("SELECT public_key FROM Key WHERE identity_name=? AND key_identifier=?");
      statement.setString(1, identityName.toUri());
      statement.setString(2, keyId);

      try {
        ResultSet result = statement.executeQuery();

        if (result.next())
          return new Blob(result.getBytes("public_key"));
        else
          return new Blob();
      } finally {
        statement.close();
      }
    } catch (SQLException exception) {
      throw new SecurityException("BasicIdentityStorage: SQLite error: " + exception);
    }
  }

  /**
   * Get the KeyType of the public key with the given keyName.
   * @param keyName The name of the requested public key.
   * @return The KeyType, for example KeyType.RSA.
   * @throws SecurityException if the keyName is not found.
   */
  public final KeyType
  getKeyType(Name keyName) throws SecurityException
  {
    throw new UnsupportedOperationException
      ("BasicIdentityStorage.getKeyType is not implemented");
  }

  /**
   * Activate a key.  If a key is marked as inactive, its private part will not
   * be used in packet signing.
   * @param keyName The name of the key.
   */
  public final void
  activateKey(Name keyName)
  {
    throw new UnsupportedOperationException
      ("BasicIdentityStorage.activateKey is not implemented");
  }

  /**
   * Deactivate a key. If a key is marked as inactive, its private part will not
   * be used in packet signing.
   * @param keyName The name of the key.
   */
  public final void
  deactivateKey(Name keyName)
  {
    throw new UnsupportedOperationException
      ("BasicIdentityStorage.deactivateKey is not implemented");
  }

  /**
   * Check if the specified certificate already exists.
   * @param certificateName The name of the certificate.
   * @return True if the certificate exists, otherwise false.
   */
  public final boolean
  doesCertificateExist(Name certificateName)
  {
    throw new UnsupportedOperationException
      ("BasicIdentityStorage.doesCertificateExist is not implemented");
  }

  /**
   * Add a certificate to the identity storage.
   * @param certificate The certificate to be added.  This makes a copy of the
   * certificate.
   * @throws SecurityException if the certificate is already installed.
   */
  public final void
  addCertificate(IdentityCertificate certificate) throws SecurityException
  {
    throw new UnsupportedOperationException
      ("BasicIdentityStorage.addCertificate is not implemented");
  }

  /**
   * Get a certificate from the identity storage.
   * @param certificateName The name of the requested certificate.
   * @param allowAny If false, only a valid certificate will be
   * returned, otherwise validity is disregarded.
   * @return The requested certificate. If not found, return null.
   */
  public final Data
  getCertificate(Name certificateName, boolean allowAny)
  {
    throw new UnsupportedOperationException
      ("BasicIdentityStorage.getCertificate is not implemented");
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
        ResultSet result = statement.executeQuery
          ("SELECT identity_name FROM Identity WHERE default_identity=1");

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
        ("SELECT key_identifier FROM Key WHERE identity_name=? AND default_key=1");
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
    Name identityName = keyName.getSubName(0, keyName.size() - 1);

    try {
      PreparedStatement statement = database_.prepareStatement
        ("SELECT cert_name FROM Certificate WHERE identity_name=? AND key_identifier=? AND default_cert=1");
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
   * Set the default identity.  If the identityName does not exist, then clear
   * the default identity so that getDefaultIdentity() throws an exception.
   * @param identityName The default identity name.
   */
  public final void
  setDefaultIdentity(Name identityName)
  {
    throw new UnsupportedOperationException
      ("BasicIdentityStorage.setDefaultIdentity is not implemented");
  }

  /**
   * Set the default key name for the specified identity.
   * @param keyName The key name.
   * @param identityNameCheck The identity name to check the keyName.
   */
  public final void
  setDefaultKeyNameForIdentity(Name keyName, Name identityNameCheck)
  {
    throw new UnsupportedOperationException
      ("BasicIdentityStorage.setDefaultKeyNameForIdentity is not implemented");
  }

  /**
   * Set the default key name for the specified identity.
   * @param keyName The key name.
   * @param certificateName The certificate name.
   */
  public final void
  setDefaultCertificateNameForKey(Name keyName, Name certificateName)
  {
    throw new UnsupportedOperationException
      ("BasicIdentityStorage.setDefaultCertificateNameForKey is not implemented");
  }

  private static final String INIT_ID_TABLE =
"CREATE TABLE IF NOT EXISTS                                           \n" +
"  Identity(                                                          \n" +
"      identity_name     BLOB NOT NULL,                               \n" +
"      default_identity  INTEGER DEFAULT 0,                           \n" +
"                                                                     \n" +
"      PRIMARY KEY (identity_name)                                    \n" +
"  );                                                                 \n" +
"                                                                     \n" +
"CREATE INDEX identity_index ON Identity(identity_name);              \n";

  private static final String INIT_KEY_TABLE =
"CREATE TABLE IF NOT EXISTS                                           \n" +
"  Key(                                                               \n" +
"      identity_name     BLOB NOT NULL,                               \n" +
"      key_identifier    BLOB NOT NULL,                               \n" +
"      key_type          INTEGER,                                     \n" +
"      public_key        BLOB,                                        \n" +
"      default_key       INTEGER DEFAULT 0,                           \n" +
"      active            INTEGER DEFAULT 0,                           \n" +
"                                                                     \n" +
"      PRIMARY KEY (identity_name, key_identifier)                    \n" +
"  );                                                                 \n" +
"                                                                     \n" +
"CREATE INDEX key_index ON Key(identity_name);                        \n";

  private static final String INIT_CERT_TABLE =
"CREATE TABLE IF NOT EXISTS                                           \n" +
"  Certificate(                                                       \n" +
"      cert_name         BLOB NOT NULL,                               \n" +
"      cert_issuer       BLOB NOT NULL,                               \n" +
"      identity_name     BLOB NOT NULL,                               \n" +
"      key_identifier    BLOB NOT NULL,                               \n" +
"      not_before        TIMESTAMP,                                   \n" +
"      not_after         TIMESTAMP,                                   \n" +
"      certificate_data  BLOB NOT NULL,                               \n" +
"      valid_flag        INTEGER DEFAULT 1,                           \n" +
"      default_cert      INTEGER DEFAULT 0,                           \n" +
"                                                                     \n" +
"      PRIMARY KEY (cert_name)                                        \n" +
"  );                                                                 \n" +
"                                                                     \n" +
"CREATE INDEX cert_index ON Certificate(cert_name);           \n" +
"CREATE INDEX subject ON Certificate(identity_name);          \n";

  Connection database_ = null;
}
