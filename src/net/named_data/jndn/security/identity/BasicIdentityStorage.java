/**
 * Copyright (C) 2014 Regents of the University of California.
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
import java.util.logging.Level;
import java.util.logging.Logger;
import net.named_data.jndn.Name;
import net.named_data.jndn.Sha256WithRsaSignature;
import net.named_data.jndn.encoding.EncodingException;
import net.named_data.jndn.security.KeyType;
import net.named_data.jndn.security.SecurityException;
import net.named_data.jndn.security.certificate.IdentityCertificate;
import net.named_data.jndn.util.Blob;

/**
 * BasicIdentityStorage extends IdentityStorage to implement a basic storage of
 * identity, public keys and certificates using SQLite.
 */
public class BasicIdentityStorage extends IdentityStorage {
  /**
   * Create a new BasicIdentityStorage to work the SQLite in the default
   * location.
   */
  public BasicIdentityStorage() throws SecurityException
  {
    // NOTE: Use File because java.nio.file.Path is not available before Java 7.
    File identityDir = new File(System.getProperty("user.home", "."), ".ndn");
    identityDir.mkdirs();
    File databasePath = new File(identityDir, "ndnsec-public-info.db");
    construct(databasePath.getAbsolutePath());
  }

  /**
   * Create a new BasicIdentityStorage to work with the given SQLite file.
   * @param databaseFilePath The path of the SQLite file. If
      omitted, use the default location.
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
  doesIdentityExist(Name identityName) throws SecurityException
  {
    try {
      PreparedStatement statement = database_.prepareStatement
        ("SELECT count(*) FROM Identity WHERE identity_name=?");
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
   * Add a public key to the identity storage. Also call addIdentity to ensure
   * that the identityName for the key exists.
   * @param keyName The name of the public key to be added.
   * @param keyType Type of the public key to be added.
   * @param publicKeyDer A blob of the public key DER to be added.
   * @throws SecurityException if a key with the keyName already exists.
   */
  public final void
  addKey(Name keyName, KeyType keyType, Blob publicKeyDer) throws SecurityException
  {
    if (keyName.size() == 0)
      return;

    if (doesKeyExist(keyName))
      throw new SecurityException("a key with the same name already exists!");

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
   * @return The DER Blob.  If not found, return a Blob with a null pointer.
   */
  public final Blob
  getKey(Name keyName) throws SecurityException
  {
    if (!doesKeyExist(keyName))
      return new Blob();

    String keyId = keyName.get(-1).toEscapedString();
    Name identityName = keyName.getPrefix(-1);

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
    String keyId = keyName.get(-1).toEscapedString();
    Name identityName = keyName.getPrefix(-1);

    try {
      PreparedStatement statement = database_.prepareStatement
        ("SELECT key_type FROM Key WHERE identity_name=? AND key_identifier=?");
      statement.setString(1, identityName.toUri());
      statement.setString(2, keyId);

      try {
        ResultSet result = statement.executeQuery();

        if (result.next())
          return KeyType.values()[result.getInt("key_type")];
        else
          throw new SecurityException
            ("Cannot get public key type because the keyName doesn't exist");
      } finally {
        statement.close();
      }
    } catch (SQLException exception) {
      throw new SecurityException("BasicIdentityStorage: SQLite error: " + exception);
    }
  }

  /**
   * Activate a key.  If a key is marked as inactive, its private part will not
   * be used in packet signing.
   * @param keyName The name of the key.
   */
  public final void
  activateKey(Name keyName) throws SecurityException
  {
    updateKeyStatus(keyName, true);
  }

  /**
   * Deactivate a key. If a key is marked as inactive, its private part will not
   * be used in packet signing.
   * @param keyName The name of the key.
   */
  public final void
  deactivateKey(Name keyName) throws SecurityException
  {
    updateKeyStatus(keyName, false);
  }

  private void
  updateKeyStatus(Name keyName, boolean isActive) throws SecurityException
  {
    String keyId = keyName.get(-1).toEscapedString();
    Name identityName = keyName.getPrefix(-1);

    try {
      PreparedStatement statement = database_.prepareStatement
        ("UPDATE Key SET active=? WHERE identity_name=? AND key_identifier=?");
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
        ("SELECT count(*) FROM Certificate WHERE cert_name=?");
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
   * Add a certificate to the identity storage.
   * @param certificate The certificate to be added.  This makes a copy of the
   * certificate.
   * @throws SecurityException if the certificate is already installed.
   */
  public final void
  addCertificate(IdentityCertificate certificate) throws SecurityException
  {
    Name certificateName = certificate.getName();
    Name keyName = certificate.getPublicKeyName();

    if (!doesKeyExist(keyName))
      throw new SecurityException
        ("No corresponding Key record for certificate!" + keyName.toUri() +
         " " + certificateName.toUri());

    // Check if the certificate already exists.
    if (doesCertificateExist(certificateName))
      throw new SecurityException("Certificate has already been installed!");

    String keyId = keyName.get(-1).toEscapedString();
    Name identity = keyName.getPrefix(-1);

    // Check if the public key of the certificate is the same as the key record.

    Blob keyBlob = getKey(keyName);

    if (keyBlob.isNull() || !keyBlob.equals(certificate.getPublicKeyInfo().getKeyDer()))
      throw new SecurityException("Certificate does not match the public key!");

    // Insert the certificate.
    try {
      PreparedStatement statement = database_.prepareStatement
        ("INSERT INTO Certificate (cert_name, cert_issuer, identity_name, key_identifier, not_before, not_after, certificate_data) " +
         "values (?, ?, ?, ?, datetime(?, 'unixepoch'), datetime(?, 'unixepoch'), ?)");
      statement.setString(1, certificateName.toUri());

      // TODO: Support signature types other than Sha256WithRsaSignature.
      if (!(certificate.getSignature() instanceof Sha256WithRsaSignature))
        throw new SecurityException
        ("BasicIdentityStorage: addCertificate: Signature is not Sha256WithRsaSignature.");
      Sha256WithRsaSignature signature = (Sha256WithRsaSignature)certificate.getSignature();
      Name signerName = signature.getKeyLocator().getKeyName();
      statement.setString(2, signerName.toUri());

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
   * @param allowAny If false, only a valid certificate will be
   * returned, otherwise validity is disregarded.
   * @return The requested certificate. If not found, return null.
   */
  public final IdentityCertificate
  getCertificate(Name certificateName, boolean allowAny) throws SecurityException
  {
    if (doesCertificateExist(certificateName)) {
      try {
        PreparedStatement statement;

        if (!allowAny) {
          throw new UnsupportedOperationException
            ("BasicIdentityStorage.getCertificate for !allowAny is not implemented");
          /*
          statement = database_.prepareStatement
            ("SELECT certificate_data FROM Certificate " +
             "WHERE cert_name=? AND not_before<datetime(?, 'unixepoch') AND not_after>datetime(?, 'unixepoch') and valid_flag=1");
          statement.setString(1, certificateName.toUri());
          sqlite3_bind_int64(statement, 2, (sqlite3_int64)floor(ndn_getNowMilliseconds() / 1000.0));
          sqlite3_bind_int64(statement, 3, (sqlite3_int64)floor(ndn_getNowMilliseconds() / 1000.0));
          */
        }
        else {
          statement = database_.prepareStatement
            ("SELECT certificate_data FROM Certificate WHERE cert_name=?");
          statement.setString(1, certificateName.toUri());
        }

        IdentityCertificate certificate = new IdentityCertificate();
        try {
          ResultSet result = statement.executeQuery();

          if (result.next()) {
            try {
              certificate.wireDecode(new Blob(result.getBytes("certificate_data")));
            } catch (EncodingException ex) {
              throw new SecurityException
                ("BasicIdentityStorage: Error decoding certificate data: " + ex);
            }
          }
        } finally {
          statement.close();
        }

        return certificate;
      } catch (SQLException exception) {
        throw new SecurityException("BasicIdentityStorage: SQLite error: " + exception);
      }
    }
    else
      return new IdentityCertificate();
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
    Name identityName = keyName.getPrefix(-1);

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
  setDefaultIdentity(Name identityName) throws SecurityException
  {
    try {
      // Reset the previous default identity.
      PreparedStatement statement = database_.prepareStatement
        ("UPDATE Identity SET default_identity=0 WHERE default_identity=1");
      try {
        statement.executeUpdate();
      } finally {
        statement.close();
      }

      // Set the current default identity.
      statement = database_.prepareStatement
        ("UPDATE Identity SET default_identity=1 WHERE identity_name=?");
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
   * Set the default key name for the specified identity.
   * @param keyName The key name.
   * @param identityNameCheck The identity name to check the keyName.
   */
  public final void
  setDefaultKeyNameForIdentity(Name keyName, Name identityNameCheck)
    throws SecurityException
  {
    String keyId = keyName.get(-1).toEscapedString();
    Name identityName = keyName.getPrefix(-1);

    if (identityNameCheck.size() > 0 && !identityNameCheck.equals(identityName))
      throw new SecurityException("Specified identity name does not match the key name");

    try {
      // Reset the previous default Key.
      PreparedStatement statement = database_.prepareStatement
        ("UPDATE Key SET default_key=0 WHERE default_key=1 and identity_name=?");
      statement.setString(1, identityName.toUri());
      try {
        statement.executeUpdate();
      } finally {
        statement.close();
      }

      // Set the current default Key.
      statement = database_.prepareStatement
        ("UPDATE Key SET default_key=1 WHERE identity_name=? AND key_identifier=?");
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
        ("UPDATE Certificate SET default_cert=0 WHERE default_cert=1 AND identity_name=? AND key_identifier=?");
      statement.setString(1, identityName.toUri());
      statement.setString(2, keyId);
      try {
        statement.executeUpdate();
      } finally {
        statement.close();
      }

      // Set the current default Certificate.
      statement = database_.prepareStatement
        ("UPDATE Certificate SET default_cert=1 WHERE identity_name=? AND key_identifier=? AND cert_name=?");
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
        ("DELETE FROM Certificate WHERE cert_name=?");
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
        ("DELETE FROM Certificate WHERE identity_name=? and key_identifier=?");
      statement.setString(1, identityName.toUri());
      statement.setString(2, keyId);

      try {
        statement.executeUpdate();
      } finally {
        statement.close();
      }

      statement = database_.prepareStatement
        ("DELETE FROM Key WHERE identity_name=? and key_identifier=?");
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
        ("DELETE FROM Certificate WHERE identity_name=?");
      statement.setString(1, identity);

      try {
        statement.executeUpdate();
      } finally {
        statement.close();
      }

      statement = database_.prepareStatement
        ("DELETE FROM Key WHERE identity_name=?");
      statement.setString(1, identity);

      try {
        statement.executeUpdate();
      } finally {
        statement.close();
      }

      statement = database_.prepareStatement
        ("DELETE FROM Identity WHERE identity_name=?");
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
