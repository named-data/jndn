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
  public BasicIdentityStorage() throws SQLException
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
  }

  public final boolean
  doesIdentityExist(Name identityName)
  {
    throw new UnsupportedOperationException
      ("BasicIdentityStorage.doesIdentityExist is not implemented");
  }

  public final void
  addIdentity(Name identityName) throws SecurityException
  {
    throw new UnsupportedOperationException
      ("BasicIdentityStorage.addIdentity is not implemented");
  }

  public final boolean
  revokeIdentity()
  {
    throw new UnsupportedOperationException
      ("BasicIdentityStorage.revokeIdentity is not implemented");
  }

  public final boolean
  doesKeyExist(Name keyName)
  {
    throw new UnsupportedOperationException
      ("BasicIdentityStorage.doesKeyExist is not implemented");
  }

  public final void
  addKey(Name keyName, KeyType keyType, Blob publicKeyDer) throws SecurityException
  {
    throw new UnsupportedOperationException
      ("BasicIdentityStorage.addKey is not implemented");
  }

  public final Blob
  getKey(Name keyName)
  {
    throw new UnsupportedOperationException
      ("BasicIdentityStorage.getKey is not implemented");
  }

  public final KeyType
  getKeyType(Name keyName) throws SecurityException
  {
    throw new UnsupportedOperationException
      ("BasicIdentityStorage.getKeyType is not implemented");
  }

  public final void
  activateKey(Name keyName)
  {
    throw new UnsupportedOperationException
      ("BasicIdentityStorage.activateKey is not implemented");
  }

  public final void
  deactivateKey(Name keyName)
  {
    throw new UnsupportedOperationException
      ("BasicIdentityStorage.deactivateKey is not implemented");
  }

  public final boolean
  doesCertificateExist(Name certificateName)
  {
    throw new UnsupportedOperationException
      ("BasicIdentityStorage.doesCertificateExist is not implemented");
  }

  public final void
  addCertificate(IdentityCertificate certificate) throws SecurityException
  {
    throw new UnsupportedOperationException
      ("BasicIdentityStorage.addCertificate is not implemented");
  }

  public final Data
  getCertificate(Name certificateName, boolean allowAny)
  {
    throw new UnsupportedOperationException
      ("BasicIdentityStorage.getCertificate is not implemented");
  }

  /*****************************************
   *           Get/Set Default             *
   *****************************************/

  public final Name
  getDefaultIdentity() throws SecurityException
  {
    throw new UnsupportedOperationException
      ("BasicIdentityStorage.getDefaultIdentity is not implemented");
  }

  public final Name
  getDefaultKeyNameForIdentity(Name identityName) throws SecurityException
  {
    throw new UnsupportedOperationException
      ("BasicIdentityStorage.getDefaultKeyNameForIdentity is not implemented");
  }

  public final Name
  getDefaultCertificateNameForKey(Name keyName) throws SecurityException
  {
    throw new UnsupportedOperationException
      ("BasicIdentityStorage.getDefaultCertificateNameForKey is not implemented");
  }

  public final void
  setDefaultIdentity(Name identityName)
  {
    throw new UnsupportedOperationException
      ("BasicIdentityStorage.setDefaultIdentity is not implemented");
  }

  public final void
  setDefaultKeyNameForIdentity(Name keyName, Name identityNameCheck)
  {
    throw new UnsupportedOperationException
      ("BasicIdentityStorage.setDefaultKeyNameForIdentity is not implemented");
  }

  public final void
  setDefaultCertificateNameForKey(Name keyName, Name certificateName)
  {
    throw new UnsupportedOperationException
      ("BasicIdentityStorage.setDefaultCertificateNameForKey is not implemented");
  }

  static final String INIT_ID_TABLE =
"CREATE TABLE IF NOT EXISTS                                           \n" +
"  Identity(                                                          \n" +
"      identity_name     BLOB NOT NULL,                               \n" +
"      default_identity  INTEGER DEFAULT 0,                           \n" +
"                                                                     \n" +
"      PRIMARY KEY (identity_name)                                    \n" +
"  );                                                                 \n" +
"                                                                     \n" +
"CREATE INDEX identity_index ON Identity(identity_name);              \n";

  static final String INIT_KEY_TABLE =
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

  static final String INIT_CERT_TABLE =
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
