/**
 * Copyright (C) 2015-2016 Regents of the University of California.
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

import net.named_data.jndn.Name;
import net.named_data.jndn.security.SecurityException;

/**
 * SqliteIdentityStorageBase is an abstract base class for the storage of
 * identity, public keys and certificates using SQLite. This base class has
 * protected SQL strings and helpers so the subclasses can work with similar
 * tables using their own SQLite libraries.
 */
public abstract class Sqlite3IdentityStorageBase extends IdentityStorage {
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

  /**
   * In table Key, set 'active' to isActive for the keyName.
   * @param keyName The name of the key.
   * @param isActive The value for the 'active' field.
   */
  protected abstract void
  updateKeyStatus(Name keyName, boolean isActive) throws SecurityException;

  /**
   * Throw an exception if it is an error for setDefaultKeyNameForIdentity to
   * set it.
   * @param keyName The key name.
   * @param identityNameCheck The identity name to check the keyName.
   * @throws SecurityException if the identity name does not match the key name
   * or other problem.
   */
  protected void
  checkSetDefaultKeyNameForIdentity(Name keyName, Name identityNameCheck)
    throws SecurityException
  {
    Name identityName = keyName.getPrefix(-1);

    if (identityNameCheck.size() > 0 && !identityNameCheck.equals(identityName))
      throw new SecurityException
        ("The specified identity name does not match the key name");
  }

  protected static final String SELECT_MASTER_TPM_INFO_TABLE =
    "SELECT name FROM sqlite_master WHERE type='table' And name='TpmInfo'";
  protected static final String SELECT_MASTER_ID_TABLE =
    "SELECT name FROM sqlite_master WHERE type='table' And name='Identity'";
  protected static final String SELECT_MASTER_KEY_TABLE =
    "SELECT name FROM sqlite_master WHERE type='table' And name='Key'";
  protected static final String SELECT_MASTER_CERT_TABLE =
    "SELECT name FROM sqlite_master WHERE type='table' And name='Certificate'";

  protected static final String INIT_TPM_INFO_TABLE =
"CREATE TABLE IF NOT EXISTS                                           \n" +
"  TpmInfo(                                                           \n" +
"      tpm_locator BLOB NOT NULL,                                     \n" +
"      PRIMARY KEY (tpm_locator)                                      \n" +
"  );                                                                 \n";

  protected static final String INIT_ID_TABLE1 =
"CREATE TABLE IF NOT EXISTS                                           \n" +
"  Identity(                                                          \n" +
"      identity_name     BLOB NOT NULL,                               \n" +
"      default_identity  INTEGER DEFAULT 0,                           \n" +
"                                                                     \n" +
"      PRIMARY KEY (identity_name)                                    \n" +
"  );                                                                 \n" +
"                                                                     \n";
  protected static final String INIT_ID_TABLE2 =
"CREATE INDEX identity_index ON Identity(identity_name);              \n";

  protected static final String INIT_KEY_TABLE1 =
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
"                                                                     \n";
  protected static final String INIT_KEY_TABLE2 =
"CREATE INDEX key_index ON Key(identity_name);                        \n";

  protected static final String INIT_CERT_TABLE1 =
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
"                                                                     \n";
  protected static final String INIT_CERT_TABLE2 =
"CREATE INDEX cert_index ON Certificate(cert_name);           \n";
  protected static final String INIT_CERT_TABLE3 =
"CREATE INDEX subject ON Certificate(identity_name);          \n";

  protected static final String SELECT_doesIdentityExist =
    "SELECT count(*) FROM Identity WHERE identity_name=?";
  protected static final String SELECT_doesKeyExist =
    "SELECT count(*) FROM Key WHERE identity_name=? AND key_identifier=?";
  protected static final String SELECT_getKey =
    "SELECT public_key FROM Key WHERE identity_name=? AND key_identifier=?";
  protected static final String SELECT_doesCertificateExist =
    "SELECT count(*) FROM Certificate WHERE cert_name=?";
  protected static final String SELECT_getCertificate =
    "SELECT certificate_data FROM Certificate WHERE cert_name=?";
  protected static final String SELECT_getDefaultIdentity =
    "SELECT identity_name FROM Identity WHERE default_identity=1";
  protected static final String SELECT_getDefaultKeyNameForIdentity =
    "SELECT key_identifier FROM Key WHERE identity_name=? AND default_key=1";
  protected static final String SELECT_getDefaultCertificateNameForKey =
    "SELECT cert_name FROM Certificate WHERE identity_name=? AND key_identifier=? AND default_cert=1";
  protected static final String SELECT_getAllIdentities_default_true =
    "SELECT identity_name FROM Identity WHERE default_identity=1";
  protected static final String SELECT_getAllIdentities_default_false =
    "SELECT identity_name FROM Identity WHERE default_identity=0";
  protected static final String SELECT_getAllKeyNamesOfIdentity_default_true =
    "SELECT key_identifier FROM Key WHERE default_key=1 and identity_name=?";
  protected static final String SELECT_getAllKeyNamesOfIdentity_default_false =
    "SELECT key_identifier FROM Key WHERE default_key=0 and identity_name=?";
  protected static final String SELECT_getAllCertificateNamesOfKey_default_true =
    "SELECT cert_name FROM Certificate" +
    "  WHERE default_cert=1 and identity_name=? and key_identifier=?";
  protected static final String SELECT_getAllCertificateNamesOfKey_default_false =
    "SELECT cert_name FROM Certificate" +
    "  WHERE default_cert=0 and identity_name=? and key_identifier=?";
  protected static final String SELECT_getTpmLocator =
    "SELECT tpm_locator FROM TpmInfo";

  protected static final String WHERE_updateKeyStatus =
    "identity_name=? AND key_identifier=?";
  protected static final String WHERE_setDefaultIdentity_reset =
    "default_identity=1";
  protected static final String WHERE_setDefaultIdentity_set =
    "identity_name=?";
  protected static final String WHERE_setDefaultKeyNameForIdentity_reset =
    "default_key=1 and identity_name=?";
  protected static final String WHERE_setDefaultKeyNameForIdentity_set =
    "identity_name=? AND key_identifier=?";
  protected static final String WHERE_setDefaultCertificateNameForKey_reset =
    "default_cert=1 AND identity_name=? AND key_identifier=?";
  protected static final String WHERE_setDefaultCertificateNameForKey_set =
    "identity_name=? AND key_identifier=? AND cert_name=?";
  protected static final String WHERE_deleteCertificateInfo =
    "cert_name=?";
  protected static final String WHERE_deletePublicKeyInfo =
    "identity_name=? and key_identifier=?";
  protected static final String WHERE_deleteIdentityInfo =
    "identity_name=?";
}
