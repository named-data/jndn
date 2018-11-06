/**
 * Copyright (C) 2018 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From the NAC library https://github.com/named-data/name-based-access-control/blob/new/src/decryptor.cpp
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

package net.named_data.jndn.encrypt;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import net.named_data.jndn.Data;
import net.named_data.jndn.Face;
import net.named_data.jndn.Interest;
import net.named_data.jndn.KeyLocatorType;
import net.named_data.jndn.Name;
import net.named_data.jndn.NetworkNack;
import net.named_data.jndn.OnData;
import net.named_data.jndn.OnNetworkNack;
import net.named_data.jndn.OnTimeout;
import net.named_data.jndn.security.KeyChain;
import net.named_data.jndn.security.SafeBag;
import net.named_data.jndn.security.pib.Pib;
import net.named_data.jndn.security.pib.PibIdentity;
import net.named_data.jndn.security.pib.PibKey;
import net.named_data.jndn.security.v2.Validator;
import net.named_data.jndn.util.Blob;

/**
 * DecryptorV2 decrypts the supplied EncryptedContent element, using
 * asynchronous operations, contingent on the retrieval of the CK Data packet,
 * the KDK, and the successful decryption of both of these. For the meaning of
 * "KDK", etc. see:
 * https://github.com/named-data/name-based-access-control/blob/new/docs/spec.rst
 */
public class DecryptorV2 {
  public interface DecryptSuccessCallback {
    void onSuccess(Blob plainData);
  }

  /**
   * Create a DecryptorV2 with the given parameters.
   * @param credentialsKey The credentials key to be used to retrieve and
   * decrypt the KDK.
   * @param validator The validation policy to ensure the validity of the KDK
   * and CK.
   * @param keyChain The KeyChain that will be used to decrypt the KDK.
   * @param face The Face that will be used to fetch the CK and KDK.
   */
  public DecryptorV2
    (PibKey credentialsKey, Validator validator, KeyChain keyChain, Face face)
  {
    credentialsKey_ = credentialsKey;
    // validator_ = validator;
    face_ = face;
    keyChain_ = keyChain;
    try {
      internalKeyChain_ = new KeyChain("pib-memory:", "tpm-memory:");
    } catch (Exception ex) {
      // We are just creating an in-memory store, so we don't expect an error.
      throw new Error("Error creating in-memory KeyChain: " + ex);
    }
  }

  public void
  shutdown()
  {
    for (ContentKey contentKey : contentKeys_.values()) {
      if (contentKey.pendingInterest > 0) {
        face_.removePendingInterest(contentKey.pendingInterest);
        contentKey.pendingInterest = 0;

        for (ContentKey.PendingDecrypt pendingDecrypt : contentKey.pendingDecrypts)
          pendingDecrypt.onError.onError
            (EncryptError.ErrorCode.CkRetrievalFailure,
             "Canceling pending decrypt as ContentKey is being destroyed");

        // Clear is not really necessary, but just in case.
        contentKey.pendingDecrypts.clear();
      }
    }
  }

  /**
   * Asynchronously decrypt the encryptedContent.
   * @param encryptedContent The EncryptedContent to decrypt, which must have
   * a KeyLocator with a KEYNAME and and initial vector. This does not copy
   * the EncryptedContent object. If you may change it later, then pass in a
   * copy of the object.
   * @param onSuccess On successful decryption, this calls
   * onSuccess.onSuccess(plainData) where plainData is the decrypted Blob.
   * NOTE: The library will log any exceptions thrown by this callback, but for
   * better error handling the callback should catch and properly handle any
   * exceptions.
   * @param onError On failure, this calls onError.onError(errorCode, message)
   * where errorCode is from the EncryptError.ErrorCode enum, and message is an
   * error string.
   * NOTE: The library will log any exceptions thrown by this callback, but for
   * better error handling the callback should catch and properly handle any
   * exceptions.
   */
  public final void
  decrypt
    (EncryptedContent encryptedContent, DecryptSuccessCallback onSuccess,
     EncryptError.OnError onError)
    throws IOException
  {
    if (encryptedContent.getKeyLocator().getType() != KeyLocatorType.KEYNAME) {
      logger_.log(Level.INFO,
        "Missing required KeyLocator in the supplied EncryptedContent block");
      onError.onError(EncryptError.ErrorCode.MissingRequiredKeyLocator,
        "Missing required KeyLocator in the supplied EncryptedContent block");
      return;
    }

    if (!encryptedContent.hasInitialVector()) {
      logger_.log(Level.INFO,
        "Missing required initial vector in the supplied EncryptedContent block");
      onError.onError(EncryptError.ErrorCode.MissingRequiredInitialVector,
        "Missing required initial vector in the supplied EncryptedContent block");
      return;
    }

    Name ckName = encryptedContent.getKeyLocatorName();
    ContentKey contentKey = contentKeys_.get(ckName);
    boolean isNew = (contentKey == null);
    if (isNew) {
      contentKey = new ContentKey();
      contentKeys_.put(ckName, contentKey);
    }

    if (contentKey.isRetrieved)
      doDecrypt(encryptedContent, contentKey.bits, onSuccess, onError);
    else {
      logger_.log(Level.INFO,
        "CK {0} not yet available, so adding to the pending decrypt queue",
        ckName);
      contentKey.pendingDecrypts.add(new ContentKey.PendingDecrypt
        (encryptedContent, onSuccess, onError));
    }

    if (isNew)
      fetchCk(ckName, contentKey, onError, EncryptorV2.N_RETRIES);
  }

  public static class ContentKey {
    public static class PendingDecrypt {
      public PendingDecrypt
        (EncryptedContent encryptedContent, DecryptSuccessCallback onSuccess,
         EncryptError.OnError onError)
      {
        this.encryptedContent = encryptedContent;
        this.onSuccess = onSuccess;
        this.onError = onError;
      }

      public EncryptedContent encryptedContent;
      public DecryptSuccessCallback onSuccess;
      public EncryptError.OnError onError;
    };

    public boolean isRetrieved = false;
    public Blob bits;
    public long pendingInterest = 0;
    public ArrayList<PendingDecrypt> pendingDecrypts = new ArrayList();
  }

  private void
  fetchCk
    (final Name ckName, final ContentKey contentKey,
     final EncryptError.OnError onError, final int nTriesLeft)
  {
    // The full name of the CK is
    //
    // <whatever-prefix>/CK/<ck-id>  /ENCRYPTED-BY /<kek-prefix>/KEK/<key-id>
    // \                          /                \                        /
    //  -----------  -------------                  -----------  -----------
    //             \/                                          \/
    //   from the encrypted data          unknown (name in retrieved CK is used to determine KDK)

    logger_.log(Level.INFO, "Fetching CK {0}", ckName);

    try {
      contentKey.pendingInterest = face_.expressInterest
        (new Interest(ckName).setMustBeFresh(false).setCanBePrefix(true),
         new OnData() {
           public void onData(Interest ckInterest, Data ckData) {
             try {
               contentKey.pendingInterest = 0;
               // TODO: Verify that the key is legitimate.
               Name[] kdkPrefix = new Name[1];
               Name[] kdkIdentityName = new Name[1];
               Name[] kdkKeyName = new Name[1];
               if (!extractKdkInfoFromCkName
                   (ckData.getName(), ckInterest.getName(), onError, kdkPrefix,
                    kdkIdentityName, kdkKeyName))
                 // The error has already been reported.
                 return;

               // Check if the KDK already exists.
               PibIdentity kdkIdentity = null;
               try {
                 kdkIdentity = internalKeyChain_.getPib().getIdentity(kdkIdentityName[0]);
               } catch (Pib.Error ex) {
               }
               if (kdkIdentity != null) {
                 PibKey kdkKey = null;
                 try {
                   kdkKey = kdkIdentity.getKey(kdkKeyName[0]);
                 } catch (Pib.Error ex) {
                 }
                 if (kdkKey != null) {
                   // The KDK was already fetched and imported.
                   logger_.log(Level.INFO,
                     "KDK {0} already exists, so directly using it to decrypt the CK",
                     kdkKeyName);
                   decryptCkAndProcessPendingDecrypts
                     (contentKey, ckData, kdkKeyName[0], onError);
                   return;
                 }
               }

               fetchKdk
                 (contentKey, kdkPrefix[0], ckData, onError, EncryptorV2.N_RETRIES);
             } catch (Exception ex) {
               onError.onError(EncryptError.ErrorCode.General,
                 "Error in fetchCk onData: " + ex);
             }
           }
         },
         new OnTimeout() {
           public void onTimeout(Interest interest) {
             contentKey.pendingInterest = 0;
             if (nTriesLeft > 1)
               fetchCk(ckName, contentKey, onError, nTriesLeft - 1);
             else
               onError.onError(EncryptError.ErrorCode.CkRetrievalTimeout,
                 "Retrieval of CK [" + interest.getName().toUri() + "] timed out");
           }
         },
         new OnNetworkNack() {
           public void onNetworkNack(Interest interest, NetworkNack networkNack) {
             contentKey.pendingInterest = 0;
             onError.onError(EncryptError.ErrorCode.CkRetrievalFailure,
               "Retrieval of CK [" + interest.getName().toUri() +
               "] failed. Got NACK (" + networkNack.getReason() + ")");
           }
         });
    } catch (Exception ex) {
      onError.onError(EncryptError.ErrorCode.General,
        "expressInterest error: " + ex);
    }
  }

  private void
  fetchKdk
    (final ContentKey contentKey, final Name kdkPrefix, final Data ckData,
     final EncryptError.OnError onError, final int nTriesLeft)
  {
    // <kdk-prefix>/KDK/<kdk-id>    /ENCRYPTED-BY  /<credential-identity>/KEY/<key-id>
    // \                          /                \                                /
    //  -----------  -------------                  ---------------  ---------------
    //             \/                                              \/
    //     from the CK data                                from configuration

    Name kdkName = new Name(kdkPrefix);
    kdkName
      .append(EncryptorV2.NAME_COMPONENT_ENCRYPTED_BY)
      .append(credentialsKey_.getName());

    logger_.log(Level.INFO, "Fetching KDK {0}", kdkName);

    try {
      contentKey.pendingInterest = face_.expressInterest
        (new Interest(kdkName).setMustBeFresh(true).setCanBePrefix(false),
         new OnData() {
           public void onData(Interest kdkInterest, Data kdkData) {
             contentKey.pendingInterest = 0;
             // TODO: Verify that the key is legitimate.

             boolean isOk = decryptAndImportKdk(kdkData, onError);
             if (!isOk)
               return;
             // This way of getting the kdkKeyName is a bit hacky.
             Name kdkKeyName = kdkPrefix.getPrefix(-2)
               .append("KEY").append(kdkPrefix.get(-1));
             decryptCkAndProcessPendingDecrypts
               (contentKey, ckData, kdkKeyName, onError);
           }
         },
         new OnTimeout() {
           public void onTimeout(Interest interest) {
             contentKey.pendingInterest = 0;
             if (nTriesLeft > 1)
               fetchKdk(contentKey, kdkPrefix, ckData, onError, nTriesLeft - 1);
             else
               onError.onError(EncryptError.ErrorCode.KdkRetrievalTimeout,
                 "Retrieval of KDK [" + interest.getName().toUri() + "] timed out");
           }
         },
         new OnNetworkNack() {
           public void onNetworkNack(Interest interest, NetworkNack networkNack) {
             contentKey.pendingInterest = 0;
             onError.onError(EncryptError.ErrorCode.KdkRetrievalFailure,
               "Retrieval of KDK [" + interest.getName().toUri() +
               "] failed. Got NACK (" + networkNack.getReason() + ")");
           }
         });
    } catch (Exception ex) {
      onError.onError(EncryptError.ErrorCode.General,
        "expressInterest error: " + ex);
    }
  }

  /**
   * @return True for success, false for error (where this has called onError).
   */
  private boolean
  decryptAndImportKdk(Data kdkData, EncryptError.OnError onError)
  {
    try {
      logger_.log(Level.INFO, "Decrypting and importing KDK {0}", kdkData.getName());
      EncryptedContent encryptedContent = new EncryptedContent();
      encryptedContent.wireDecodeV2(kdkData.getContent());

      SafeBag safeBag = new SafeBag(encryptedContent.getPayload());
      Blob secret = keyChain_.getTpm().decrypt
        (encryptedContent.getPayloadKey().buf(), credentialsKey_.getName());
      if (secret.isNull()) {
        onError.onError(EncryptError.ErrorCode.TpmKeyNotFound,
           "Could not decrypt secret, " + credentialsKey_.getName().toUri() +
           " not found in TPM");
        return false;
      }

      internalKeyChain_.importSafeBag(safeBag, secret.buf());
      return true;
    } catch (Exception ex) {
      // This can be EncodingException, Pib.Error, Tpm.Error, or a bunch of
      // other runtime-derived errors.
      onError.onError(EncryptError.ErrorCode.DecryptionFailure,
         "Failed to decrypt KDK [" + kdkData.getName().toUri() + "]: " + ex);
      return false;
    }
  }

  private void
  decryptCkAndProcessPendingDecrypts
    (ContentKey contentKey, Data ckData, Name kdkKeyName,
     EncryptError.OnError onError)
  {
    logger_.log(Level.INFO, "Decrypting CK data {0}", ckData.getName());

    EncryptedContent content = new EncryptedContent();
    try {
      content.wireDecodeV2(ckData.getContent());
    } catch (Exception ex) {
      onError.onError(EncryptError.ErrorCode.InvalidEncryptedFormat,
        "Error decrypting EncryptedContent: " + ex);
      return;
    }

    Blob ckBits;
    try {
      ckBits = internalKeyChain_.getTpm().decrypt
        (content.getPayload().buf(), kdkKeyName);
    } catch (Exception ex) {
      // We don't expect this from the in-memory KeyChain.
      onError.onError(EncryptError.ErrorCode.DecryptionFailure,
        "Error decrypting the CK EncryptedContent " + ex);
      return;
    }
    
    if (ckBits.isNull()) {
      onError.onError(EncryptError.ErrorCode.TpmKeyNotFound,
        "Could not decrypt secret, " + kdkKeyName.toUri() + " not found in TPM");
      return;
    }

    contentKey.bits = ckBits;
    contentKey.isRetrieved = true;

    for (ContentKey.PendingDecrypt pendingDecrypt : contentKey.pendingDecrypts)
      // TODO: If this calls onError, should we quit?
      doDecrypt
        (pendingDecrypt.encryptedContent, contentKey.bits,
         pendingDecrypt.onSuccess, pendingDecrypt.onError);

    contentKey.pendingDecrypts.clear();
  }

  private static void
  doDecrypt
    (EncryptedContent content, Blob ckBits, DecryptSuccessCallback onSuccess,
     EncryptError.OnError onError)
  {
    if (!content.hasInitialVector()) {
      onError.onError(EncryptError.ErrorCode.MissingRequiredInitialVector,
        "Expecting Initial Vector in the encrypted content, but it is not present");
      return;
    }

    Blob plainData;
    try {
      Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
      cipher.init
        (Cipher.DECRYPT_MODE,
         new SecretKeySpec(ckBits.getImmutableArray(), "AES"),
         new IvParameterSpec(content.getInitialVector().getImmutableArray()));
      plainData = new Blob
        (cipher.doFinal(content.getPayload().getImmutableArray()), false);
    } catch (Exception ex) {
      onError.onError(EncryptError.ErrorCode.DecryptionFailure,
        "Decryption error in doDecrypt: " + ex);
      return;
    }

    try {
      onSuccess.onSuccess(plainData);
    } catch (Throwable exception) {
      logger_.log(Level.SEVERE, "Error in onSuccess", exception);
    }
  }

  /**
   * Convert the KEK name to the KDK prefix:
   * <access-namespace>/KEK/<key-id> ==> <access-namespace>/KDK/<key-id>.
   * @param kekName The KEK name.
   * @param onError This calls onError.onError(errorCode, message) for an error.
   * @return The KDK prefix, or null if an error was reported to onError.
   */
  private static Name
  convertKekNameToKdkPrefix(Name kekName, EncryptError.OnError onError)
  {
    if (kekName.size() < 2 ||
        !kekName.get(-2).equals(EncryptorV2.NAME_COMPONENT_KEK)) {
      onError.onError(EncryptError.ErrorCode.KekInvalidName,
        "Invalid KEK name [" + kekName.toUri() + "]");
      return null;
    }

    return kekName.getPrefix(-2)
      .append(EncryptorV2.NAME_COMPONENT_KDK).append(kekName.get(-1));
  }

  /**
   * Extract the KDK information from the CK Data packet name. The KDK identity name
   * plus the KDK key ID together identify the KDK private key in the KeyChain.
   * @param ckDataName The name of the CK Data packet.
   * @param ckName The CK name from the Interest used to fetch the CK Data packet.
   * @param onError This calls onError.onError(errorCode, message) for an error.
   * @param kdkPrefix This sets kdkPrefix[0] to the KDK prefix.
   * @param kdkIdentityName This sets kdkIdentityName[0] to the KDK identity name.
   * @param kdkKeyId This sets kdkKeyId[0] to the KDK key ID.
   * @return True for success or false if an error was reported to onError.
   */
  private static boolean
  extractKdkInfoFromCkName
    (Name ckDataName, Name ckName, EncryptError.OnError onError,
     Name[] kdkPrefix, Name[] kdkIdentityName, Name[] kdkKeyId)
  {
    // <full-ck-name-with-id> | /ENCRYPTED-BY/<kek-prefix>/NAC/KEK/<key-id>

    if (ckDataName.size() < ckName.size() + 1 ||
        !ckDataName.getPrefix(ckName.size()).equals(ckName) ||
        !ckDataName.get(ckName.size()).equals(EncryptorV2.NAME_COMPONENT_ENCRYPTED_BY)) {
      onError.onError(EncryptError.ErrorCode.CkInvalidName,
        "Invalid CK name [" + ckDataName.toUri() + "]");
      return false;
    }

    Name kekName = ckDataName.getSubName(ckName.size() + 1);
    kdkPrefix[0] = convertKekNameToKdkPrefix(kekName, onError);
    if (kdkPrefix[0] == null)
      // The error has already been reported.
      return false;

    kdkIdentityName[0] = kekName.getPrefix(-2);
    kdkKeyId[0] = kekName.getPrefix(-2).append("KEY").append(kekName.get(-1));
    return true;
  }

  private final PibKey credentialsKey_;
  // private final Validator validator_;
  private final Face face_;
  // The external keychain with access credentials.
  private final KeyChain keyChain_;
  // The internal in-memory keychain for temporarily storing KDKs.
  private final KeyChain internalKeyChain_;

  // TODO: add some expiration, so they are not stored forever.
  private final HashMap<Name, ContentKey> contentKeys_ =
    new HashMap<Name, ContentKey>();

  private static final Logger logger_ = Logger.getLogger(DecryptorV2.class.getName());
}
