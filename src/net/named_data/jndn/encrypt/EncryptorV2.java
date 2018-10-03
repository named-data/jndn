/**
 * Copyright (C) 2018 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From the NAC library https://github.com/named-data/name-based-access-control/blob/new/src/encryptor.cpp
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
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import net.named_data.jndn.Data;
import net.named_data.jndn.Face;
import net.named_data.jndn.Interest;
import net.named_data.jndn.InterestFilter;
import net.named_data.jndn.Name;
import net.named_data.jndn.NetworkNack;
import net.named_data.jndn.OnData;
import net.named_data.jndn.OnInterestCallback;
import net.named_data.jndn.OnNetworkNack;
import net.named_data.jndn.OnRegisterFailed;
import net.named_data.jndn.OnTimeout;
import net.named_data.jndn.security.KeyChain;
import net.named_data.jndn.security.SigningInfo;
import net.named_data.jndn.security.v2.Validator;
import net.named_data.jndn.encrypt.EncryptError.OnError;
import net.named_data.jndn.encrypt.algo.EncryptAlgorithmType;
import net.named_data.jndn.in_memory_storage.InMemoryStorageRetaining;
import net.named_data.jndn.security.SecurityException;
import net.named_data.jndn.security.certificate.PublicKey;
import net.named_data.jndn.util.Blob;
import net.named_data.jndn.util.Common;

/**
 * EncryptorV2 encrypts the requested content for name-based access control (NAC)
 * using security v2. For the meaning of "KEK", etc. see:
 * https://github.com/named-data/name-based-access-control/blob/new/docs/spec.rst
 */
public class EncryptorV2 {
  /**
   * Create an EncryptorV2 with the given parameters. This uses the face to
   * register to receive Interests for the prefix {ckPrefix}/CK.
   * @param accessPrefix The NAC prefix to fetch the Key Encryption Key (KEK)
   * (e.g., /access/prefix/NAC/data/subset). This copies the Name.
   * @param ckPrefix The prefix under which Content Keys (CK) will be generated.
   * (Each will have a unique version appended.) This copies the Name.
   * @param ckDataSigningInfo The SigningInfo parameters to sign the Content Key
   * (CK) Data packet. This copies the SigningInfo.
   * @param onError On failure to create the CK data (failed to fetch the KEK,
   * failed to encrypt with the KEK, etc.), this calls
   * onError.onError(errorCode, message) where errorCode is from the
   * EncryptError.ErrorCode enum, and message is an error string. The encrypt
   * method will continue trying to retrieve the KEK until success (with each
   * attempt separated by RETRY_DELAY_KEK_RETRIEVAL_MS) and onError may be
   * called multiple times.
   * NOTE: The library will log any exceptions thrown by this callback, but for
   * better error handling the callback should catch and properly handle any
   * exceptions.
   * @param validator The validation policy to ensure correctness of the KEK.
   * @param keyChain The KeyChain used to sign Data packets.
   * @param face The Face that will be used to fetch the KEK and publish CK data.
   */
  public EncryptorV2
    (Name accessPrefix, Name ckPrefix, SigningInfo ckDataSigningInfo,
     OnError onError, Validator validator, KeyChain keyChain, Face face)
    throws IOException, SecurityException
  {
    // Copy the Name.
    accessPrefix_ = new Name(accessPrefix);
    ckPrefix_ = new Name(ckPrefix);
    ckBits_ = new byte[AES_KEY_SIZE];
    ckDataSigningInfo_ = new SigningInfo(ckDataSigningInfo);
    isKekRetrievalInProgress_ = false;
    onError_ = onError;
    keyChain_ = keyChain;
    face_ = face;

    regenerateCk();

    ckRegisteredPrefixId_ = face_.registerPrefix
      (new Name(ckPrefix).append(NAME_COMPONENT_CK),
       new OnInterestCallback() {
         public void onInterest(Name prefix, Interest interest, Face face, long interestFilterId, InterestFilter filter) {
           Data data = storage_.find(interest);
           if (data != null) {
             logger_.log(Level.INFO, "Serving {0} from InMemoryStorage",
               data.getName());
             try {
               face.putData(data);
             } catch (IOException ex) {
               logger_.log(Level.SEVERE, "Error in Face.putData: {0}", ex);
             }
           }
           else {
             logger_.log(Level.INFO, "Didn't find CK data for {0}",
               interest.getName());
             // TODO: Send NACK?
           }
         }
       },
       new OnRegisterFailed() {
         public void onRegisterFailed(Name prefix) {
           logger_.log(Level.SEVERE, "Failed to register prefix {0}", prefix);
         }
       });
  }

  public final void
  shutdown()
  {
    face_.unsetInterestFilter(ckRegisteredPrefixId_);
    if (kekPendingInterestId_ > 0)
      face_.removePendingInterest(kekPendingInterestId_);
  }

  /**
   * Encrypt the plainData using the existing Content Key (CK) and return a new
   * EncryptedContent.
   * @param plainData The data to encrypt.
   * @return The new EncryptedContent.
   */
  public final EncryptedContent
  encrypt(byte[] plainData)
    throws NoSuchAlgorithmException, NoSuchPaddingException,
      InvalidAlgorithmParameterException, IllegalBlockSizeException,
      BadPaddingException
  {
    // Generate the initial vector.
    byte[] initialVector = new byte[AES_IV_SIZE];
    Common.getRandom().nextBytes(initialVector);

    Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
    try {
      cipher.init
        (Cipher.ENCRYPT_MODE, new SecretKeySpec(ckBits_, "AES"),
         new IvParameterSpec(initialVector));
    } catch (InvalidKeyException ex) {
      throw new Error
        ("If the error is 'Illegal key size', try installing the " +
         "Java Cryptography Extension (JCE) Unlimited Strength Jurisdiction Policy Files: " +
         ex);
    }
    byte[] encryptedData = cipher.doFinal(plainData);

    EncryptedContent content = new EncryptedContent();
    content.setInitialVector(new Blob(initialVector, false));
    content.setPayload(new Blob(encryptedData, false));
    content.setKeyLocatorName(ckName_);

    return content;
  }

  /**
   * Create a new Content Key (CK) and publish the corresponding CK Data packet.
   * This uses the onError given to the constructor to report errors.
   */
  public final void
  regenerateCk()
  {
    // TODO: Ensure that the CK Data packet for the old CK is published when the
    // CK is updated before the KEK is fetched.

    ckName_ = new Name(ckPrefix_);
    ckName_.append(NAME_COMPONENT_CK);
    // The version is the ID of the CK.
    ckName_.appendVersion((long)Common.getNowMilliseconds());

    logger_.log(Level.INFO, "Generating new CK: {0}", ckName_);
    Common.getRandom().nextBytes(ckBits_);

    // One implication: If the CK is updated before the KEK is fetched, then
    // the KDK for the old CK will not be published.
    if (kekData_ == null)
      retryFetchingKek();
    else
      makeAndPublishCkData(onError_);
  }

  /**
   * Get the number of packets stored in in-memory storage.
   * @return The number of packets.
   */
  public final int
  size() { return storage_.size(); }

  /**
   * Get the the storage cache, which should only be used for testing.
   * @return The storage cache.
   */
  public final HashMap
  getCache_() { return storage_.getCache_(); }

  /**
   * Get the isKekRetrievalInProgress_ flag. This is only for testing.
   * @return The isKekRetrievalInProgress_ flag;
   */
  public final boolean
  getIsKekRetrievalInProgress_() { return isKekRetrievalInProgress_; }

  /**
   * Set the internal kekData_ to null. This is only for testing.
   */
  public final void
  clearKekData_() { kekData_ = null; }

  private void
  retryFetchingKek()
  {
    if (isKekRetrievalInProgress_)
      return;

    logger_.log(Level.INFO, "Retrying fetching of the KEK");
    isKekRetrievalInProgress_ = true;
    fetchKekAndPublishCkData
      (new Runnable() {
         public void run() {
           logger_.log(Level.INFO, "The KEK was retrieved and published");
           isKekRetrievalInProgress_ = false;
         }
       },
       new OnError() {
         public void onError(EncryptError.ErrorCode errorCode, String message) {
           logger_.log(Level.INFO, "Failed to retrieve KEK: {0}", message);
           isKekRetrievalInProgress_ = false;
           onError_.onError(errorCode, message);
         }
       },
       N_RETRIES);
  }

  /**
   * Create an Interest for <access-prefix>/KEK to retrieve the
   * <access-prefix>/KEK/<key-id> KEK Data packet, and set kekData_.
   * @param onReady When the KEK is retrieved and published, this calls
   * onReady.run().
   * @param onError On failure, this calls onError.onError(errorCode, message)
   * where errorCode is from the EncryptError.ErrorCode enum, and message is an
   * error string.
   * @param nTriesLeft The number of retries for expressInterest timeouts.
   */
  private void
  fetchKekAndPublishCkData
    (final Runnable onReady, final OnError onError, final int nTriesLeft)
  {
    logger_.log(Level.INFO, "Fetching KEK: {0}",
      new Name(accessPrefix_).append(NAME_COMPONENT_KEK));

    if (kekPendingInterestId_ > 0) {
      onError.onError(EncryptError.ErrorCode.General,
        "fetchKekAndPublishCkData: There is already a kekPendingInterestId_");
      return;
    }

    try {
      kekPendingInterestId_ = face_.expressInterest
        (new Interest(new Name(accessPrefix_).append(NAME_COMPONENT_KEK))
               .setMustBeFresh(true)
               .setCanBePrefix(true),
         new OnData() {
           public void onData(Interest interest, Data kekData) {
             kekPendingInterestId_ = 0;
             // TODO: Verify if the key is legitimate.
             kekData_ = kekData;
             if (makeAndPublishCkData(onError))
               onReady.run();
             // Otherwise, failure has already been reported.
           }
         },
         new OnTimeout() {
           public void onTimeout(Interest interest) {
             kekPendingInterestId_ = 0;
             if (nTriesLeft > 1)
               fetchKekAndPublishCkData(onReady, onError, nTriesLeft - 1);
             else {
               onError.onError(EncryptError.ErrorCode.KekRetrievalTimeout,
                 "Retrieval of KEK [" + interest.getName().toUri() + "] timed out");
               logger_.log(Level.INFO, "Scheduling retry after all timeouts");
               face_.callLater
                 (RETRY_DELAY_KEK_RETRIEVAL_MS,
                  new Runnable() {
                    public void run() {
                      retryFetchingKek();
                    }
                  });
             }
           }
         },
         new OnNetworkNack() {
           public void onNetworkNack(Interest interest, NetworkNack networkNack) {
             kekPendingInterestId_ = 0;
             if (nTriesLeft > 1) {
               face_.callLater
                 (RETRY_DELAY_AFTER_NACK_MS,
                  new Runnable() {
                    public void run() {
                      fetchKekAndPublishCkData(onReady, onError, nTriesLeft - 1);
                    }
                  });
             }
             else {
               onError.onError(EncryptError.ErrorCode.KekRetrievalFailure,
                 "Retrieval of KEK [" + interest.getName().toUri() +
                 "] failed. Got NACK (" + networkNack.getReason() + ")");
               logger_.log(Level.INFO, "Scheduling retry from NACK");
               face_.callLater
                 (RETRY_DELAY_KEK_RETRIEVAL_MS,
                  new Runnable() {
                    public void run() {
                      retryFetchingKek();
                    }
                  });
             }
           }
         });
    } catch (Exception ex) {
      onError.onError(EncryptError.ErrorCode.General,
        "expressInterest error: " + ex);
    }
  }

  /**
   * Make a CK Data packet for ckName_ encrypted by the KEK in kekData_ and
   * insert it in the storage_.
   * @param onError On failure, this calls onError.onError(errorCode, message)
   * where errorCode is from the EncryptError.ErrorCode enum, and message is an
   * error string.
   * @return True on success, else false.
   */
  private boolean
  makeAndPublishCkData(OnError onError)
  {
    try {
      PublicKey kek = new PublicKey(kekData_.getContent());

      EncryptedContent content = new EncryptedContent();
      content.setPayload(kek.encrypt(ckBits_, EncryptAlgorithmType.RsaOaep));

      Data ckData = new Data
        (new Name(ckName_).append(NAME_COMPONENT_ENCRYPTED_BY)
         .append(kekData_.getName()));
      ckData.setContent(content.wireEncodeV2());
      // FreshnessPeriod can serve as a soft access control for revoking access.
      ckData.getMetaInfo().setFreshnessPeriod(DEFAULT_CK_FRESHNESS_PERIOD_MS);
      keyChain_.sign(ckData, ckDataSigningInfo_);
      storage_.insert(ckData);

      logger_.log(Level.INFO, "Publishing CK data: {0}", ckData.getName());
      return true;
    }
    catch (Throwable ex) {
      onError.onError(EncryptError.ErrorCode.EncryptionFailure,
        "Failed to encrypt generated CK with KEK " + kekData_.getName().toUri());
      return false;
    }
  }

  public static final Name.Component NAME_COMPONENT_ENCRYPTED_BY =
    new Name.Component("ENCRYPTED-BY");
  public static final Name.Component NAME_COMPONENT_NAC = new Name.Component("NAC");
  public static final Name.Component NAME_COMPONENT_KEK = new Name.Component("KEK");
  public static final Name.Component NAME_COMPONENT_KDK = new Name.Component("KDK");
  public static final Name.Component NAME_COMPONENT_CK = new Name.Component("CK");

  public static final double RETRY_DELAY_AFTER_NACK_MS = 1000.0;
  public static final double RETRY_DELAY_KEK_RETRIEVAL_MS = 60 * 1000.0;

  private final Name accessPrefix_;
  private final Name ckPrefix_;
  private Name ckName_;
  private final byte[] ckBits_;
  private final SigningInfo ckDataSigningInfo_;

  private boolean isKekRetrievalInProgress_;
  private Data kekData_ = null;
  private final OnError onError_;

  // Storage for encrypted CKs.
  private final InMemoryStorageRetaining storage_ = new InMemoryStorageRetaining();
  private final long ckRegisteredPrefixId_;
  private long kekPendingInterestId_ = 0;

  private final KeyChain keyChain_;
  private final Face face_;
  private static final Logger logger_ = Logger.getLogger(EncryptorV2.class.getName());

  public static final int AES_KEY_SIZE = 32;
  public static final int AES_IV_SIZE = 16;
  public static final int N_RETRIES = 3;

  private static final double DEFAULT_CK_FRESHNESS_PERIOD_MS = 3600 * 1000.0;
}
