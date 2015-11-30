/**
 * Copyright (C) 2015 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From ndn-group-encrypt src/consumer https://github.com/named-data/ndn-group-encrypt
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
import java.nio.ByteBuffer;
import java.util.HashMap;
import net.named_data.jndn.Data;
import net.named_data.jndn.Face;
import net.named_data.jndn.Interest;
import net.named_data.jndn.Name;
import net.named_data.jndn.OnData;
import net.named_data.jndn.OnTimeout;
import net.named_data.jndn.encoding.EncodingException;
import net.named_data.jndn.encrypt.algo.AesAlgorithm;
import net.named_data.jndn.encrypt.algo.EncryptAlgorithmType;
import net.named_data.jndn.encrypt.algo.EncryptParams;
import net.named_data.jndn.encrypt.algo.Encryptor;
import net.named_data.jndn.encrypt.algo.RsaAlgorithm;
import net.named_data.jndn.security.KeyChain;
import net.named_data.jndn.security.OnVerified;
import net.named_data.jndn.security.OnVerifyFailed;
import net.named_data.jndn.security.SecurityException;
import net.named_data.jndn.util.Blob;

/**
 * A Consumer manages fetched group keys used to decrypt a data packet in the
 * group-based encryption protocol.
 * @note This class is an experimental feature. The API may change.
 */
public class Consumer {
  /**
   * Create a Consumer to use the given ConsumerDb, Face and other values.
   * @param face The face used for data packet and key fetching.
   * @param keyChain The keyChain used to verify data packets.
   * @param groupName The reading group name that the consumer belongs to.
   * This makes a copy of the Name.
   * @param consumerName The identity of the consumer. This makes a copy of the
   * Name.
   * @param database The ConsumerDb database for storing decryption keys.
   */
  public Consumer
    (Face face, KeyChain keyChain, Name groupName, Name consumerName,
     ConsumerDb database)
  {
    database_ = database;
    keyChain_ = keyChain;
    face_ = face;
    groupName_ = new Name(groupName);
    consumerName_ = new Name(consumerName);
  }

  public enum ErrorCode {
    Timeout,
    Validation,
    UnsupportedEncryptionScheme,
    InvalidEncryptedFormat,
    NoDecryptKey,
    SecurityException,
    IOException
  }

  public interface OnConsumeComplete {
    void onConsumeComplete(Data data, Blob result);
  }

  public interface OnError {
    void onError(ErrorCode errorCode, String message);
  }

  /**
   * Express an Interest to fetch the content packet with contentName, and
   * decrypt it, fetching keys as needed.
   * @param contentName The name of the content packet.
   * @param onConsumeComplete When the content packet is fetched and decrypted,
   * this calls onConsumeComplete.onConsumeComplete(contentData, result) where
   * contentData is the fetched Data packet and result is the decrypted plain
   * text Blob.
   * @param onError This calls onError.onError(errorCode, message) for an error.
   */
  public final void
  consume
    (Name contentName, final OnConsumeComplete onConsumeComplete,
     final OnError onError)
  {
    final Interest interest = new Interest(contentName);

    // Prepare the callback functions.
    final OnData onData = new OnData() {
      public void onData(Interest contentInterest, final Data contentData) {
        // The Interest has no selectors, so assume the library correctly
        // matched with the Data name before calling onData.

        try {
          keyChain_.verifyData
            (contentData,
             new OnVerified() {
               public void onVerified(Data validData) {
                 // Decrypt the content.
                 decryptContent
                   (validData,
                    new OnPlainText() {
                      public void onPlainText(Blob plainText) {
                        onConsumeComplete.onConsumeComplete(contentData, plainText);
                      }
                    },
                    onError);
               }
             },
             new OnVerifyFailed() {
               public void onVerifyFailed(Data d) {
                 onError.onError(ErrorCode.Validation, "verifyData failed");
               }
             });
        } catch (SecurityException ex) {
          onError.onError
           (ErrorCode.SecurityException, "verifyData error: " + ex.getMessage());
        }
      }
    };

    OnTimeout onTimeout = new OnTimeout() {
      public void onTimeout(Interest contentInterest) {
        // We should re-try at least once.
        try {
          face_.expressInterest
            (interest, onData,
             new OnTimeout() {
               public void onTimeout(Interest contentInterest) {
                 onError.onError(ErrorCode.Timeout, interest.getName().toUri());
               }
             });
        } catch (IOException ex) {
          onError.onError
           (ErrorCode.IOException, "expressInterest error: " + ex.getMessage());
        }
      }
    };

    // Express the Interest.
    try {
      face_.expressInterest(interest, onData, onTimeout);
    } catch (IOException ex) {
      onError.onError
       (ErrorCode.IOException, "expressInterest error: " + ex.getMessage());
    }
  }

  /**
   * Set the group name.
   * @param groupName The reading group name that the consumer belongs to.
   * This makes a copy of the Name.
   */
  public final void
  setGroup(Name groupName) { groupName_ = new Name(groupName); }

  /**
   * Add a new decryption key with keyName and keyBlob to the database.
   * @param keyName The key name.
   * @param keyBlob The encoded key.
   * @throws ConsumerDb.Error if a key with the same keyName already exists in
   * the database, or other database error.
   * @throws Error if the consumer name is not a prefix of the key name.
   */
  public final void
  addDecryptionKey(Name keyName, Blob keyBlob) throws ConsumerDb.Error
  {
    if (!(consumerName_.match(keyName)))
      throw new Error
        ("addDecryptionKey: The consumer name must be a prefix of the key name");

    database_.addKey(keyName, keyBlob);
  }

  public interface OnPlainText {
    void onPlainText(Blob plainText);
  }

  /**
   * Decode encryptedBlob as an EncryptedContent and decrypt using keyBits.
   * @param encryptedBlob The encoded EncryptedContent to decrypt.
   * @param keyBits The key value.
   * @param onPlainText When encryptedBlob is decrypted, this calls
   * onPlainText.onPlainText(decryptedBlob) with the decrypted blob.
   * @param onError This calls onError.onError(errorCode, message) for an error.
   */
  private static void
  decrypt
    (Blob encryptedBlob, Blob keyBits, OnPlainText onPlainText, OnError onError)
  {
    EncryptedContent encryptedContent = new EncryptedContent();
    try {
      encryptedContent.wireDecode(encryptedBlob);
    } catch (EncodingException ex) {
      onError.onError(ErrorCode.InvalidEncryptedFormat, ex.getMessage());
      return;
    }

    decrypt(encryptedContent, keyBits, onPlainText, onError);
  }

  /**
   * Decrypt encryptedContent using keyBits.
   * @param encryptedContent The EncryptedContent to decrypt.
   * @param keyBits The key value.
   * @param onPlainText When encryptedBlob is decrypted, this calls
   * onPlainText.onPlainText(decryptedBlob) with the decrypted blob.
   * @param onError This calls onError.onError(errorCode, message) for an error.
   */
  private static void
  decrypt
    (EncryptedContent encryptedContent, Blob keyBits, OnPlainText onPlainText,
     OnError onError)
  {
    Blob payload = encryptedContent.getPayload();

    if (encryptedContent.getAlgorithmType() == EncryptAlgorithmType.AesCbc) {
      // Prepare the parameters.
      EncryptParams decryptParams = new EncryptParams(EncryptAlgorithmType.AesCbc);
      decryptParams.setInitialVector(encryptedContent.getInitialVector());

      // Decrypt the content.
      Blob content;
      try {
        content = AesAlgorithm.decrypt(keyBits, payload, decryptParams);
      } catch (Exception ex) {
        onError.onError(ErrorCode.InvalidEncryptedFormat, ex.getMessage());
        return;
      }
      onPlainText.onPlainText(content);
    }
    else if (encryptedContent.getAlgorithmType() == EncryptAlgorithmType.RsaOaep) {
      // Prepare the parameters.
      EncryptParams decryptParams = new EncryptParams(EncryptAlgorithmType.RsaOaep);

      // Decrypt the content.
      Blob content;
      try {
        content = RsaAlgorithm.decrypt(keyBits, payload, decryptParams);
      } catch (Exception ex) {
        onError.onError(ErrorCode.InvalidEncryptedFormat, ex.getMessage());
        return;
      }
      onPlainText.onPlainText(content);
    }
    else
      onError.onError
        (ErrorCode.UnsupportedEncryptionScheme,
         encryptedContent.getAlgorithmType().toString());
  }

  /**
   * Decrypt the data packet.
   * @param data The data packet.
   * @param onPlainText When the data packet is decrypted, this calls
   * onPlainText.onPlainText(decryptedBlob) with the decrypted blob.
   * @param onError This calls onError.onError(errorCode, message) for an error.
   */
  private void
  decryptContent(Data data, final OnPlainText onPlainText, final OnError onError)
  {
    // Get the encrypted content.
    final EncryptedContent dataEncryptedContent = new EncryptedContent();
    try {
      dataEncryptedContent.wireDecode(data.getContent());
    } catch (EncodingException ex) {
      onError.onError(ErrorCode.InvalidEncryptedFormat, ex.getMessage());
      return;
    }
    final Name cKeyName = dataEncryptedContent.getKeyLocator().getKeyName();

    // Check if the content key is already in the store.
    Blob cKey = (Blob)cKeyMap_.get(cKeyName);
    if (cKey != null)
      decrypt(dataEncryptedContent, cKey, onPlainText, onError);
    else {
      // Retrieve the C-KEY Data from network.
      Name interestName = new Name(cKeyName);
      interestName.append(Encryptor.NAME_COMPONENT_FOR).append(groupName_);
      final Interest interest = new Interest(interestName);

      // Prepare the callback functions.
      final OnData onData = new OnData() {
        public void onData(Interest cKeyInterest, Data cKeyData) {
          // The Interest has no selectors, so assume the library correctly
          // matched with the Data name before calling onData.

          try {
            keyChain_.verifyData
              (cKeyData,
               new OnVerified() {
                 public void onVerified(Data validCKeyData) {
                   decryptCKey
                     (validCKeyData,
                      new OnPlainText() {
                        public void onPlainText(Blob cKeyBits) {
                          // cKeyName is already a copy inside the local dataEncryptedContent.
                          cKeyMap_.put(cKeyName, cKeyBits);
                          decrypt
                            (dataEncryptedContent, cKeyBits, onPlainText, onError);
                        }
                      },
                      onError);
                 }
               },
               new OnVerifyFailed() {
                 public void onVerifyFailed(Data d) {
                   onError.onError(ErrorCode.Validation, "verifyData failed");
                 }
               });
          } catch (SecurityException ex) {
            onError.onError
             (ErrorCode.SecurityException, "verifyData error: " + ex.getMessage());
          }
        }
      };

      OnTimeout onTimeout = new OnTimeout() {
        public void onTimeout(Interest dKeyInterest) {
          // We should re-try at least once.
          try {
            face_.expressInterest
              (interest, onData,
               new OnTimeout() {
                 public void onTimeout(Interest contentInterest) {
                   onError.onError(ErrorCode.Timeout, interest.getName().toUri());
                 }
               });
          } catch (IOException ex) {
            onError.onError
             (ErrorCode.IOException, "expressInterest error: " + ex.getMessage());
          }
        }
      };

      // Express the Interest.
      try {
        face_.expressInterest(interest, onData, onTimeout);
      } catch (IOException ex) {
        onError.onError
         (ErrorCode.IOException, "expressInterest error: " + ex.getMessage());
      }
    }
  }

  /**
   * Decrypt cKeyData.
   * @param cKeyData The C-KEY data packet.
   * @param onPlainText When the data packet is decrypted, this calls
   * onPlainText.onPlainText(decryptedBlob) with the decrypted blob.
   * @param onError This calls onError.onError(errorCode, message) for an error.
   */
  private void
  decryptCKey(Data cKeyData, final OnPlainText onPlainText, final OnError onError)
  {
    // Get the encrypted content.
    Blob cKeyContent = cKeyData.getContent();
    final EncryptedContent cKeyEncryptedContent = new EncryptedContent();
    try {
      cKeyEncryptedContent.wireDecode(cKeyContent);
    } catch (EncodingException ex) {
      onError.onError(ErrorCode.InvalidEncryptedFormat, ex.getMessage());
      return;
    }
    Name eKeyName = cKeyEncryptedContent.getKeyLocator().getKeyName();
    final Name dKeyName = eKeyName.getPrefix(-3);
    dKeyName.append(Encryptor.NAME_COMPONENT_D_KEY).append(eKeyName.getSubName(-2));

    // Check if the decryption key is already in the store.
    Blob dKey = (Blob)dKeyMap_.get(dKeyName);
    if (dKey != null)
      decrypt(cKeyEncryptedContent, dKey, onPlainText, onError);
    else {
      // Get the D-Key Data.
      Name interestName = new Name(dKeyName);
      interestName.append(Encryptor.NAME_COMPONENT_FOR).append(consumerName_);
      final Interest interest = new Interest(interestName);

      // Prepare the callback functions.
      final OnData onData = new OnData() {
        public void onData(Interest dKeyInterest, Data dKeyData) {
          // The Interest has no selectors, so assume the library correctly
          // matched with the Data name before calling onData.

          try {
            keyChain_.verifyData
              (dKeyData,
               new OnVerified() {
                 public void onVerified(Data validDKeyData) {
                   decryptDKey
                     (validDKeyData,
                      new OnPlainText() {
                        public void onPlainText(Blob dKeyBits) {
                          // dKeyName is already a local copy.
                          dKeyMap_.put(dKeyName, dKeyBits);
                          decrypt
                            (cKeyEncryptedContent, dKeyBits, onPlainText, onError);
                        }
                      },
                      onError);
                 }
               },
               new OnVerifyFailed() {
                 public void onVerifyFailed(Data d) {
                   onError.onError(ErrorCode.Validation, "verifyData failed");
                 }
               });
          } catch (SecurityException ex) {
            onError.onError
             (ErrorCode.SecurityException, "verifyData error: " + ex.getMessage());
          }
        }
      };

      OnTimeout onTimeout = new OnTimeout() {
        public void onTimeout(Interest dKeyInterest) {
          // We should re-try at least once.
          try {
            face_.expressInterest
              (interest, onData,
               new OnTimeout() {
                 public void onTimeout(Interest contentInterest) {
                   onError.onError(ErrorCode.Timeout, interest.getName().toUri());
                 }
               });
          } catch (IOException ex) {
            onError.onError
             (ErrorCode.IOException, "expressInterest error: " + ex.getMessage());
          }
        }
      };

      // Express the Interest.
      try {
        face_.expressInterest(interest, onData, onTimeout);
      } catch (IOException ex) {
        onError.onError
         (ErrorCode.IOException, "expressInterest error: " + ex.getMessage());
      }
    }
  }

  /**
   * Decrypt dKeyData.
   * @param dKeyData The D-KEY data packet.
   * @param onPlainText When the data packet is decrypted, this calls
   * onPlainText.onPlainText(decryptedBlob) with the decrypted blob.
   * @param onError This calls onError.onError(errorCode, message) for an error.
   */
  private void
  decryptDKey(Data dKeyData, OnPlainText onPlainText, final OnError onError)
  {
    // Get encrypted content.
    Blob dataContent = dKeyData.getContent();

    // Process the nonce.
    // dataContent is a sequence of the two EncryptedContent.
    EncryptedContent encryptedNonce = new EncryptedContent();
    try {
      encryptedNonce.wireDecode(dataContent);
    } catch (EncodingException ex) {
      onError.onError(ErrorCode.InvalidEncryptedFormat, ex.getMessage());
      return;
    }
    Name consumerKeyName = encryptedNonce.getKeyLocator().getKeyName();

    // Get consumer decryption key.
    Blob consumerKeyBlob;
    try {
      consumerKeyBlob = getDecryptionKey(consumerKeyName);
    } catch (ConsumerDb.Error ex) {
      onError.onError(ErrorCode.NoDecryptKey, "Database error: " + ex.getMessage());
      return;
    }
    if (consumerKeyBlob.size() == 0) {
      onError.onError(ErrorCode.NoDecryptKey,
        "The desired consumer decryption key in not in the database");
      return;
    }

    // Process the D-KEY.
    // Use the size of encryptedNonce to find the start of encryptedPayload.
    ByteBuffer encryptedPayloadBuffer = dataContent.buf().duplicate();
    encryptedPayloadBuffer.position(encryptedNonce.wireEncode().size());
    final Blob encryptedPayloadBlob = new Blob(encryptedPayloadBuffer, false);
    if (encryptedPayloadBlob.size() == 0)
      onError.onError(ErrorCode.InvalidEncryptedFormat,
        "The data packet does not satisfy the D-KEY packet format");

    // Decrypt the D-KEY.
    final OnPlainText callerOnPlainText = onPlainText;
    decrypt
      (encryptedNonce, consumerKeyBlob,
       new Consumer.OnPlainText() {
         public void onPlainText(Blob nonceKeyBits) {
           decrypt(encryptedPayloadBlob, nonceKeyBits, callerOnPlainText, onError);
         }
       },
       onError);
  }

  /**
   * Get the encoded blob of the decryption key with decryptionKeyName from the
   * database.
   * @param decryptionKeyName The key name.
   * @return A Blob with the encoded key, or an isNull Blob if cannot find the
   * key with decryptionKeyName.
   * @throws ConsumerDb.Error for a database error.
   */
  private Blob
  getDecryptionKey(Name decryptionKeyName) throws ConsumerDb.Error
  {
    return database_.getKey(decryptionKeyName);
  }

  /**
   * A class implements Friend if it has a method setConsumerFriendAccess
   * which setFriendAccess calls to set the FriendAccess object.
   */
  public interface Friend {
    void setConsumerFriendAccess(FriendAccess friendAccess);
  }

  /**
   * Call friend.setConsumerFriendAccess to pass an instance of
   * a FriendAccess class to allow a friend class to call private methods.
   * @param friend The friend class for calling setConsumerFriendAccess.
   * This uses friend.getClass() to make sure that it is a friend class.
   * Therefore, only a friend class gets an implementation of FriendAccess.
   */
  public static void setFriendAccess(Friend friend)
  {
    if (friend.getClass().getName().equals
          ("src.net.named_data.jndn.tests.integration_tests.TestGroupConsumer"))
    {
      friend.setConsumerFriendAccess(new FriendAccessImpl());
    }
  }

  /**
   * A friend class can call the methods of FriendAccess to access private
   * methods.  This abstract class is public, but setFriendAccess passes an
   * instance of a private class which implements the methods.
   */
  public abstract static class FriendAccess {
    public abstract void
    decrypt
      (Blob encryptedBlob, Blob keyBits, OnPlainText onPlainText,
       OnError onError);
  }

  /**
   * setFriendAccess passes an instance of this private class which implements
   * the FriendAccess methods.
   */
  private static class FriendAccessImpl extends FriendAccess {
    public void
    decrypt
      (Blob encryptedBlob, Blob keyBits, OnPlainText onPlainText,
       OnError onError)
    {
      Consumer.decrypt(encryptedBlob, keyBits, onPlainText, onError);
    }
  }

  private final ConsumerDb database_;
  private final KeyChain keyChain_;
  private final Face face_;
  private Name groupName_;
  private final Name consumerName_;

  // Use HashMap without generics so it works with older Java compilers.
  private final HashMap cKeyMap_ =
    new HashMap(); /**< The map key is the C-KEY name. The value is the encoded key Blob. */
  private final HashMap dKeyMap_ =
    new HashMap(); /**< The map key is the D-KEY name. The value is the encoded key Blob. */
}
