/**
 * Copyright (C) 2015 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From ndn-group-encrypt src/producer https://github.com/named-data/ndn-group-encrypt
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
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import net.named_data.jndn.Data;
import net.named_data.jndn.Exclude;
import net.named_data.jndn.Face;
import net.named_data.jndn.Interest;
import net.named_data.jndn.Name;
import net.named_data.jndn.OnData;
import net.named_data.jndn.OnTimeout;
import net.named_data.jndn.encoding.EncodingException;
import net.named_data.jndn.encoding.der.DerDecodingException;
import net.named_data.jndn.encrypt.algo.AesAlgorithm;
import net.named_data.jndn.encrypt.algo.EncryptAlgorithmType;
import net.named_data.jndn.encrypt.algo.EncryptParams;
import net.named_data.jndn.encrypt.algo.Encryptor;
import net.named_data.jndn.security.AesKeyParams;
import net.named_data.jndn.security.KeyChain;
import net.named_data.jndn.security.SecurityException;
import net.named_data.jndn.util.Blob;

/**
 * A Producer manages content keys used to encrypt a data packet in the
 * group-based encryption protocol.
 * @note This class is an experimental feature. The API may change.
 */
public class Producer {
  public interface OnProducerEKey {
    // List is a list of Data packets with the content key encrypted by E-KEYS.
    void onProducerEKey(List keys);
  }

  /**
   * Create a Producer to use the given ProducerDb, Face and other values.
   *
   * A producer can produce data with a naming convention:
   *   /&lt;prefix>/SAMPLE/&lt;dataType>/[timestamp]
   *
   * The produced data packet is encrypted with a content key,
   * which is stored in the ProducerDb database.
   *
   * A producer also needs to produce data containing a content key
   * encrypted with E-KEYs. A producer can retrieve E-KEYs through the face,
   * and will re-try for at most repeatAttemps times when E-KEY retrieval fails.
   * @param prefix The producer name prefix.
   * @param dataType The dataType portion of the producer name.
   * @param face The face used to retrieve keys.
   * @param keyChain The keyChain used to sign data packets.
   * @param database The ProducerDb database for storing keys.
   * @param repeatAttempts The maximum retry for retrieving keys.
   */
  public Producer
    (Name prefix, Name dataType, Face face, KeyChain keyChain,
     ProducerDb database, int repeatAttempts)
  {
    face_ = face;
    keyChain_ = keyChain;
    database_ = database;
    maxRepeatAttempts_ = repeatAttempts;

    construct(prefix, dataType);
  }

  /**
   * Create a Producer to use the given ProducerDb, Face and other values.
   *
   * A producer can produce data with a naming convention:
   *   /&lt;prefix>/SAMPLE/&lt;dataType>/[timestamp]
   *
   * The produced data packet is encrypted with a content key,
   * which is stored in the ProducerDb database.
   *
   * A producer also needs to produce data containing a content key
   * encrypted with E-KEYs. A producer can retrieve E-KEYs through the face,
   * and will re-try for at most 3 times when E-KEY retrieval fails.
   * @param prefix The producer name prefix.
   * @param dataType The dataType portion of the producer name.
   * @param face The face used to retrieve keys.
   * @param keyChain The keyChain used to sign data packets.
   * @param database The ProducerDb database for storing keys.
   */
  public Producer
    (Name prefix, Name dataType, Face face, KeyChain keyChain,
     ProducerDb database)
  {
    face_ = face;
    keyChain_ = keyChain;
    database_ = database;
    maxRepeatAttempts_ = 3;

    construct(prefix, dataType);
  }

  private void
  construct(Name prefix, Name dataType)
  {
    Name fixedPrefix = new Name(prefix);
    Name fixedDataType = new Name(dataType);

    // Fill ekeyInfo_ with all permutations of dataType, including the 'E-KEY'
    // component of the name. This will be used in createContentKey to send
    // interests without reconstructing names every time.
    fixedPrefix.append(Encryptor.NAME_COMPONENT_READ);
    while (fixedDataType.size() > 0) {
      Name nodeName = new Name(fixedPrefix);
      nodeName.append(fixedDataType);
      nodeName.append(Encryptor.NAME_COMPONENT_E_KEY);

      eKeyInfo_.put(nodeName, new KeyInfo());
      fixedDataType = fixedDataType.getPrefix(-1);
    }
    fixedPrefix.append(dataType);
    namespace_ = new Name(prefix);
    namespace_.append(Encryptor.NAME_COMPONENT_SAMPLE);
    namespace_.append(dataType);
  }

  /**
   * Create the content key. This first checks if the content key exists. For an
   * existing content key, this returns the content key name directly. If the
   * key does not exist, this creates one and encrypts it using the
   * corresponding E-KEY. The encrypted content keys are passed to the
   * onProducerEKey callback.
   * @param timeSlot The time slot as milliseconds since Jan 1, 1970 GMT.
   * @param onProducerEKey This calls onProducerEKey.onProducerEKey(keys) where
   * keys is a list of encrypted content key Data packets.
   * @return The content key name.
   */
  public final Name
  createContentKey(double timeSlot, OnProducerEKey onProducerEKey)
    throws ProducerDb.Error, IOException, SecurityException
  {
    double hourSlot = getRoundedTimeslot(timeSlot);

    // Create the content key name.
    Name contentKeyName = new Name(namespace_);
    contentKeyName.append(Encryptor.NAME_COMPONENT_C_KEY);
    contentKeyName.append(Schedule.toIsoString(hourSlot));

    Blob contentKeyBits;
    if (database_.hasContentKey(timeSlot)) {
      contentKeyBits = database_.getContentKey(timeSlot);
      return contentKeyName;
    }

    AesKeyParams aesParams = new AesKeyParams(128);
    contentKeyBits = AesAlgorithm.generateKey(aesParams).getKeyBits();
    database_.addContentKey(timeSlot, contentKeyBits);

    double timeCount = timeSlot;
    keyRequests_.put(timeCount, new KeyRequest(eKeyInfo_.size()));
    KeyRequest keyRequest = (KeyRequest)keyRequests_.get(timeCount);

    Exclude timeRange = new Exclude();
    // Exclude after the time slot.
    timeRange.appendComponent(new Name.Component(Schedule.toIsoString(timeSlot)));
    timeRange.appendAny();

    // Send interests for all nodes in the tree.
    eKeyInfo_.entrySet().iterator();
    for (Iterator i = eKeyInfo_.entrySet().iterator(); i.hasNext(); ) {
      Map.Entry entry = (Map.Entry)i.next();
      KeyInfo keyInfo = (KeyInfo)entry.getValue();
      keyRequest.repeatAttempts.put(entry.getKey(), 0);
      if (timeSlot < keyInfo.beginTimeslot || timeSlot >= keyInfo.endTimeslot) {
        sendKeyInterest
          ((Name)entry.getKey(), timeSlot, keyRequest, onProducerEKey, timeRange);
      }
      else {
        Name eKeyName = new Name((Name)entry.getKey());
        eKeyName.append(Schedule.toIsoString(keyInfo.beginTimeslot));
        eKeyName.append(Schedule.toIsoString(keyInfo.endTimeslot));
        encryptContentKey
          (keyRequest, keyInfo.keyBits, eKeyName, timeSlot, onProducerEKey);
      }
    }

    return contentKeyName;
  }

  /**
   * Produce a data packet encrypted using the corresponding content key. This
   * encrypts the given content with a content key that covers timeSlot, and
   * updates data with the encrypted content and an appropriate data name.
   * @param data
   * @param timeSlot
   * @param content
   */
  public final void
  produce(Data data, double timeSlot, Blob content)
    throws ProducerDb.Error, IOException, SecurityException,
      NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
      IllegalBlockSizeException, BadPaddingException,
      InvalidAlgorithmParameterException, InvalidKeySpecException
  {
    Name contentKeyName = new Name(createContentKey(timeSlot, null));
    Blob contentKey = database_.getContentKey(timeSlot);

    Name dataName = new Name(namespace_);
    dataName.append(Schedule.toIsoString(getRoundedTimeslot(timeSlot)));

    data.setName(dataName);
    EncryptParams params = new EncryptParams(EncryptAlgorithmType.AesCbc, 16);
    Encryptor.encryptData(data, content, contentKeyName, contentKey, params);
    // TODO: When implemented, use KeyChain.sign(data) which does the same thing.
    try {
      Name certificateName = keyChain_.getAnyCertificate
        (keyChain_.getDefaultCertificateName()).getName().getPrefix(-1);
      keyChain_.sign(data, certificateName);
    } catch (DerDecodingException ex) {
      // We don't expect this to happen.
      throw new SecurityException
        ("Error decoding the default certificate: " + ex.getMessage());
    }
  }

  private static class KeyInfo {
    public double beginTimeslot;
    public double endTimeslot;
    public Blob keyBits;
  }

  private static class KeyRequest {
    public KeyRequest(int interests)
    {
      interestCount = interests;
    }

    public int interestCount;
    public final Map repeatAttempts =
      new HashMap(); /**< The map key is the Name. The value is an int count. */
    public final List encryptedKeys = new ArrayList(); // of Data.
  }

  /**
   * Round timeSlot to the nearest whole hour, so that we can store content keys
   * uniformly (by start of the hour).
   * @param timeSlot The time slot as milliseconds since Jan 1, 1970 GMT.
   * @return The start of the hour as milliseconds since Jan 1, 1970 GMT.
   */
  private static double
  getRoundedTimeslot(double timeSlot)
  {
    return Math.round
      (Math.floor(Math.round(timeSlot) / 3600000.0) * 3600000.0);
  }

  /**
   * Send an interest with the given name through the face with necessary
   * callbacks.
   */
  private void
  sendKeyInterest
    (Name name, final double timeSlot, final KeyRequest keyRequest,
     final OnProducerEKey onProducerEKey, Exclude timeRange) throws IOException
  {
    OnData onKey = new OnData() {
      public void onData(Interest interest, final Data data) {
        try {
          handleCoveringKey(interest, data, timeSlot, keyRequest, onProducerEKey);
        } catch (Exception ex) {
          Logger.getLogger(Producer.class.getName()).log(Level.SEVERE, null, ex);
        }
      }
    };

    OnTimeout onTimeout = new OnTimeout() {
      public void onTimeout(Interest interest) {
        try {
          handleTimeout(interest, timeSlot, keyRequest, onProducerEKey);
        } catch (IOException ex) {
          Logger.getLogger(Producer.class.getName()).log(Level.SEVERE, null, ex);
        }
      }
    };

    Interest keyInterest = new Interest(name);
    keyInterest.setExclude(timeRange);
    keyInterest.setChildSelector(1);

    face_.expressInterest(keyInterest, onKey, onTimeout);
  }

  /**
   * This is called from an expressInterest timeout to update the state of
   * keyRequest.
   */
  private void
  handleTimeout
    (Interest interest, double timeSlot, KeyRequest keyRequest,
     OnProducerEKey onProducerEKey) throws IOException
  {
    Name interestName = interest.getName();

    if ((int)keyRequest.repeatAttempts.get(interestName) < maxRepeatAttempts_) {
      keyRequest.repeatAttempts.put
        (interestName, (int)keyRequest.repeatAttempts.get(interestName) + 1);
      sendKeyInterest
        (interestName, timeSlot, keyRequest, onProducerEKey, interest.getExclude());
    }
    else
      keyRequest.interestCount--;

    if (keyRequest.interestCount == 0 && onProducerEKey != null) {
      onProducerEKey.onProducerEKey(keyRequest.encryptedKeys);
      keyRequests_.remove(timeSlot);
    }
  }

  /**
   * This is called from an expressInterest OnData to check that the encryption
   * key contained in data fits the timeSlot. This sends a refined interest if
   * required.
   */
  private void
  handleCoveringKey
    (Interest interest, Data data, double timeSlot, KeyRequest keyRequest,
     OnProducerEKey onProducerEKey)
    throws EncodingException, ProducerDb.Error, SecurityException, IOException
  {
    Name interestName = interest.getName();
    Name keyName = data.getName();

    double begin = Schedule.fromIsoString
      (keyName.get(iStartTimeStamp).getValue().toString());
    double end = Schedule.fromIsoString
      (keyName.get(iEndTimeStamp).getValue().toString());

    if (timeSlot >= end) {
      Exclude timeRange = new Exclude(interest.getExclude());
      if (true) throw new Error("debug: TODO Implement excludeBefore"); /*
      timeRange.excludeBefore(keyName.get(iStartTimeStamp));
*/
      keyRequest.repeatAttempts.put(interestName, 0);
      sendKeyInterest
        (interestName, timeSlot, keyRequest, onProducerEKey, timeRange);
      return;
    }

    Blob encryptionKey = data.getContent();
    KeyInfo keyInfo = (KeyInfo)eKeyInfo_.get(interestName);
    keyInfo.beginTimeslot = begin;
    keyInfo.endTimeslot = end;
    keyInfo.keyBits = encryptionKey;

    encryptContentKey
      (keyRequest, encryptionKey, keyName, timeSlot, onProducerEKey);
  }

  /**
   * Get the content key from the database_ and encrypt it for the timeSlot
   * using encryptionKey. This calls onProducerEKey when there are no more
   * interests to process.
   */
  private void
  encryptContentKey
    (KeyRequest keyRequest, Blob encryptionKey, Name eKeyName,
     double timeSlot, OnProducerEKey onProducerEKey) 
    throws ProducerDb.Error, SecurityException
  {
    Name keyName = new Name(namespace_);
    keyName.append(Encryptor.NAME_COMPONENT_C_KEY);
    keyName.append(Schedule.toIsoString(getRoundedTimeslot(timeSlot)));

    Blob contentKey = database_.getContentKey(timeSlot);

    Data cKeyData = new Data();
    cKeyData.setName(keyName);
    EncryptParams params = new EncryptParams(EncryptAlgorithmType.RsaOaep);
    try {
      Encryptor.encryptData
        (cKeyData, contentKey, eKeyName, encryptionKey, params);
    } catch (Exception ex) {
      // Consolidate errors such as InvalidKeyException.
      throw new SecurityException
        ("encryptContentKey: Error in encryptData: " + ex.getMessage());
    }
    
    // TODO: When implemented, use KeyChain.sign(data) which does the same thing.
    try {
      Name certificateName = keyChain_.getAnyCertificate
        (keyChain_.getDefaultCertificateName()).getName().getPrefix(-1);
      keyChain_.sign(cKeyData, certificateName);
    } catch (DerDecodingException ex) {
      // We don't expect this to happen.
      throw new SecurityException
        ("Error decoding the default certificate: " + ex.getMessage());
    }

    keyRequest.encryptedKeys.add(cKeyData);

    keyRequest.interestCount--;
    if (keyRequest.interestCount == 0 && onProducerEKey != null) {
      onProducerEKey.onProducerEKey(keyRequest.encryptedKeys);
      keyRequests_.remove(timeSlot);
    }
  }

  private final Face face_;
  private Name namespace_;
  private final KeyChain keyChain_;
  // Use HashMap without generics so it works with older Java compilers.
  private final Map eKeyInfo_ =
    new HashMap(); /**< The map key is the key Name. The value is a KeyInfo. */
  private final Map keyRequests_ =
    new HashMap(); /**< The map key is the double time stamp. The value is a KeyRequest. */
  private final ProducerDb database_;
  private final int maxRepeatAttempts_;

  private static final int iStartTimeStamp = -2;
  private static final int iEndTimeStamp = -1;
}
