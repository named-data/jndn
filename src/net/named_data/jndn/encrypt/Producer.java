/**
 * Copyright (C) 2015-2018 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From ndn-group-encrypt src/producer https://github.com/named-data/ndn-group-encrypt
 * @author: excludeRange from ndn-cxx https://github.com/named-data/ndn-cxx/blob/master/src/exclude.cpp
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
import net.named_data.jndn.Link;
import net.named_data.jndn.Name;
import net.named_data.jndn.NetworkNack;
import net.named_data.jndn.OnData;
import net.named_data.jndn.OnNetworkNack;
import net.named_data.jndn.OnTimeout;
import net.named_data.jndn.encoding.EncodingException;
import net.named_data.jndn.encrypt.EncryptError.ErrorCode;
import net.named_data.jndn.encrypt.EncryptError.OnError;
import net.named_data.jndn.encrypt.algo.AesAlgorithm;
import net.named_data.jndn.encrypt.algo.EncryptAlgorithmType;
import net.named_data.jndn.encrypt.algo.EncryptParams;
import net.named_data.jndn.encrypt.algo.Encryptor;
import net.named_data.jndn.security.AesKeyParams;
import net.named_data.jndn.security.KeyChain;
import net.named_data.jndn.security.SecurityException;
import net.named_data.jndn.security.pib.PibImpl;
import net.named_data.jndn.security.tpm.TpmBackEnd;
import net.named_data.jndn.util.Blob;

/**
 * A Producer manages content keys used to encrypt a data packet in the
 * group-based encryption protocol.
 * @note This class is an experimental feature. The API may change.
 */
public class Producer {
  public interface OnEncryptedKeys {
    // keys is a list of Data packets with the content key encrypted by E-KEYS.
    void onEncryptedKeys(List keys);
  }

  /**
   * Create a Producer to use the given ProducerDb, Face and other values.
   *
   * A producer can produce data with a naming convention:
   *   /{prefix}/SAMPLE/{dataType}/[timestamp]
   *
   * The produced data packet is encrypted with a content key,
   * which is stored in the ProducerDb database.
   *
   * A producer also needs to produce data containing a content key
   * encrypted with E-KEYs. A producer can retrieve E-KEYs through the face,
   * and will re-try for at most repeatAttemps times when E-KEY retrieval fails.
   * @param prefix The producer name prefix. This makes a copy of the Name.
   * @param dataType The dataType portion of the producer name. This makes a
   * copy of the Name.
   * @param face The face used to retrieve keys.
   * @param keyChain The keyChain used to sign data packets.
   * @param database The ProducerDb database for storing keys.
   * @param repeatAttempts The maximum retry for retrieving keys.
   * @param keyRetrievalLink The Link object to use in Interests for key
   * retrieval. This makes a copy of the Link object. If the Link object's
   * getDelegations().size() is zero, don't use it.
   */
  public Producer
    (Name prefix, Name dataType, Face face, KeyChain keyChain,
     ProducerDb database, int repeatAttempts, Link keyRetrievalLink)
  {
    face_ = face;
    keyChain_ = keyChain;
    database_ = database;
    maxRepeatAttempts_ = repeatAttempts;
    // Copy the Link object.
    keyRetrievalLink_ = new Link(keyRetrievalLink);

    construct(prefix, dataType);
  }

  /**
   * Create a Producer to use the given ProducerDb, Face and other values.
   *
   * A producer can produce data with a naming convention:
   *   /{prefix}/SAMPLE/{dataType}/[timestamp]
   *
   * The produced data packet is encrypted with a content key,
   * which is stored in the ProducerDb database.
   *
   * A producer also needs to produce data containing a content key
   * encrypted with E-KEYs. A producer can retrieve E-KEYs through the face,
   * and will re-try for at most repeatAttemps times when E-KEY retrieval fails.
   * @param prefix The producer name prefix. This makes a copy of the Name.
   * @param dataType The dataType portion of the producer name. This makes a
   * copy of the Name.
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
    keyRetrievalLink_ = NO_LINK;

    construct(prefix, dataType);
  }

  /**
   * Create a Producer to use the given ProducerDb, Face and other values.
   *
   * A producer can produce data with a naming convention:
   *   /{prefix}/SAMPLE/{dataType}/[timestamp]
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
    keyRetrievalLink_ = NO_LINK;

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
   * Create the content key corresponding to the timeSlot. This first checks if
   * the content key exists. For an existing content key, this returns the
   * content key name directly. If the key does not exist, this creates one and
   * encrypts it using the corresponding E-KEYs. The encrypted content keys are
   * passed to the onEncryptedKeys callback.
   * @param timeSlot The time slot as milliseconds since Jan 1, 1970 UTC.
   * @param onEncryptedKeys If this creates a content key, then this calls
   * onEncryptedKeys.onEncryptedKeys(keys) where keys is a list of encrypted
   * content key Data packets. If onEncryptedKeys is null, this does not use it.
   * NOTE: The library will log any exceptions thrown by this callback, but for
   * better error handling the callback should catch and properly handle any
   * exceptions.
   * @param onError This calls onError.onError(errorCode, message) for an error.
   * NOTE: The library will log any exceptions thrown by this callback, but for
   * better error handling the callback should catch and properly handle any
   * exceptions.
   * @return The content key name.
   */
  public final Name
  createContentKey
    (double timeSlot, OnEncryptedKeys onEncryptedKeys,
     OnError onError)
    throws ProducerDb.Error, IOException, SecurityException, TpmBackEnd.Error,
      PibImpl.Error, KeyChain.Error
  {
    double hourSlot = getRoundedTimeSlot(timeSlot);

    // Create the content key name.
    Name contentKeyName = new Name(namespace_);
    contentKeyName.append(Encryptor.NAME_COMPONENT_C_KEY);
    contentKeyName.append(Schedule.toIsoString(hourSlot));

    Blob contentKeyBits;

    // Check if we have created the content key before.
    if (database_.hasContentKey(timeSlot))
      // We have created the content key. Return its name directly.
      return contentKeyName;

    // We haven't created the content key. Create one and add it into the database.
    AesKeyParams aesParams = new AesKeyParams(128);
    contentKeyBits = AesAlgorithm.generateKey(aesParams).getKeyBits();
    database_.addContentKey(timeSlot, contentKeyBits);

    // Now we need to retrieve the E-KEYs for content key encryption.
    double timeCount = Math.round(timeSlot);
    keyRequests_.put(timeCount, new KeyRequest(eKeyInfo_.size()));
    KeyRequest keyRequest = (KeyRequest)keyRequests_.get(timeCount);

    // Check if the current E-KEYs can cover the content key.
    Exclude timeRange = new Exclude();
    excludeAfter(timeRange, new Name.Component(Schedule.toIsoString(timeSlot)));
    for (Object entryObj : eKeyInfo_.entrySet()) {
      // For each current E-KEY.
      Map.Entry entry = (Map.Entry)entryObj;
      KeyInfo keyInfo = (KeyInfo)entry.getValue();
      if (timeSlot < keyInfo.beginTimeSlot || timeSlot >= keyInfo.endTimeSlot) {
        // The current E-KEY cannot cover the content key, so retrieve one.
        keyRequest.repeatAttempts.put(entry.getKey(), 0);
        sendKeyInterest
          (new Interest((Name)entry.getKey()).setExclude(timeRange).setChildSelector(1),
           timeSlot, onEncryptedKeys, onError);
      }
      else {
        // The current E-KEY can cover the content key.
        // Encrypt the content key directly.
        Name eKeyName = new Name((Name)entry.getKey());
        eKeyName.append(Schedule.toIsoString(keyInfo.beginTimeSlot));
        eKeyName.append(Schedule.toIsoString(keyInfo.endTimeSlot));
        encryptContentKey
          (keyInfo.keyBits, eKeyName, timeSlot, onEncryptedKeys, onError);
      }
    }

    return contentKeyName;
  }

  /**
   * Call the main createContentKey method where onError is defaultOnError.
   */
  public final Name
  createContentKey(double timeSlot, OnEncryptedKeys onEncryptedKeys)
    throws ProducerDb.Error, IOException, SecurityException, TpmBackEnd.Error,
      PibImpl.Error, KeyChain.Error
  {
    return createContentKey(timeSlot, onEncryptedKeys, defaultOnError);
  }

  /**
   * Encrypt the given content with the content key that covers timeSlot, and
   * update the data packet with the encrypted content and an appropriate data
   * name.
   * @param data An empty Data object which is updated.
   * @param timeSlot The time slot as milliseconds since Jan 1, 1970 UTC.
   * @param content The content to encrypt.
   * @param onError This calls onError.onError(errorCode, message) for an error.
   * NOTE: The library will log any exceptions thrown by this callback, but for
   * better error handling the callback should catch and properly handle any
   * exceptions.
   */
  public final void
  produce(Data data, double timeSlot, Blob content, OnError onError)
    throws ProducerDb.Error, IOException, SecurityException,
      NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
      IllegalBlockSizeException, BadPaddingException,
      InvalidAlgorithmParameterException, InvalidKeySpecException,
      TpmBackEnd.Error, PibImpl.Error, KeyChain.Error
  {
    // Get a content key.
    Name contentKeyName = createContentKey(timeSlot, null, onError);
    Blob contentKey = database_.getContentKey(timeSlot);

    // Produce data.
    Name dataName = new Name(namespace_);
    dataName.append(Schedule.toIsoString(timeSlot));

    data.setName(dataName);
    EncryptParams params = new EncryptParams(EncryptAlgorithmType.AesCbc, 16);
    Encryptor.encryptData(data, content, contentKeyName, contentKey, params);
    keyChain_.sign(data);
  }

  /**
   * Call the main produce method where onError is defaultOnError.
   */
  public final void
  produce(Data data, double timeSlot, Blob content)
    throws ProducerDb.Error, IOException, SecurityException,
      NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
      IllegalBlockSizeException, BadPaddingException,
      InvalidAlgorithmParameterException, InvalidKeySpecException,
      TpmBackEnd.Error, PibImpl.Error, KeyChain.Error
  {
    produce(data, timeSlot, content, defaultOnError);
  }

  /**
   * The default OnError callback which does nothing.
   */
  public static final OnError
  defaultOnError = new OnError() {
    public void onError(ErrorCode errorCode, String message) {
      // Do nothing.
    }
  };

  private static class KeyInfo {
    public double beginTimeSlot;
    public double endTimeSlot;
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
   * @param timeSlot The time slot as milliseconds since Jan 1, 1970 UTC.
   * @return The start of the hour as milliseconds since Jan 1, 1970 UTC.
   */
  private static double
  getRoundedTimeSlot(double timeSlot)
  {
    return Math.round
      (Math.floor(Math.round(timeSlot) / 3600000.0) * 3600000.0);
  }

  /**
   * Send an interest with the given name through the face with callbacks to
   * handleCoveringKey, handleTimeout and handleNetworkNack.
   * @param interest The interest to send.
   * @param timeSlot The time slot, passed to handleCoveringKey, handleTimeout
   * and handleNetworkNack.
   * @param onEncryptedKeys The OnEncryptedKeys callback, passed to
   * handleCoveringKey, handleTimeout and handleNetworkNack.
   */
  private void
  sendKeyInterest
    (Interest interest, final double timeSlot,
     final OnEncryptedKeys onEncryptedKeys, final OnError onError)
    throws IOException
  {
    OnData onKey = new OnData() {
      public void onData(Interest interest, final Data data) {
        try {
          handleCoveringKey(interest, data, timeSlot, onEncryptedKeys, onError);
        } catch (Exception ex) {
          logger_.log(Level.SEVERE, null, ex);
        }
      }
    };

    OnTimeout onTimeout = new OnTimeout() {
      public void onTimeout(Interest interest) {
        try {
          handleTimeout(interest, timeSlot, onEncryptedKeys, onError);
        } catch (IOException ex) {
          logger_.log(Level.SEVERE, null, ex);
        }
      }
    };

    OnNetworkNack onNetworkNack = new OnNetworkNack() {
      public void onNetworkNack(Interest interest, NetworkNack networkNack) {
        handleNetworkNack
          (interest, networkNack, timeSlot, onEncryptedKeys, onError);
      }
    };

    Interest request;
    if (keyRetrievalLink_.getDelegations().size() == 0)
      // We can use the supplied interest without copying.
      request = interest;
    else {
      // Copy the supplied interest and add the Link.
      request = new Interest(interest);
      // This will use a cached encoding if available.
      request.setLinkWireEncoding(keyRetrievalLink_.wireEncode());
    }

    face_.expressInterest(request, onKey, onTimeout, onNetworkNack);
  }

  /**
   * This is called from an expressInterest timeout to update the state of
   * keyRequest. Re-express the interest if the number of retrials is less than
   * the max limit.
   * @param interest The timed-out interest.
   * @param timeSlot The time slot as milliseconds since Jan 1, 1970 UTC.
   * @param onEncryptedKeys When there are no more interests to process, this
   * calls onEncryptedKeys.onEncryptedKeys(keys) where keys is a list of
   * encrypted content key Data packets. If onEncryptedKeys is null, this does
   * not use it.
   */
  private void
  handleTimeout
    (Interest interest, double timeSlot, OnEncryptedKeys onEncryptedKeys,
     OnError onError)
     throws IOException
  {
    double timeCount = Math.round(timeSlot);
    KeyRequest keyRequest = (KeyRequest)keyRequests_.get(timeCount);

    Name interestName = interest.getName();
    if ((int)(Integer)keyRequest.repeatAttempts.get(interestName) < maxRepeatAttempts_) {
      // Increase the retrial count.
      keyRequest.repeatAttempts.put
        (interestName, (int)(Integer)keyRequest.repeatAttempts.get(interestName) + 1);
      sendKeyInterest(interest, timeSlot, onEncryptedKeys, onError);
    }
    else
      // Treat an eventual timeout as a network Nack.
      handleNetworkNack
        (interest, new NetworkNack(), timeSlot, onEncryptedKeys, onError);
  }

  /**
   * This is called from an expressInterest OnNetworkNack to handle a network
   * Nack for the E-KEY requested through the Interest. Decrease the outstanding
   * E-KEY interest count for the C-KEY corresponding to the timeSlot.
   * @param interest The interest given to expressInterest.
   * @param networkNack The returned NetworkNack (unused).
   * @param timeSlot The time slot as milliseconds since Jan 1, 1970 UTC.
   * @param onEncryptedKeys When there are no more interests to process, this
   * calls onEncryptedKeys.onEncryptedKeys(keys) where keys is a list of
   * encrypted content key Data packets. If onEncryptedKeys is null, this does
   * not use it.
   */
  private void
  handleNetworkNack
    (Interest interest, NetworkNack networkNack, double timeSlot,
     OnEncryptedKeys onEncryptedKeys, OnError onError)
  {
    // We have run out of options....
    double timeCount = Math.round(timeSlot);
    updateKeyRequest
      ((KeyRequest)keyRequests_.get(timeCount), timeCount, onEncryptedKeys);
  }

  /**
   * Decrease the count of outstanding E-KEY interests for the C-KEY for
   * timeCount. If the count decreases to 0, invoke onEncryptedKeys.
   * @param keyRequest The KeyRequest with the interestCount to update.
   * @param timeCount The time count for indexing keyRequests_.
   * @param onEncryptedKeys When there are no more interests to process, this
   * calls onEncryptedKeys.onEncryptedKeys(keys) where keys is a list of
   * encrypted content key Data packets. If onEncryptedKeys is null, this does
   * not use it.
   */
  private void
  updateKeyRequest
    (KeyRequest keyRequest, double timeCount, OnEncryptedKeys onEncryptedKeys)
  {
    --keyRequest.interestCount;
    if (keyRequest.interestCount == 0 && onEncryptedKeys != null) {
      try {
        onEncryptedKeys.onEncryptedKeys(keyRequest.encryptedKeys);
      } catch (Throwable exception) {
        logger_.log(Level.SEVERE, "Error in onEncryptedKeys", exception);
      }
      keyRequests_.remove(timeCount);
    }
  }

  /**
   * This is called from an expressInterest OnData to check that the encryption
   * key contained in data fits the timeSlot. This sends a refined interest if
   * required.
   * @param interest The interest given to expressInterest.
   * @param data The fetched Data packet.
   * @param timeSlot The time slot as milliseconds since Jan 1, 1970 UTC.
   * @param onEncryptedKeys When there are no more interests to process, this
   * calls onEncryptedKeys.onEncryptedKeys(keys) where keys is a list of
   * encrypted content key Data packets. If onEncryptedKeys is null, this does
   * not use it.
   */
  private void
  handleCoveringKey
    (Interest interest, Data data, double timeSlot,
     OnEncryptedKeys onEncryptedKeys, OnError onError)
    throws EncodingException, ProducerDb.Error, SecurityException, IOException,
      TpmBackEnd.Error, PibImpl.Error, KeyChain.Error
  {
    double timeCount = Math.round(timeSlot);
    KeyRequest keyRequest = (KeyRequest)keyRequests_.get(timeCount);

    Name interestName = interest.getName();
    Name keyName = data.getName();

    double begin = Schedule.fromIsoString
      (keyName.get(START_TIME_STAMP_INDEX).getValue().toString());
    double end = Schedule.fromIsoString
      (keyName.get(END_TIME_STAMP_INDEX).getValue().toString());

    if (timeSlot >= end) {
      // If the received E-KEY covers some earlier period, try to retrieve an
      // E-KEY covering a later one.
      Exclude timeRange = new Exclude(interest.getExclude());
      excludeBefore(timeRange, keyName.get(START_TIME_STAMP_INDEX));
      keyRequest.repeatAttempts.put(interestName, 0);

      sendKeyInterest
        (new Interest(interestName).setExclude(timeRange).setChildSelector(1),
         timeSlot, onEncryptedKeys, onError);
    }
    else {
      // If the received E-KEY covers the content key, encrypt the content.
      Blob encryptionKey = data.getContent();
      // If everything is correct, save the E-KEY as the current key.
      if (encryptContentKey
          (encryptionKey, keyName, timeSlot, onEncryptedKeys, onError)) {
        KeyInfo keyInfo = (KeyInfo)eKeyInfo_.get(interestName);
        keyInfo.beginTimeSlot = begin;
        keyInfo.endTimeSlot = end;
        keyInfo.keyBits = encryptionKey;
      }
    }
  }

  /**
   * Get the content key from the database_ and encrypt it for the timeSlot
   * using encryptionKey.
   * @param encryptionKey The encryption key value.
   * @param eKeyName The key name for the EncryptedContent.
   * @param timeSlot The time slot as milliseconds since Jan 1, 1970 UTC.
   * @param onEncryptedKeys When there are no more interests to process, this
   * calls onEncryptedKeys.onEncryptedKeys(keys) where keys is a list of
   * encrypted content key Data packets. If onEncryptedKeys is null, this does
   * not use it.
   * @return True if encryption succeeds, otherwise false.
   */
  private boolean
  encryptContentKey
    (Blob encryptionKey, Name eKeyName, double timeSlot,
     OnEncryptedKeys onEncryptedKeys, OnError onError)
    throws ProducerDb.Error, SecurityException, TpmBackEnd.Error, PibImpl.Error,
      KeyChain.Error
  {
    double timeCount = Math.round(timeSlot);
    KeyRequest keyRequest = (KeyRequest)keyRequests_.get(timeCount);

    Name keyName = new Name(namespace_);
    keyName.append(Encryptor.NAME_COMPONENT_C_KEY);
    keyName.append(Schedule.toIsoString(getRoundedTimeSlot(timeSlot)));

    Blob contentKey = database_.getContentKey(timeSlot);

    Data cKeyData = new Data();
    cKeyData.setName(keyName);
    EncryptParams params = new EncryptParams(EncryptAlgorithmType.RsaOaep);
    try {
      Encryptor.encryptData
        (cKeyData, contentKey, eKeyName, encryptionKey, params);
    } catch (Exception ex) {
      try {
        onError.onError(ErrorCode.EncryptionFailure, ex.getMessage());
      } catch (Exception exception) {
        logger_.log(Level.SEVERE, "Error in onError", exception);
      }
      return false;
    }

    keyChain_.sign(cKeyData);
    keyRequest.encryptedKeys.add(cKeyData);
    updateKeyRequest(keyRequest, timeCount, onEncryptedKeys);
    return true;
  }

  // TODO: Move this to be the main representation inside the Exclude object.
  private static class ExcludeEntry {
    public ExcludeEntry(Name.Component component, boolean anyFollowsComponent)
    {
      component_ = component;
      anyFollowsComponent_ = anyFollowsComponent;
    }

    public Name.Component component_;
    public boolean anyFollowsComponent_;
  }

  /**
   * Create a list of ExcludeEntry from the Exclude object.
   * @param exclude The Exclude object to read.
   * @return A new list of ExcludeEntry.
   */
  private static ArrayList
  getExcludeEntries(Exclude exclude)
  {
    ArrayList entries = new ArrayList();

    for (int i = 0; i < exclude.size(); ++i) {
      if (exclude.get(i).getType() == Exclude.Type.ANY) {
        if (entries.size() == 0)
          // Add a "beginning ANY".
          entries.add(new ExcludeEntry(new Name.Component(), true));
        else
          // Set anyFollowsComponent of the final component.
          ((ExcludeEntry)entries.get(entries.size() - 1)).anyFollowsComponent_ = true;
      }
      else
        entries.add(new ExcludeEntry(exclude.get(i).getComponent(), false));
    }

    return entries;
  }

  /**
   * Set the Exclude object from the list of ExcludeEntry.
   * @param exclude The Exclude object to update.
   * @param entries The list of ExcludeEntry.
   */
  private static void
  setExcludeEntries(Exclude exclude, ArrayList entries)
  {
    exclude.clear();

    for (int i = 0; i < entries.size(); ++i) {
      ExcludeEntry entry = (ExcludeEntry)entries.get(i);

      if (i == 0 && entry.component_.getValue().size() == 0 &&
          entry.anyFollowsComponent_)
        // This is a "beginning ANY".
        exclude.appendAny();
      else {
        exclude.appendComponent(entry.component_);
        if (entry.anyFollowsComponent_)
          exclude.appendAny();
      }
    }
  }

  /**
   * Get the latest entry in the list whose component_ is less than or equal to
   * component.
   * @param entries The list of ExcludeEntry.
   * @param component The component to compare.
   * @return The index of the found entry, or -1 if not found.
   */
  private static int
  findEntryBeforeOrAt(ArrayList entries, Name.Component component)
  {
    int i = entries.size() - 1;
    while (i >= 0) {
      if (((ExcludeEntry)entries.get(i)).component_.compare(component) <= 0)
        break;
      --i;
    }

    return i;
  }

  /**
   * Exclude all components in the range beginning at "from".
   * @param exclude The Exclude object to update.
   * @param from The first component in the exclude range.
   */
  private static void
  excludeAfter(Exclude exclude, Name.Component from)
  {
    ArrayList entries = getExcludeEntries(exclude);

    int iNewFrom;
    int iFoundFrom = findEntryBeforeOrAt(entries, from);
    if (iFoundFrom < 0) {
      // There is no entry before "from" so insert at the beginning.
      entries.add(0, new ExcludeEntry(from, true));
      iNewFrom = 0;
    }
    else {
      ExcludeEntry foundFrom = (ExcludeEntry)entries.get(iFoundFrom);

      if (!foundFrom.anyFollowsComponent_) {
        if (foundFrom.component_.equals(from)) {
          // There is already an entry with "from", so just set the "ANY" flag.
          foundFrom.anyFollowsComponent_ = true;
          iNewFrom = iFoundFrom;
        }
        else {
          // Insert following the entry before "from".
          entries.add(iFoundFrom + 1, new ExcludeEntry(from, true));
          iNewFrom = iFoundFrom + 1;
        }
      }
      else
        // The entry before "from" already has an "ANY" flag, so do nothing.
        iNewFrom = iFoundFrom;
    }

    // Remove entries after the new "from".
    int iRemoveBegin = iNewFrom + 1;
    int nRemoveNeeded = entries.size() - iRemoveBegin;
    for (int i = 0; i < nRemoveNeeded; ++i)
      entries.remove(iRemoveBegin);

    setExcludeEntries(exclude, entries);
  }

  /**
   * Exclude all components in the range ending at "to".
   * @param exclude The Exclude object to update.
   * @param to The last component in the exclude range.
   */
  private static void
  excludeBefore(Exclude exclude, Name.Component to)
  {
    excludeRange(exclude, new Name.Component(), to);
  }

  /**
   * Exclude all components in the range beginning at "from" and ending at "to".
   * @param exclude The Exclude object to update.
   * @param from The first component in the exclude range.
   * @param to The last component in the exclude range.
   */
  private static void
  excludeRange(Exclude exclude, Name.Component from, Name.Component to)
  {
    if (from.compare(to) >= 0) {
      if (from.compare(to) == 0)
        throw new Error
          ("excludeRange: from == to. To exclude a single component, sue excludeOne.");
      else
        throw new Error
          ("excludeRange: from must be less than to. Invalid range: [" +
           from.toEscapedString() + ", " + to.toEscapedString() + "]");
    }

    ArrayList entries = getExcludeEntries(exclude);

    int iNewFrom;
    int iFoundFrom = findEntryBeforeOrAt(entries, from);
    if (iFoundFrom < 0) {
      // There is no entry before "from" so insert at the beginning.
      entries.add(0, new ExcludeEntry(from, true));
      iNewFrom = 0;
    }
    else {
      ExcludeEntry foundFrom = (ExcludeEntry)entries.get(iFoundFrom);

      if (!foundFrom.anyFollowsComponent_) {
        if (foundFrom.component_.equals(from)) {
          // There is already an entry with "from", so just set the "ANY" flag.
          foundFrom.anyFollowsComponent_ = true;
          iNewFrom = iFoundFrom;
        }
        else {
          // Insert following the entry before "from".
          entries.add(iFoundFrom + 1, new ExcludeEntry(from, true));
          iNewFrom = iFoundFrom + 1;
        }
      }
      else
        // The entry before "from" already has an "ANY" flag, so do nothing.
        iNewFrom = iFoundFrom;
    }

    // We have at least one "from" before "to", so we know this will find an entry.
    int iFoundTo = findEntryBeforeOrAt(entries, to);
    ExcludeEntry foundTo = (ExcludeEntry)entries.get(iFoundTo);
    if (iFoundTo == iNewFrom)
      // Insert the "to" immediately after the "from".
      entries.add(iNewFrom + 1, new ExcludeEntry(to, false));
    else {
      int iRemoveEnd;
      if (!foundTo.anyFollowsComponent_) {
        if (foundTo.component_.equals(to))
          // The "to" entry already exists. Remove up to it.
          iRemoveEnd = iFoundTo;
        else {
          // Insert following the previous entry, which will be removed.
          entries.add(iFoundTo + 1, new ExcludeEntry(to, false));
          iRemoveEnd = iFoundTo + 1;
        }
      }
      else
        // "to" follows a component which is already followed by "ANY", meaning
        // the new range now encompasses it, so remove the component.
        iRemoveEnd = iFoundTo + 1;

      // Remove intermediate entries since they are inside the range.
      int iRemoveBegin = iNewFrom + 1;
      int nRemoveNeeded = iRemoveEnd - iRemoveBegin;
      for (int i = 0; i < nRemoveNeeded; ++i)
        entries.remove(iRemoveBegin);
    }

    setExcludeEntries(exclude, entries);
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
  private final Link keyRetrievalLink_;
  private static final Logger logger_ = Logger.getLogger(Producer.class.getName());

  private static final int START_TIME_STAMP_INDEX = -2;
  private static final int END_TIME_STAMP_INDEX = -1;
  private static final Link NO_LINK = new Link();
}
