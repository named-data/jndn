/**
 * Copyright (C) 2015-2016 Regents of the University of California.
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
  public interface OnEncryptedKeys {
    // List is a list of Data packets with the content key encrypted by E-KEYS.
    void onEncryptedKeys(List keys);
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
   * corresponding E-KEYs. The encrypted content keys are passed to the
   * onEncryptedKeys callback.
   * @param timeSlot The time slot as milliseconds since Jan 1, 1970 UTC.
   * @param onEncryptedKeys If this creates a content key, then this calls
   * onEncryptedKeys.onEncryptedKeys(keys) where keys is a list of encrypted
   * content key Data packets. If onEncryptedKeys is null, this does not use it.
   * @return The content key name.
   */
  public final Name
  createContentKey(double timeSlot, OnEncryptedKeys onEncryptedKeys)
    throws ProducerDb.Error, IOException, SecurityException
  {
    double hourSlot = getRoundedTimeSlot(timeSlot);

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
    excludeAfter(timeRange, new Name.Component(Schedule.toIsoString(timeSlot)));
    // Send interests for all nodes in the tree.
    eKeyInfo_.entrySet().iterator();
    for (Iterator i = eKeyInfo_.entrySet().iterator(); i.hasNext(); ) {
      Map.Entry entry = (Map.Entry)i.next();
      KeyInfo keyInfo = (KeyInfo)entry.getValue();
      keyRequest.repeatAttempts.put(entry.getKey(), 0);
      if (timeSlot < keyInfo.beginTimeSlot || timeSlot >= keyInfo.endTimeSlot) {
        sendKeyInterest
          ((Name)entry.getKey(), timeSlot, keyRequest, onEncryptedKeys, timeRange);
      }
      else {
        Name eKeyName = new Name((Name)entry.getKey());
        eKeyName.append(Schedule.toIsoString(keyInfo.beginTimeSlot));
        eKeyName.append(Schedule.toIsoString(keyInfo.endTimeSlot));
        encryptContentKey
          (keyRequest, keyInfo.keyBits, eKeyName, timeSlot, onEncryptedKeys);
      }
    }

    return contentKeyName;
  }

  /**
   * Encrypt the given content with the content key that covers timeSlot, and
   * update the data packet with the encrypted content and an appropriate data
   * name.
   * @param data An empty Data object which is updated.
   * @param timeSlot The time slot as milliseconds since Jan 1, 1970 UTC.
   * @param content The content to encrypt.
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
    dataName.append(Schedule.toIsoString(getRoundedTimeSlot(timeSlot)));

    data.setName(dataName);
    EncryptParams params = new EncryptParams(EncryptAlgorithmType.AesCbc, 16);
    Encryptor.encryptData(data, content, contentKeyName, contentKey, params);
    keyChain_.sign(data);
  }

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
   * handleCoveringKey and handleTimeout.
   * @param name The name of the interest to send.
   * @param timeSlot The time slot, passed to handleCoveringKey and
   * handleTimeout.
   * @param keyRequest The KeyRequest, passed to handleCoveringKey and
   * handleTimeout.
   * @param onEncryptedKeys The OnEncryptedKeys callback, passed to
   * handleCoveringKey and handleTimeout.
   * @param timeRange The Exclude for the interest.
   */
  private void
  sendKeyInterest
    (Name name, final double timeSlot, final KeyRequest keyRequest,
     final OnEncryptedKeys onEncryptedKeys, Exclude timeRange) throws IOException
  {
    OnData onKey = new OnData() {
      public void onData(Interest interest, final Data data) {
        try {
          handleCoveringKey(interest, data, timeSlot, keyRequest, onEncryptedKeys);
        } catch (Exception ex) {
          Logger.getLogger(Producer.class.getName()).log(Level.SEVERE, null, ex);
        }
      }
    };

    OnTimeout onTimeout = new OnTimeout() {
      public void onTimeout(Interest interest) {
        try {
          handleTimeout(interest, timeSlot, keyRequest, onEncryptedKeys);
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
   * @param interest The timed-out interest.
   * @param timeSlot The time slot as milliseconds since Jan 1, 1970 UTC.
   * @param keyRequest The KeyRequest which is updated.
   * @param onEncryptedKeys When there are no more interests to process, this
   * calls onEncryptedKeys.onEncryptedKeys(keys) where keys is a list of
   * encrypted content key Data packets. If onEncryptedKeys is null, this does
   * not use it.
   */
  private void
  handleTimeout
    (Interest interest, double timeSlot, KeyRequest keyRequest,
     OnEncryptedKeys onEncryptedKeys) throws IOException
  {
    Name interestName = interest.getName();

    if ((int)(Integer)keyRequest.repeatAttempts.get(interestName) < maxRepeatAttempts_) {
      keyRequest.repeatAttempts.put
        (interestName, (int)(Integer)keyRequest.repeatAttempts.get(interestName) + 1);
      sendKeyInterest
        (interestName, timeSlot, keyRequest, onEncryptedKeys, interest.getExclude());
    }
    else
      --keyRequest.interestCount;

    if (keyRequest.interestCount == 0 && onEncryptedKeys != null) {
      onEncryptedKeys.onEncryptedKeys(keyRequest.encryptedKeys);
      keyRequests_.remove(timeSlot);
    }
  }

  /**
   * This is called from an expressInterest OnData to check that the encryption
   * key contained in data fits the timeSlot. This sends a refined interest if
   * required.
   * @param interest The interest given to expressInterest.
   * @param data The fetched Data packet.
   * @param timeSlot The time slot as milliseconds since Jan 1, 1970 UTC.
   * @param keyRequest The KeyRequest which is updated.
   * @param onEncryptedKeys When there are no more interests to process, this
   * calls onEncryptedKeys.onEncryptedKeys(keys) where keys is a list of
   * encrypted content key Data packets. If onEncryptedKeys is null, this does
   * not use it.
   */
  private void
  handleCoveringKey
    (Interest interest, Data data, double timeSlot, KeyRequest keyRequest,
     OnEncryptedKeys onEncryptedKeys)
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
      excludeBefore(timeRange, keyName.get(iStartTimeStamp));
      keyRequest.repeatAttempts.put(interestName, 0);
      sendKeyInterest
        (interestName, timeSlot, keyRequest, onEncryptedKeys, timeRange);
      return;
    }

    Blob encryptionKey = data.getContent();
    KeyInfo keyInfo = (KeyInfo)eKeyInfo_.get(interestName);
    keyInfo.beginTimeSlot = begin;
    keyInfo.endTimeSlot = end;
    keyInfo.keyBits = encryptionKey;

    encryptContentKey
      (keyRequest, encryptionKey, keyName, timeSlot, onEncryptedKeys);
  }

  /**
   * Get the content key from the database_ and encrypt it for the timeSlot
   * using encryptionKey.
   * @param keyRequest The KeyRequest which is updated.
   * @param encryptionKey The encryption key value.
   * @param eKeyName The key name for the EncryptedContent.
   * @param timeSlot The time slot as milliseconds since Jan 1, 1970 UTC.
   * @param onEncryptedKeys When there are no more interests to process, this
   * calls onEncryptedKeys.onEncryptedKeys(keys) where keys is a list of
   * encrypted content key Data packets. If onEncryptedKeys is null, this does
   * not use it.
   */
  private void
  encryptContentKey
    (KeyRequest keyRequest, Blob encryptionKey, Name eKeyName,
     double timeSlot, OnEncryptedKeys onEncryptedKeys)
    throws ProducerDb.Error, SecurityException
  {
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
      // Consolidate errors such as InvalidKeyException.
      throw new SecurityException
        ("encryptContentKey: Error in encryptData: " + ex.getMessage());
    }

    keyChain_.sign(cKeyData);
    keyRequest.encryptedKeys.add(cKeyData);

    --keyRequest.interestCount;
    if (keyRequest.interestCount == 0 && onEncryptedKeys != null) {
      onEncryptedKeys.onEncryptedKeys(keyRequest.encryptedKeys);
      keyRequests_.remove(timeSlot);
    }
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
  private static ArrayList getExcludeEntries(Exclude exclude)
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
  private static void setExcludeEntries(Exclude exclude, ArrayList entries)
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
  private static int findEntryBeforeOrAt
    (ArrayList entries, Name.Component component)
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
  private static void excludeAfter(Exclude exclude, Name.Component from)
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
  private static void excludeBefore(Exclude exclude, Name.Component to)
  {
    excludeRange(exclude, new Name.Component(), to);
  }

  /**
   * Exclude all components in the range beginning at "from" and ending at "to".
   * @param exclude The Exclude object to update.
   * @param from The first component in the exclude range.
   * @param to The last component in the exclude range.
   */
  private static void excludeRange
    (Exclude exclude, Name.Component from, Name.Component to)
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

  private static final int iStartTimeStamp = -2;
  private static final int iEndTimeStamp = -1;
}
