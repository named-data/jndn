/**
 * Copyright (C) 2014-2016 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
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

package net.named_data.jndn.util;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.logging.Level;
import java.util.logging.Logger;
import net.named_data.jndn.Data;
import net.named_data.jndn.Face;
import net.named_data.jndn.ForwardingFlags;
import net.named_data.jndn.Interest;
import net.named_data.jndn.InterestFilter;
import net.named_data.jndn.Name;
import net.named_data.jndn.OnInterestCallback;
import net.named_data.jndn.OnRegisterFailed;
import net.named_data.jndn.OnRegisterSuccess;
import net.named_data.jndn.encoding.WireFormat;
import net.named_data.jndn.security.SecurityException;

/**
 * A MemoryContentCache holds a set of Data packets and answers an Interest to
 * return the correct Data packet. The cache is periodically cleaned up to
 * remove each stale Data packet based on its FreshnessPeriod (if it has one).
 * @note This class is an experimental feature.  See the API docs for more detail at
 * http://named-data.net/doc/ndn-ccl-api/memory-content-cache.html .
 */
public class MemoryContentCache implements OnInterestCallback {
  /**
   * Create a new MemoryContentCache to use the given Face.
   * @param face The Face to use to call registerPrefix and setInterestFilter,
   * and which will call this object's OnInterest callback.
   * @param cleanupIntervalMilliseconds The interval in milliseconds
   * between each check to clean up stale content in the cache. If this is a
   * large number, then effectively the stale content will not be removed from
   * the cache.
   */
  public MemoryContentCache(Face face, double cleanupIntervalMilliseconds)
  {
    face_ = face;
    cleanupIntervalMilliseconds_ = cleanupIntervalMilliseconds;
    construct();
  }

  /**
   * Create a new MemoryContentCache to use the given Face, with a default
   * cleanupIntervalMilliseconds of 1000.0 milliseconds.
   * @param face The Face to use to call registerPrefix and setInterestFilter,
   * and which will call this object's OnInterest callback.
   */
  public MemoryContentCache(Face face)
  {
    face_ = face;
    cleanupIntervalMilliseconds_ = 1000.0;
    construct();
  }

  private void
  construct()
  {
    nextCleanupTime_ = Common.getNowMilliseconds() + cleanupIntervalMilliseconds_;

    storePendingInterestCallback_ = new OnInterestCallback() {
      public void onInterest
        (Name localPrefix, Interest localInterest, Face localFace,
         long localInterestFilterId, InterestFilter localFilter)
      {
        storePendingInterest(localInterest, localFace);
      }
    };
  }

  /**
   * Call registerPrefix on the Face given to the constructor so that this
   * MemoryContentCache will answer interests whose name has the prefix.
   * Alternatively, if the Face's registerPrefix has already been called, then
   * you can call this object's setInterestFilter.
   * @param prefix The Name for the prefix to register. This copies the Name.
   * @param onRegisterFailed If register prefix fails for any reason, this
   * calls onRegisterFailed.onRegisterFailed(prefix).
   * NOTE: The library will log any exceptions thrown by this callback, but for
   * better error handling the callback should catch and properly handle any
   * exceptions.
   * @param onRegisterSuccess This calls
   * onRegisterSuccess.onRegisterSuccess(prefix, registeredPrefixId) when this
   * receives a success message from the forwarder. If onRegisterSuccess is null,
   * this does not use it.
   * NOTE: The library will log any exceptions thrown by this callback, but for
   * better error handling the callback should catch and properly handle any
   * exceptions.
   * @param onDataNotFound If a data packet for an interest is not found in the
   * cache, this forwards the interest by calling
   * onDataNotFound.onInterest(prefix, interest, face, interestFilterId, filter).
   * Your callback can find the Data packet for the interest and call
   * face.putData(data).  If your callback cannot find the Data packet, it can
   * optionally call storePendingInterest(interest, face) to store the pending
   * interest in this object to be satisfied by a later call to add(data). If
   * you want to automatically store all pending interests, you can simply use
   * getStorePendingInterest() for onDataNotFound. If onDataNotFound is null,
   * this does not use it.
   * NOTE: The library will log any exceptions thrown by this callback, but for
   * better error handling the callback should catch and properly handle any
   * exceptions.
   * @param flags See Face.registerPrefix.
   * @param wireFormat See Face.registerPrefix.
   * @throws IOException For I/O error in sending the registration request.
   * @throws SecurityException If signing a command interest for NFD and cannot
   * find the private key for the certificateName.
   */
  public final void
  registerPrefix
    (Name prefix, OnRegisterFailed onRegisterFailed,
     OnRegisterSuccess onRegisterSuccess, OnInterestCallback onDataNotFound,
     ForwardingFlags flags, WireFormat wireFormat)
     throws IOException, SecurityException
  {
    if (onDataNotFound != null)
      onDataNotFoundForPrefix_.put(prefix.toUri(), onDataNotFound);
    long registeredPrefixId = face_.registerPrefix
      (prefix, this, onRegisterFailed, onRegisterSuccess, flags, wireFormat);
    registeredPrefixIdList_.add(registeredPrefixId);
  }

  /**
   * Call registerPrefix on the Face given to the constructor so that this
   * MemoryContentCache will answer interests whose name has the prefix.
   * Alternatively, if the Face's registerPrefix has already been called, then
   * you can call this object's setInterestFilter.
   * This uses the default WireFormat.getDefaultWireFormat().
   * @param prefix The Name for the prefix to register. This copies the Name.
   * @param onRegisterFailed If register prefix fails for any reason, this
   * calls onRegisterFailed.onRegisterFailed(prefix).
   * NOTE: The library will log any exceptions thrown by this callback, but for
   * better error handling the callback should catch and properly handle any
   * exceptions.
   * @param onRegisterSuccess This calls
   * onRegisterSuccess.onRegisterSuccess(prefix, registeredPrefixId) when this
   * receives a success message from the forwarder. If onRegisterSuccess is null,
   * this does not use it.
   * NOTE: The library will log any exceptions thrown by this callback, but for
   * better error handling the callback should catch and properly handle any
   * exceptions.
   * @param onDataNotFound If a data packet for an interest is not found in the
   * cache, this forwards the interest by calling
   * onInterest.onInterest(prefix, interest, face, interestFilterId, filter).
   * Your callback can find the Data packet for the interest and call
   * face.putData(data).  If your callback cannot find the Data packet, it can
   * optionally call storePendingInterest(interest, face) to store the pending
   * interest in this object to be satisfied by a later call to add(data). If
   * you want to automatically store all pending interests, you can simply use
   * getStorePendingInterest() for onDataNotFound. If onDataNotFound is null,
   * this does not use it.
   * @param flags See Face.registerPrefix.
   * @throws IOException For I/O error in sending the registration request.
   * @throws SecurityException If signing a command interest for NFD and cannot
   * find the private key for the certificateName.
   */
  public final void
  registerPrefix
    (Name prefix, OnRegisterFailed onRegisterFailed,
     OnRegisterSuccess onRegisterSuccess, OnInterestCallback onDataNotFound,
     ForwardingFlags flags) throws IOException, SecurityException
  {
    registerPrefix
      (prefix, onRegisterFailed, onRegisterSuccess, onDataNotFound, flags,
       WireFormat.getDefaultWireFormat());
  }

  /**
   * Call registerPrefix on the Face given to the constructor so that this
   * MemoryContentCache will answer interests whose name has the prefix.
   * Alternatively, if the Face's registerPrefix has already been called, then
   * you can call this object's setInterestFilter.
   * This uses the default WireFormat.getDefaultWireFormat().
   * Use default ForwardingFlags.
   * @param prefix The Name for the prefix to register. This copies the Name.
   * @param onRegisterFailed If register prefix fails for any reason, this
   * calls onRegisterFailed.onRegisterFailed(prefix).
   * NOTE: The library will log any exceptions thrown by this callback, but for
   * better error handling the callback should catch and properly handle any
   * exceptions.
   * @param onRegisterSuccess This calls
   * onRegisterSuccess.onRegisterSuccess(prefix, registeredPrefixId) when this
   * receives a success message from the forwarder. If onRegisterSuccess is null,
   * this does not use it.
   * NOTE: The library will log any exceptions thrown by this callback, but for
   * better error handling the callback should catch and properly handle any
   * exceptions.
   * @param onDataNotFound If a data packet for an interest is not found in the
   * cache, this forwards the interest by calling
   * onDataNotFound.onInterest(prefix, interest, face, interestFilterId, filter).
   * Your callback can find the Data packet for the interest and call
   * face.putData(data).  If your callback cannot find the Data packet, it can
   * optionally call storePendingInterest(interest, face) to store the pending
   * interest in this object to be satisfied by a later call to add(data). If
   * you want to automatically store all pending interests, you can simply use
   * getStorePendingInterest() for onDataNotFound. If onDataNotFound is null,
   * this does not use it.
   * NOTE: The library will log any exceptions thrown by this callback, but for
   * better error handling the callback should catch and properly handle any
   * exceptions.
   * @throws IOException For I/O error in sending the registration request.
   * @throws SecurityException If signing a command interest for NFD and cannot
   * find the private key for the certificateName.
   */
  public final void
  registerPrefix
    (Name prefix, OnRegisterFailed onRegisterFailed,
     OnRegisterSuccess onRegisterSuccess, OnInterestCallback onDataNotFound)
    throws IOException, SecurityException
  {
    registerPrefix
      (prefix, onRegisterFailed, onRegisterSuccess, onDataNotFound,
       new ForwardingFlags(), WireFormat.getDefaultWireFormat());
  }

  /**
   * Call registerPrefix on the Face given to the constructor so that this
   * MemoryContentCache will answer interests whose name has the prefix.
   * Alternatively, if the Face's registerPrefix has already been called, then
   * you can call this object's setInterestFilter.
   * Do not call a callback if a data packet is not found in the cache.
   * This uses the default WireFormat.getDefaultWireFormat().
   * Use default ForwardingFlags.
   * @param prefix The Name for the prefix to register. This copies the Name.
   * @param onRegisterFailed If register prefix fails for any reason, this
   * calls onRegisterFailed.onRegisterFailed(prefix).
   * NOTE: The library will log any exceptions thrown by this callback, but for
   * better error handling the callback should catch and properly handle any
   * exceptions.
   * @param onRegisterSuccess This calls
   * onRegisterSuccess.onRegisterSuccess(prefix, registeredPrefixId) when this
   * receives a success message from the forwarder. If onRegisterSuccess is null,
   * this does not use it.
   * NOTE: The library will log any exceptions thrown by this callback, but for
   * better error handling the callback should catch and properly handle any
   * exceptions.
   * @throws IOException For I/O error in sending the registration request.
   * @throws SecurityException If signing a command interest for NFD and cannot
   * find the private key for the certificateName.
   */
  public final void
  registerPrefix(Name prefix, OnRegisterFailed onRegisterFailed,
     OnRegisterSuccess onRegisterSuccess)
    throws IOException, SecurityException
  {
    registerPrefix
      (prefix, onRegisterFailed, onRegisterSuccess, null, new ForwardingFlags(),
       WireFormat.getDefaultWireFormat());
  }

  /**
   * Call registerPrefix on the Face given to the constructor so that this
   * MemoryContentCache will answer interests whose name has the prefix.
   * Alternatively, if the Face's registerPrefix has already been called, then
   * you can call this object's setInterestFilter.
   * @param prefix The Name for the prefix to register. This copies the Name.
   * @param onRegisterFailed If register prefix fails for any reason, this
   * calls onRegisterFailed.onRegisterFailed(prefix).
   * NOTE: The library will log any exceptions thrown by this callback, but for
   * better error handling the callback should catch and properly handle any
   * exceptions.
   * @param onDataNotFound If a data packet for an interest is not found in the
   * cache, this forwards the interest by calling
   * onDataNotFound.onInterest(prefix, interest, face, interestFilterId, filter).
   * Your callback can find the Data packet for the interest and call
   * face.putData(data).  If your callback cannot find the Data packet, it can
   * optionally call storePendingInterest(interest, face) to store the pending
   * interest in this object to be satisfied by a later call to add(data). If
   * you want to automatically store all pending interests, you can simply use
   * getStorePendingInterest() for onDataNotFound. If onDataNotFound is null,
   * this does not use it.
   * NOTE: The library will log any exceptions thrown by this callback, but for
   * better error handling the callback should catch and properly handle any
   * exceptions.
   * @param flags See Face.registerPrefix.
   * @param wireFormat See Face.registerPrefix.
   * @throws IOException For I/O error in sending the registration request.
   * @throws SecurityException If signing a command interest for NFD and cannot
   * find the private key for the certificateName.
   */
  public final void
  registerPrefix
    (Name prefix, OnRegisterFailed onRegisterFailed, OnInterestCallback onDataNotFound,
     ForwardingFlags flags, WireFormat wireFormat) throws IOException, SecurityException
  {
    registerPrefix
      (prefix, onRegisterFailed, null, onDataNotFound, flags, wireFormat);
  }

  /**
   * Call registerPrefix on the Face given to the constructor so that this
   * MemoryContentCache will answer interests whose name has the prefix.
   * Alternatively, if the Face's registerPrefix has already been called, then
   * you can call this object's setInterestFilter.
   * This uses the default WireFormat.getDefaultWireFormat().
   * @param prefix The Name for the prefix to register. This copies the Name.
   * @param onRegisterFailed If register prefix fails for any reason, this
   * calls onRegisterFailed.onRegisterFailed(prefix).
   * NOTE: The library will log any exceptions thrown by this callback, but for
   * better error handling the callback should catch and properly handle any
   * exceptions.
   * @param onDataNotFound If a data packet for an interest is not found in the
   * cache, this forwards the interest by calling
   * onDataNotFound.onInterest(prefix, interest, face, interestFilterId, filter).
   * Your callback can find the Data packet for the interest and call
   * face.putData(data).  If your callback cannot find the Data packet, it can
   * optionally call storePendingInterest(interest, face) to store the pending
   * interest in this object to be satisfied by a later call to add(data). If
   * you want to automatically store all pending interests, you can simply use
   * getStorePendingInterest() for onDataNotFound. If onDataNotFound is null,
   * this does not use it.
   * @param flags See Face.registerPrefix.
   * @throws IOException For I/O error in sending the registration request.
   * @throws SecurityException If signing a command interest for NFD and cannot
   * find the private key for the certificateName.
   */
  public final void
  registerPrefix
    (Name prefix, OnRegisterFailed onRegisterFailed, OnInterestCallback onDataNotFound,
     ForwardingFlags flags) throws IOException, SecurityException
  {
    registerPrefix
      (prefix, onRegisterFailed, onDataNotFound, flags,
       WireFormat.getDefaultWireFormat());
  }

  /**
   * Call registerPrefix on the Face given to the constructor so that this
   * MemoryContentCache will answer interests whose name has the prefix.
   * Alternatively, if the Face's registerPrefix has already been called, then
   * you can call this object's setInterestFilter.
   * This uses the default WireFormat.getDefaultWireFormat().
   * Use default ForwardingFlags.
   * @param prefix The Name for the prefix to register. This copies the Name.
   * @param onRegisterFailed If register prefix fails for any reason, this
   * calls onRegisterFailed.onRegisterFailed(prefix).
   * NOTE: The library will log any exceptions thrown by this callback, but for
   * better error handling the callback should catch and properly handle any
   * exceptions.
   * @param onDataNotFound If a data packet for an interest is not found in the
   * cache, this forwards the interest by calling
   * onDataNotFound.onInterest(prefix, interest, face, interestFilterId, filter).
   * Your callback can find the Data packet for the interest and call
   * face.putData(data).  If your callback cannot find the Data packet, it can
   * optionally call storePendingInterest(interest, face) to store the pending
   * interest in this object to be satisfied by a later call to add(data). If
   * you want to automatically store all pending interests, you can simply use
   * getStorePendingInterest() for onDataNotFound. If onDataNotFound is null,
   * this does not use it.
   * NOTE: The library will log any exceptions thrown by this callback, but for
   * better error handling the callback should catch and properly handle any
   * exceptions.
   * @throws IOException For I/O error in sending the registration request.
   * @throws SecurityException If signing a command interest for NFD and cannot
   * find the private key for the certificateName.
   */
  public final void
  registerPrefix
    (Name prefix, OnRegisterFailed onRegisterFailed, OnInterestCallback onDataNotFound)
    throws IOException, SecurityException
  {
    registerPrefix
      (prefix, onRegisterFailed, onDataNotFound, new ForwardingFlags(),
       WireFormat.getDefaultWireFormat());
  }

  /**
   * Call registerPrefix on the Face given to the constructor so that this
   * MemoryContentCache will answer interests whose name matches the filter.
   * Alternatively, if the Face's registerPrefix has already been called, then
   * you can call this object's setInterestFilter.
   * Do not call a callback if a data packet is not found in the cache.
   * This uses the default WireFormat.getDefaultWireFormat().
   * Use default ForwardingFlags.
   * @param prefix The Name for the prefix to register. This copies the Name.
   * @param onRegisterFailed If register prefix fails for any reason, this
   * calls onRegisterFailed.onRegisterFailed(prefix).
   * NOTE: The library will log any exceptions thrown by this callback, but for
   * better error handling the callback should catch and properly handle any
   * exceptions.
   * @throws IOException For I/O error in sending the registration request.
   * @throws SecurityException If signing a command interest for NFD and cannot
   * find the private key for the certificateName.
   */
  public final void
  registerPrefix(Name prefix, OnRegisterFailed onRegisterFailed)
    throws IOException, SecurityException
  {
    registerPrefix
      (prefix, onRegisterFailed, null, new ForwardingFlags(),
       WireFormat.getDefaultWireFormat());
  }

  /**
   * Call setInterestFilter on the Face given to the constructor so that this
   * MemoryContentCache will answer interests whose name matches the filter.
   * @param filter The InterestFilter with a prefix and optional regex filter
   * used to match the name of an incoming Interest. This makes a copy of filter.
   * @param onDataNotFound If a data packet for an interest is not found in the
   * cache, this forwards the interest by calling
   * onDataNotFound.onInterest(prefix, interest, face, interestFilterId, filter).
   * Your callback can find the Data packet for the interest and call
   * face.putData(data).  Note: If you call setInterestFilter multiple times where
   * filter.getPrefix() is the same, it is undetermined which onDataNotFound
   * will be called. If your callback cannot find the Data packet, it can
   * optionally call storePendingInterest(interest, face) to store the pending
   * interest in this object to be satisfied by a later call to add(data). If
   * you want to automatically store all pending interests, you can simply use
   * getStorePendingInterest() for onDataNotFound. If onDataNotFound is null,
   * this does not use it.
   * NOTE: The library will log any exceptions thrown by this callback, but for
   * better error handling the callback should catch and properly handle any
   * exceptions.
   */
  public final void
  setInterestFilter(InterestFilter filter, OnInterestCallback onDataNotFound)
  {
    if (onDataNotFound != null)
      onDataNotFoundForPrefix_.put(filter.getPrefix().toUri(), onDataNotFound);
    long interestFilterId = face_.setInterestFilter(filter, this);
    interestFilterIdList_.add(interestFilterId);
  }

  /**
   * Call setInterestFilter on the Face given to the constructor so that this
   * MemoryContentCache will answer interests whose name has the prefix.
   * Do not call a callback if a data packet is not found in the cache.
   * @param filter The InterestFilter with a prefix and optional regex filter
   * used to match the name of an incoming Interest. This makes a copy of filter.
   */
  public final void
  setInterestFilter(InterestFilter filter)
  {
    setInterestFilter(filter, null);
  }

  /**
   * Call setInterestFilter on the Face given to the constructor so that this
   * MemoryContentCache will answer interests whose name has the prefix.
   * @param prefix The Name prefix used to match the name of an incoming
   * Interest. This copies the Name.
   * @param onDataNotFound If a data packet for an interest is not found in the
   * cache, this forwards the interest by calling
   * onDataNotFound.onInterest(prefix, interest, face, interestFilterId, filter).
   * Your callback can find the Data packet for the interest and call
   * face.putData(data).  Note: If you call setInterestFilter multiple times where
   * filter.getPrefix() is the same, it is undetermined which onDataNotFound
   * will be called. If your callback cannot find the Data packet, it can
   * optionally call storePendingInterest(interest, face) to store the pending
   * interest in this object to be satisfied by a later call to add(data). If
   * you want to automatically store all pending interests, you can simply use
   * getStorePendingInterest() for onDataNotFound. If onDataNotFound is null,
   * this does not use it.
   * NOTE: The library will log any exceptions thrown by this callback, but for
   * better error handling the callback should catch and properly handle any
   * exceptions.
   */
  public final void
  setInterestFilter(Name prefix, OnInterestCallback onDataNotFound)
  {
    if (onDataNotFound != null)
      onDataNotFoundForPrefix_.put(prefix.toUri(), onDataNotFound);
    long interestFilterId = face_.setInterestFilter(prefix, this);
    interestFilterIdList_.add(interestFilterId);
  }

  /**
   * Call setInterestFilter on the Face given to the constructor so that this
   * MemoryContentCache will answer interests whose name has the prefix.
   * Do not call a callback if a data packet is not found in the cache.
   * @param prefix The Name prefix used to match the name of an incoming
   * Interest. This copies the Name.
   */
  public final void
  setInterestFilter(Name prefix)
  {
    setInterestFilter(prefix, null);
  }

  /**
   * Call Face.unsetInterestFilter and Face.removeRegisteredPrefix for all the
   * prefixes given to the setInterestFilter and registerPrefix method on this
   * MemoryContentCache object so that it will not receive interests any more.
   * You can call this if you want to "shut down" this MemoryContentCache while
   * your application is still running.
   */
  public final void
  unregisterAll()
  {
    for (int i = 0; i < interestFilterIdList_.size(); ++i)
      face_.unsetInterestFilter((long)interestFilterIdList_.get(i));
    interestFilterIdList_.clear();

    for (int i = 0; i < registeredPrefixIdList_.size(); ++i)
      face_.removeRegisteredPrefix((long)registeredPrefixIdList_.get(i));
    registeredPrefixIdList_.clear();

    // Also clear each onDataNotFoundForPrefix given to registerPrefix.
    onDataNotFoundForPrefix_.clear();
  }

  /**
   * Add the Data packet to the cache so that it is available to use to
   * answer interests. If data.getMetaInfo().getFreshnessPeriod() is not
   * negative, set the staleness time to now plus
   * data.getMetaInfo().getFreshnessPeriod(), which is checked during cleanup to
   * remove stale content. This also checks if cleanupIntervalMilliseconds
   * milliseconds have passed and removes stale content from the cache. After
   * removing stale content, remove timed-out pending interests from
   * storePendingInterest(), then if the added Data packet satisfies any
   * interest, send it through the face and remove the interest from the pending
   * interest table.
   * @param data The Data packet object to put in the cache. This copies the
   * fields from the object.
   */
  public final void
  add(Data data)
  {
    doCleanup();

    if (data.getMetaInfo().getFreshnessPeriod() >= 0.0) {
      // The content will go stale, so use staleTimeCache_.
      StaleTimeContent content = new StaleTimeContent(data);
      // Insert into staleTimeCache, sorted on content.staleTimeMilliseconds.
      // Search from the back since we expect it to go there.
      int i = staleTimeCache_.size() - 1;
      while (i >= 0) {
        if (staleTimeCache_.get(i).getStaleTimeMilliseconds() <=
            content.getStaleTimeMilliseconds())
          break;
        --i;
      }
      // Element i is the greatest less than or equal to
      // content.staleTimeMilliseconds, so insert after it.
      staleTimeCache_.add(i + 1, content);
    }
    else
      // The data does not go stale, so use noStaleTimeCache_.
      noStaleTimeCache_.add(new Content(data));

    // Remove timed-out interests and check if the data packet matches any
    // pending interest.
    // Go backwards through the list so we can erase entries.
    double nowMilliseconds = Common.getNowMilliseconds();
    for (int i = pendingInterestTable_.size() - 1; i >= 0; --i) {
      PendingInterest pendingInterest = pendingInterestTable_.get(i);
      if (pendingInterest.isTimedOut(nowMilliseconds)) {
        pendingInterestTable_.remove(i);
        continue;
      }

      if (pendingInterest.getInterest().matchesName(data.getName())) {
        try {
          // Send to the same face from the original call to onInterest.
          // wireEncode returns the cached encoding if available.
          pendingInterest.getFace().send(data.wireEncode());
        } catch (IOException ex) {
          Logger.getLogger(MemoryContentCache.class.getName()).log(Level.SEVERE,
            ex.getMessage());
          return;
        }

        // The pending interest is satisfied, so remove it.
        pendingInterestTable_.remove(i);
      }
    }
  }

  /**
   * Store an interest from an OnInterest callback in the internal pending
   * interest table (normally because there is no Data packet available yet to
   * satisfy the interest). add(data) will check if the added Data packet
   * satisfies any pending interest and send it through the face.
   * @param interest The Interest for which we don't have a Data packet yet. You
   * should not modify the interest after calling this.
   * @param face The Face with the connection which received the interest. This
   * comes from the OnInterest callback.
   */
  public final void
  storePendingInterest(Interest interest, Face face)
  {
    pendingInterestTable_.add(new PendingInterest(interest, face));
  }

  /**
   * Return a callback to use for onDataNotFound in registerPrefix which simply
   * calls storePendingInterest() to store the interest that doesn't match a
   * Data packet. add(data) will check if the added Data packet satisfies any
   * pending interest and send it.
   * @return A callback to use for onDataNotFound in registerPrefix().
   */
  public final OnInterestCallback
  getStorePendingInterest()
  {
    return storePendingInterestCallback_;
  }

  public final void
  onInterest
    (Name prefix, Interest interest, Face face, long interestFilterId,
     InterestFilter filter)
  {
    doCleanup();

    Name.Component selectedComponent = null;
    Blob selectedEncoding = null;
    // We need to iterate over both arrays.
    int totalSize = staleTimeCache_.size() + noStaleTimeCache_.size();
    for (int i = 0; i < totalSize; ++i) {
      Content content;
      if (i < staleTimeCache_.size())
        content = staleTimeCache_.get(i);
      else
        // We have iterated over the first array. Get from the second.
        content = noStaleTimeCache_.get(i - staleTimeCache_.size());

      if (interest.matchesName(content.getName())) {
        if (interest.getChildSelector() < 0) {
          // No child selector, so send the first match that we have found.
          try {
            face.send(content.getDataEncoding());
          } catch (IOException ex) {
            Logger.getLogger(MemoryContentCache.class.getName()).log(Level.SEVERE, null, ex);
          }
          return;
        }
        else {
          // Update selectedEncoding based on the child selector.
          Name.Component component;
          if (content.getName().size() > interest.getName().size())
            component = content.getName().get(interest.getName().size());
          else
            component = emptyComponent_;

          boolean gotBetterMatch = false;
          if (selectedEncoding == null)
            // Save the first match.
            gotBetterMatch = true;
          else {
            if (interest.getChildSelector() == 0) {
              // Leftmost child.
              if (component.compare(selectedComponent) < 0)
                gotBetterMatch = true;
            }
            else {
              // Rightmost child.
              if (component.compare(selectedComponent) > 0)
                gotBetterMatch = true;
            }
          }

          if (gotBetterMatch) {
            selectedComponent = component;
            selectedEncoding = content.getDataEncoding();
          }
        }
      }
    }

    if (selectedEncoding != null) {
      // We found the leftmost or rightmost child.
      try {
        face.send(selectedEncoding);
      } catch (IOException ex) {
        Logger.getLogger(MemoryContentCache.class.getName()).log(Level.SEVERE, null, ex);
      }
    }
    else {
      // Call the onDataNotFound callback (if defined).
      Object onDataNotFound = onDataNotFoundForPrefix_.get(prefix.toUri());
      if (onDataNotFound != null) {
        try {
          ((OnInterestCallback)onDataNotFound).onInterest
            (prefix, interest, face, interestFilterId, filter);
        } catch (Throwable ex) {
          logger_.log(Level.SEVERE, "Error in onDataNotFound", ex);
        }
      }
    }
  }

  /**
   * Content is a private class to hold the name and encoding for each entry
   * in the cache. This base class is for a Data packet without a
   * FreshnessPeriod.
   */
  private class Content {
    /**
     * Create a new Content entry to hold data's name and wire encoding.
     * @param data The Data packet whose name and wire encoding are copied.
     */
    public Content(Data data)
    {
      // wireEncode returns the cached encoding if available.
      name_ = data.getName();
      dataEncoding_ = data.wireEncode();
    }

    public final Name
    getName() { return name_; }

    public final Blob
    getDataEncoding() { return dataEncoding_; }

    private final Name name_;
    private final Blob dataEncoding_;
  }

  /**
   * StaleTimeContent extends Content to include the staleTimeMilliseconds
   * for when this entry should be cleaned up from the cache.
   */
  private class StaleTimeContent extends Content {
    /**
     * Create a new StaleTimeContent to hold data's name and wire encoding
     * as well as the staleTimeMilliseconds which is now plus
     * data.getMetaInfo().getFreshnessPeriod().
     * @param data The Data packet whose name and wire encoding are copied.
     */
    public StaleTimeContent(Data data)
    {
      // wireEncode returns the cached encoding if available.
      super(data);

      // Set up staleTimeMilliseconds_.
      staleTimeMilliseconds_ = Common.getNowMilliseconds() +
        data.getMetaInfo().getFreshnessPeriod();
    }

    /**
     * Check if this content is stale.
     * @param nowMilliseconds The current time in milliseconds from
     * Common.getNowMilliseconds().
     * @return True if this content is stale, otherwise false.
     */
    public final boolean
    isStale(double nowMilliseconds)
    {
      return staleTimeMilliseconds_ <= nowMilliseconds;
    }

    public final double
    getStaleTimeMilliseconds() { return staleTimeMilliseconds_; }

    private final double staleTimeMilliseconds_; /**< The time when the content
      becomse stale in milliseconds according to Common.getNowMilliseconds() */
  }

  /**
   * A PendingInterest holds an interest which onInterest received but could
   * not satisfy. When we add a new data packet to the cache, we will also check
   * if it satisfies a pending interest.
   */
  private static class PendingInterest {
    /**
     * Create a new PendingInterest and set the timeoutTime_ based on the current
     * time and the interest lifetime.
     * @param interest The interest.
     * @param face The face from the onInterest callback. If the
     * interest is satisfied later by a new data packet, we will send the data
     * packet to the face.
     */
    public PendingInterest(Interest interest, Face face)
    {
      interest_ = interest;
      face_ = face;

      // Set up timeoutTimeMilliseconds_.
      if (interest_.getInterestLifetimeMilliseconds() >= 0.0)
        timeoutTimeMilliseconds_ = Common.getNowMilliseconds() +
          interest_.getInterestLifetimeMilliseconds();
      else
        // No timeout.
        timeoutTimeMilliseconds_ = -1.0;
    }

    /**
     * Return the interest given to the constructor.
     */
    public final Interest
    getInterest() { return interest_; }

    /**
     * Return the face given to the constructor.
     */
    public final Face
    getFace() { return face_; }

    /**
     * Check if this interest is timed out.
     * @param nowMilliseconds The current time in milliseconds from
     *   Common.getNowMilliseconds.
     * @return True if this interest timed out, otherwise false.
     */
    public final boolean
    isTimedOut(double nowMilliseconds)
    {
      return timeoutTimeMilliseconds_ >= 0.0 && nowMilliseconds >= timeoutTimeMilliseconds_;
    }

    private final Interest interest_;
    private final Face face_;
    private final double timeoutTimeMilliseconds_; /**< The time when the
      * interest times out in milliseconds according to ndn_getNowMilliseconds,
      * or -1 for no timeout. */
  }

  /**
   * Check if now is greater than nextCleanupTime_ and, if so, remove stale
   * content from staleTimeCache_ and reset nextCleanupTime_ based on
   * cleanupIntervalMilliseconds_. Since add(Data) does a sorted insert into
   * staleTimeCache_, the check for stale data is quick and does not require
   * searching the entire staleTimeCache_.
   */
  private void
  doCleanup()
  {
    double now = Common.getNowMilliseconds();
    if (now >= nextCleanupTime_) {
      // staleTimeCache_ is sorted on staleTimeMilliseconds_, so we only need to
      // erase the stale entries at the front, then quit.
      while (staleTimeCache_.size() > 0 && staleTimeCache_.get(0).isStale(now))
        staleTimeCache_.remove(0);

      nextCleanupTime_ = now + cleanupIntervalMilliseconds_;
    }
  }

  private final Face face_;
  private final double cleanupIntervalMilliseconds_;
  private double nextCleanupTime_;
  // Use HashMap without generics so it works with older Java compilers.
  private final HashMap onDataNotFoundForPrefix_ =
    new HashMap(); /**< The map key is the prefix.toUri().
                    * The value is the OnInterest callback. */
  // Use ArrayList without generics so it works with older Java compilers.
  private final ArrayList<Long> interestFilterIdList_ = new ArrayList<Long>();
  private final ArrayList<Long> registeredPrefixIdList_ = new ArrayList<Long>();
  private final ArrayList<Content> noStaleTimeCache_ = new ArrayList<Content>();
  private final ArrayList<StaleTimeContent> staleTimeCache_ =
    new ArrayList<StaleTimeContent>();
  private final Name.Component emptyComponent_ = new Name.Component();
  private final ArrayList<PendingInterest> pendingInterestTable_ =
    new ArrayList<PendingInterest>();
  private OnInterestCallback storePendingInterestCallback_;
  private static final Logger logger_ = Logger.getLogger(MemoryContentCache.class.getName());
}
