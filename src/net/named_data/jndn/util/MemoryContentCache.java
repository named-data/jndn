/**
 * Copyright (C) 2014-2015 Regents of the University of California.
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
import net.named_data.jndn.Name;
import net.named_data.jndn.OnInterest;
import net.named_data.jndn.OnRegisterFailed;
import net.named_data.jndn.encoding.WireFormat;
import net.named_data.jndn.security.SecurityException;
import net.named_data.jndn.transport.Transport;

/**
 * A MemoryContentCache holds a set of Data packets and answers an Interest to
 * return the correct Data packet. The cached is periodically cleaned up to
 * remove each stale Data packet based on its FreshnessPeriod (if it has one).
 * @note This class is an experimental feature.  See the API docs for more detail at
 * http://named-data.net/doc/ndn-ccl-api/memory-content-cache.html .
 */
public class MemoryContentCache implements OnInterest {
  /**
   * Create a new MemoryContentCache to use the given Face.
   * @param face The Face to use to call registerPrefix and which will call
   * the OnInterest callback.
   * @param cleanupIntervalMilliseconds The interval in milliseconds
   * between each check to clean up stale content in the cache. If this is a
   * large number, then effectively the stale content will not be removed from
   * the cache.
   */
  public MemoryContentCache(Face face, double cleanupIntervalMilliseconds)
  {
    face_ = face;
    cleanupIntervalMilliseconds_ = cleanupIntervalMilliseconds;
    nextCleanupTime_ = Common.getNowMilliseconds() + cleanupIntervalMilliseconds_;
  }

  /**
   * Create a new MemoryContentCache to use the given Face, with a default
   * cleanupIntervalMilliseconds of 1000.0 milliseconds.
   * @param face The Face to use to call registerPrefix and which will call
   * the OnInterest callback.
   */
  public MemoryContentCache(Face face)
  {
    face_ = face;
    cleanupIntervalMilliseconds_ = 1000.0;
    nextCleanupTime_ = Common.getNowMilliseconds() + cleanupIntervalMilliseconds_;
  }

  /**
   * Call registerPrefix on the Face given to the constructor so that this
   * MemoryContentCache will answer interests whose name has the prefix.
   * @param prefix The Name for the prefix to register. This copies the Name.
   * @param onRegisterFailed If register prefix fails for any reason, this
   * calls onRegisterFailed.onRegisterFailed(prefix).
   * @param onDataNotFound If a data packet is not found in the cache, this
   * calls onDataNotFound.onInterest(prefix, interest, transport, interestFilterId)
   * to forward the OnInterest message. If onDataNotFound is null, this does not
   * use it.
   * @param flags See Face.registerPrefix.
   * @param wireFormat See Face.registerPrefix.
   * @throws IOException For I/O error in sending the registration request.
   * @throws SecurityException If signing a command interest for NFD and cannot
   * find the private key for the certificateName.
   */
  public final void
  registerPrefix
    (Name prefix, OnRegisterFailed onRegisterFailed, OnInterest onDataNotFound,
     ForwardingFlags flags, WireFormat wireFormat) throws IOException, SecurityException
  {
    if (onDataNotFound != null)
      onDataNotFoundForPrefix_.put(prefix.toUri(), onDataNotFound);
    long registeredPrefixId = face_.registerPrefix
      (prefix, this, onRegisterFailed, flags, wireFormat);
    registeredPrefixIdList_.add(registeredPrefixId);
  }

  /**
   * Call Face.removeRegisteredPrefix for all the prefixes given to the
   * registerPrefix method on this MemoryContentCache object so that it will not
   * receive interests any more. You can call this if you want to "shut down"
   * this MemoryContentCache while your application is still running.
   */
  public final void
  unregisterAll()
  {
    for (int i = 0; i < registeredPrefixIdList_.size(); ++i)
      face_.removeRegisteredPrefix((long)(Long)registeredPrefixIdList_.get(i));
    registeredPrefixIdList_.clear();

    // Also clear each onDataNotFoundForPrefix given to registerPrefix.
    onDataNotFoundForPrefix_.clear();
  }

  /**
   * Call registerPrefix on the Face given to the constructor so that this
   * MemoryContentCache will answer interests whose name has the prefix.
   * This uses the default WireFormat.getDefaultWireFormat().
   * @param prefix The Name for the prefix to register. This copies the Name.
   * @param onRegisterFailed If register prefix fails for any reason, this
   * calls onRegisterFailed.onRegisterFailed(prefix).
   * @param onDataNotFound If a data packet is not found in the cache, this
   * calls onDataNotFound.onInterest(prefix, interest, transport, interestFilterId)
   * to forward the OnInterest message. If onDataNotFound is null, this does not
   * use it.
   * @param flags See Face.registerPrefix.
   * @throws IOException For I/O error in sending the registration request.
   * @throws SecurityException If signing a command interest for NFD and cannot
   * find the private key for the certificateName.
   */
  public final void
  registerPrefix
    (Name prefix, OnRegisterFailed onRegisterFailed, OnInterest onDataNotFound,
     ForwardingFlags flags) throws IOException, SecurityException
  {
    registerPrefix
      (prefix, onRegisterFailed, onDataNotFound, flags,
       WireFormat.getDefaultWireFormat());
  }

  /**
   * Call registerPrefix on the Face given to the constructor so that this
   * MemoryContentCache will answer interests whose name has the prefix.
   * This uses the default WireFormat.getDefaultWireFormat().
   * Use default ForwardingFlags.
   * @param prefix The Name for the prefix to register. This copies the Name.
   * @param onRegisterFailed If register prefix fails for any reason, this
   * calls onRegisterFailed.onRegisterFailed(prefix).
   * @param onDataNotFound If a data packet is not found in the cache, this
   * calls onDataNotFound.onInterest(prefix, interest, transport, interestFilterId)
   * to forward the OnInterest message. If onDataNotFound is null, this does not
   * use it.
   * @throws IOException For I/O error in sending the registration request.
   * @throws SecurityException If signing a command interest for NFD and cannot
   * find the private key for the certificateName.
   */
  public final void
  registerPrefix
    (Name prefix, OnRegisterFailed onRegisterFailed, OnInterest onDataNotFound)
    throws IOException, SecurityException
  {
    registerPrefix
      (prefix, onRegisterFailed, onDataNotFound, new ForwardingFlags(),
       WireFormat.getDefaultWireFormat());
  }

  /**
   * Call registerPrefix on the Face given to the constructor so that this
   * MemoryContentCache will answer interests whose name has the prefix.
   * Do not call a callback if a data packet is not found in the cache.
   * This uses the default WireFormat.getDefaultWireFormat().
   * Use default ForwardingFlags.
   * @param prefix The Name for the prefix to register. This copies the Name.
   * @param onRegisterFailed If register prefix fails for any reason, this
   * calls onRegisterFailed.onRegisterFailed(prefix).
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
   * Add the Data packet to the cache so that it is available to use to
   * answer interests. If data.getFreshnessPeriod() is not negative, set the
   * staleness time to now plus data.getFreshnessPeriod(), which is checked
   * during cleanup to remove stale content. This also checks if
   * cleanupIntervalMilliseconds milliseconds have passed and removes stale
   * content from the cache.
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
        if (((StaleTimeContent)staleTimeCache_.get(i)).getStaleTimeMilliseconds() <=
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
  }

  public final void
  onInterest(Name prefix, Interest interest, Transport transport,
    long interestFilterId)
  {
    doCleanup();

    Name.Component selectedComponent = null;
    Blob selectedEncoding = null;
    // We need to iterate over both arrays.
    int totalSize = staleTimeCache_.size() + noStaleTimeCache_.size();
    for (int i = 0; i < totalSize; ++i) {
      Content content;
      if (i < staleTimeCache_.size())
        content = (Content)staleTimeCache_.get(i);
      else
        // We have iterated over the first array. Get from the second.
        content = (Content)noStaleTimeCache_.get(i - staleTimeCache_.size());

      if (interest.matchesName(content.getName())) {
        if (interest.getChildSelector() < 0) {
          // No child selector, so send the first match that we have found.
          try {
            transport.send(content.getDataEncoding().buf());
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
        transport.send(selectedEncoding.buf());
      } catch (IOException ex) {
        Logger.getLogger(MemoryContentCache.class.getName()).log(Level.SEVERE, null, ex);
      }
    }
    else {
      // Call the onDataNotFound callback (if defined).
      Object onDataNotFound = onDataNotFoundForPrefix_.get(prefix.toUri());
      if (onDataNotFound != null)
        ((OnInterest)onDataNotFound).onInterest
          (prefix, interest, transport, interestFilterId);
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
      while (staleTimeCache_.size() > 0 &&
             ((StaleTimeContent)staleTimeCache_.get(0)).isStale(now))
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
  private final ArrayList registeredPrefixIdList_ = new ArrayList(); // of long
  private final ArrayList noStaleTimeCache_ = new ArrayList(); // of Content
  private final ArrayList staleTimeCache_ = new ArrayList(); // of StaleTimeContent
  private final Name.Component emptyComponent_ = new Name.Component();
}
