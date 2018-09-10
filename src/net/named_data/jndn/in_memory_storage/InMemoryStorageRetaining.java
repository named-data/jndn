/**
 * Copyright (C) 2018 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From ndn-cxx security https://github.com/named-data/ndn-cxx/blob/master/src/ims/in-memory-storage-persistent.cpp
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

package net.named_data.jndn.in_memory_storage;

import java.util.HashMap;
import java.util.Map;
import net.named_data.jndn.Data;
import net.named_data.jndn.Interest;
import net.named_data.jndn.Name;
import net.named_data.jndn.encoding.EncodingException;

/**
 * InMemoryStorageRetaining provides an application cache with in-memory 
 * storage, of which no eviction policy will be employed. Entries will only be
 * evicted by explicit application control.
 * Note: In ndn-cxx, this class is called InMemoryStoragePersistent, but
 * "persistent" misleadingly sounds like persistent on-disk storage.
 */
public class InMemoryStorageRetaining {
  /**
   * Insert a Data packet. If a Data packet with the same name, including the
   * implicit digest, already exists, replace it. 
   * @param data The packet to insert, which is copied.
   * @throws EncodingException for error encoding the Data packet to get the
   * implicit digest.
   */
  public void
  insert(Data data)
    throws EncodingException
  {
    cache_.put(data.getFullName(), new Data(data));
  }

  /** 
   * Find the best match Data for an Interest.
   * @param interest The Interest with the Name of the Data packet to find.
   * @return The best match if any, otherwise null. You should not modify the
   * returned object. If you need to modify it then you must make a copy.
   */
  public Data
  find(Interest interest)
  {
    for (Object entry : cache_.entrySet()) {
      // Debug: Check selectors, especially CanBePrefix.
      if (interest.getName().isPrefixOf((Name)((Map.Entry)entry).getKey()))
        return (Data)((Map.Entry)entry).getValue();
    }

    return null;
  }

  /**
   * Get the number of packets stored in the in-memory storage.
   * @return The number of packets.
   */
  public int
  size() { return cache_.size(); }

  /**
   * Get the the storage cache, which should only be used for testing.
   * @return The storage cache.
   */
  public final HashMap
  getCache_() { return cache_; }

  // Use HashMap without generics so it works with older Java compilers.
  private final HashMap cache_ = 
    new HashMap(); /**< The map key is the Data packet Name. The value is a Data. */
}
