/**
 * Copyright (C) 2019 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From the PSync library https://github.com/named-data/PSync/blob/master/PSync/producer-base.cpp
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

package net.named_data.jndn.sync;

import java.util.HashMap;
import java.util.logging.Level;
import java.util.logging.Logger;
import net.named_data.jndn.Name;
import net.named_data.jndn.sync.detail.InvertibleBloomLookupTable;
import net.named_data.jndn.util.Blob;
import net.named_data.jndn.util.Common;

/**
 * PSyncProducerBase is a base class for PsyncPartialProducer and FullPSync2017.
 */
public class PSyncProducerBase {
  /**
   * Create a PSyncProducerBase.
   * @param expectedNEntries The expected number of entries in the IBLT.
   * @param syncPrefix The prefix Name of the sync group, which is copied.
   * @param syncReplyFreshnessPeriod The freshness period of the sync
   * Data packet, in milliseconds.
   */
  protected PSyncProducerBase
    (int expectedNEntries, Name syncPrefix, double syncReplyFreshnessPeriod)
  {
    iblt_ = new InvertibleBloomLookupTable(expectedNEntries);
    expectedNEntries_ = expectedNEntries;
    threshold_ = expectedNEntries / 2;
    syncPrefix_ = new Name(syncPrefix);
    syncReplyFreshnessPeriod_ = syncReplyFreshnessPeriod;
  }

  /**
   * Insert the URI of the name into the iblt_, and update nameToHash_ and
   * hashToName_.
   * @param name The Name to insert.
   */
  protected final void
  insertIntoIblt(Name name)
  {
    String uri = name.toUri();
    long newHash = Common.murmurHash3
      (InvertibleBloomLookupTable.N_HASHCHECK, new Blob(uri).getImmutableArray());
    nameToHash_.put(name, newHash);
    hashToName_.put(newHash, name);
    iblt_.insert(newHash);
  }

  /**
   * If the Name is in nameToHash_, then remove the hash from the iblt_,
   * nameToHash_ and hashToName_. However, if the Name is not in nameToHash_
   * then do nothing.
   * @param name The Name to remove.
   */
  protected final void
  removeFromIblt(Name name)
  {
    Object hash = nameToHash_.get(name);
    if (hash != null) {
      nameToHash_.remove(name);
      hashToName_.remove(hash);
      iblt_.erase((long)hash);
    }
  }

  /**
   * This is called when registerPrefix fails to log an error message.
   */
  public static void
  onRegisterFailed(Name prefix)
  {
    logger_.log(Level.SEVERE, "PSyncProduerBase: Failed to register prefix: {0}",
      prefix);
  }

  protected final InvertibleBloomLookupTable iblt_;
  protected final int expectedNEntries_;
  // threshold_ is used to check if an IBLT difference is greater than the
  // threshold, and whether we need to update the other IBLT.
  protected final int threshold_;

  // nameToHash_ and hashToName_ are just for looking up the hash more quickly
  // (instead of calculating it again).
  // The key is the Name. The value is the hash.
  protected final HashMap<Name, Object> nameToHash_ = new HashMap<Name, Object>();
  // The key is the hash. The value is the Name.
  protected final HashMap<Object, Name> hashToName_ = new HashMap<Object, Name>();

  protected final Name syncPrefix_;
  protected final double syncReplyFreshnessPeriod_;
  private static final Logger logger_ = Logger.getLogger(PSyncProducerBase.class.getName());
}
