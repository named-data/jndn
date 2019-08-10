/**
 * Copyright (C) 2019 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From the PSync library https://github.com/named-data/PSync/blob/master/PSync/segment-publisher.cpp
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

package net.named_data.jndn.sync.detail;

import java.io.IOException;
import java.nio.ByteBuffer;
import net.named_data.jndn.Data;
import net.named_data.jndn.Face;
import net.named_data.jndn.Interest;
import net.named_data.jndn.Name;
import net.named_data.jndn.encoding.EncodingException;
import net.named_data.jndn.in_memory_storage.InMemoryStorageRetaining;
import net.named_data.jndn.security.KeyChain;
import net.named_data.jndn.security.SigningInfo;
import net.named_data.jndn.security.pib.PibImpl;
import net.named_data.jndn.security.tpm.TpmBackEnd;
import net.named_data.jndn.util.Blob;
import net.named_data.jndn.util.Common;

/**
 * The PSyncSegmentPublisher class has methods to publish segmented data used by
 * PSync.
 */
public class PSyncSegmentPublisher {
  /**
   * Create a PSyncSegmentPublisher.
   * @param face The application's Face.
   * @param keyChain The KeyChain for signing Data packets.
   * @param inMemoryStorageLimit The limit for the in-memory storage.
   */
  public PSyncSegmentPublisher
    (Face face, KeyChain keyChain, int inMemoryStorageLimit)
  {
    face_ = face;
    keyChain_ = keyChain;
    // Until InMemoryStorageFifo implements an eviction policy, use InMemoryStorageRetaining.
    storage_ = new InMemoryStorageRetaining();
  }

  /**
   * Create a PSyncSegmentPublisher where inMemoryStorageLimit is
   * MAX_SEGMENTS_STORED.
   * @param face The application's Face.
   * @param keyChain The KeyChain for signing Data packets.
   */
  public PSyncSegmentPublisher(Face face, KeyChain keyChain)
  {
    face_ = face;
    keyChain_ = keyChain;
    // Until InMemoryStorageFifo implements an eviction policy, use InMemoryStorageRetaining.
    storage_ = new InMemoryStorageRetaining();
  }

  /**
   * Put all the segments in the memory store.
   * @param interestName If the Interest name ends in a segment, immediately
   * send the Data packet for the segment to the Face.
   * @param dataName The Data name, which has components after the Interest name.
   * @param content The content of the data to be segmented.
   * @param freshnessPeriod The freshness period of the segments, in milliseconds.
   * @param signingInfo The SigningInfo for signing segment Data packets.
   */
  public final void
  publish
    (Name interestName, Name dataName, Blob content, double freshnessPeriod,
     SigningInfo signingInfo)
    throws EncodingException, TpmBackEnd.Error, PibImpl.Error, KeyChain.Error,
      IOException
  {
    long interestSegment = 0;
    if (interestName.get(-1).isSegment())
      interestSegment = interestName.get(-1).toSegment();

    ByteBuffer rawBuffer = content.buf().slice();
    int iSegmentBegin = 0;
    int iEnd = content.size();

    int maxPacketSize = Common.MAX_NDN_PACKET_SIZE / 2;

    long totalSegments = content.size() / maxPacketSize;
    Name.Component finalBlockId = Name.Component.fromSegment(totalSegments);

    Name segmentPrefix = new Name(dataName);
    segmentPrefix.appendVersion((long)Common.getNowMilliseconds());

    long segmentNo = 0;
    do {
      int iSegmentEnd = iSegmentBegin + maxPacketSize;
      if (iSegmentEnd > iEnd)
        iSegmentEnd = iEnd;

      final Name segmentName = new Name(segmentPrefix);
      segmentName.appendSegment(segmentNo);

      Data data = new Data(segmentName);
      // Set the position in the rawBuffer and tell Blob to make a copy.
      rawBuffer.limit(iSegmentEnd);
      rawBuffer.position(iSegmentBegin);
      data.setContent(new Blob(rawBuffer, true));

      data.getMetaInfo().setFreshnessPeriod(freshnessPeriod);
      data.getMetaInfo().setFinalBlockId(finalBlockId);

      iSegmentBegin = iSegmentEnd;

      keyChain_.sign(data, signingInfo);

      // Only send the segment to the Face if it has a pending interest.
      // Otherwise, the segment is unsolicited.
      if (interestSegment == segmentNo)
        face_.putData(data);

/* Until InMemoryStorageFifo implements an eviction policy, use InMemoryStorageRetaining.
      storage_.insert(*data, freshnessPeriod);
*/
      storage_.insert(data);

      face_.callLater
        (freshnessPeriod,
         new Runnable() {
           public void run() {
             storage_.remove(segmentName);
           }
         });

      ++segmentNo;
    } while (iSegmentBegin < iEnd);
  }

  /**
   * Put all the segments in the memory store, where signingInfo is the default
   * SigningInfo().
   * @param interestName If the Interest name ends in a segment, immediately
   * send the Data packet for the segment to the Face.
   * @param dataName The Data name, which has components after the Interest name.
   * @param content The content of the data to be segmented.
   * @param freshnessPeriod The freshness period of the segments, in milliseconds.
   */
  public final void
  publish
    (Name interestName, Name dataName, Blob content, double freshnessPeriod)
    throws EncodingException, TpmBackEnd.Error, PibImpl.Error, KeyChain.Error,
      IOException
  {
    publish(interestName, dataName, content, freshnessPeriod, new SigningInfo());
  }

  /**
   * Try to reply to the Interest name from the memory store.
   * @param interestName The Interest name for looking up in the memory store.
   * @return True if sent the segment Data packet to the Face, or false if we
   * cannot find the segment, in which case the caller is expected to publish
   * the segment.
   */
  public final boolean
  replyFromStore(Name interestName) throws IOException
  {
    Data data = storage_.find(new Interest(interestName));

    if (data != null) {
      face_.putData(data);
      return true;
    }

    return false;
  }

  public static final int MAX_SEGMENTS_STORED = 100;

  private final Face face_;
  private final KeyChain keyChain_;
/* Until InMemoryStorageFifo implements an eviction policy, use InMemoryStorageRetaining.
  private final InMemoryStorageFifo storage_ = new InMemoryStorageFifo();
*/
  private final InMemoryStorageRetaining storage_;
}
