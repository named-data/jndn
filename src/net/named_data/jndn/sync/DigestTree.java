/**
 * Copyright (C) 2014-2018 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * Derived from ChronoChat-js by Qiuhan Ding and Wentao Shang.
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

import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.logging.Level;
import java.util.logging.Logger;
import net.named_data.jndn.util.Common;

public class DigestTree {
  public DigestTree()
  {
    root_ = "00";
  }

  public static class Node {
    /**
     * Create a new DigestTree.Node with the given fields and compute the digest.
     * @param dataPrefix The data prefix. This is encoded as UTF-8 to digest.
     * @param sessionNo The session number.
     * @param sequenceNo The sequence number.
     */
    public Node(String dataPrefix, long sessionNo, long sequenceNo)
    {
      dataPrefix_ = dataPrefix;
      sessionNo_ = sessionNo;
      sequenceNo_ = sequenceNo;
      recomputeDigest();
    }

    public final String
    getDataPrefix() { return dataPrefix_; }

    public final long
    getSessionNo() { return sessionNo_; }

    public final long
    getSequenceNo() { return sequenceNo_; }

    /**
     * Get the digest.
     * @return The digest as a hex string.
     */
    public final String
    getDigest() { return digest_; }


    /**
     * Set the sequence number and recompute the digest.
     * @param sequenceNo The new sequence number.
     */
    public final void
    setSequenceNo(long sequenceNo)
    {
      sequenceNo_ = sequenceNo;
      recomputeDigest();
    }

    /**
     * Compare this Node with node2 first comparing dataPrefix_ then sessionNo_.
     * @param node2 The other Node to compare.
     * @return True if this node is less than node2.
     */
    public final boolean
    lessThan(Node node2)
    {
      // We compare the Unicode strings which is OK because it has the same sort
      // order as the UTF-8 encoding: http://en.wikipedia.org/wiki/UTF-8#Advantages
      // "Sorting a set of UTF-8 encoded strings as strings of unsigned bytes
      // yields the same order as sorting the corresponding Unicode strings
      // lexicographically by codepoint."
      int prefixComparison = dataPrefix_.compareTo(node2.dataPrefix_);
      if (prefixComparison != 0)
        return prefixComparison < 0;

      return sessionNo_ < node2.sessionNo_;
    }

    /**
     * Digest the fields and set digest_ to the hex digest.
     */
    private void
    recomputeDigest()
    {
      MessageDigest sha256;
      try {
        sha256 = MessageDigest.getInstance("SHA-256");
      }
      catch (NoSuchAlgorithmException exception) {
        // Don't expect this to happen.
        throw new Error
          ("MessageDigest: SHA-256 is not supported: " + exception.getMessage());
      }

      byte[] number = new byte[4];
      // Debug: sync-state-proto.proto defines seq and session as uint64, but
      //   the original ChronoChat-js only digests 32 bits.
      int32ToLittleEndian((int)sessionNo_, number);
      sha256.update(number);
      int32ToLittleEndian((int)sequenceNo_, number);
      sha256.update(number);
      byte[] sequenceDigest = sha256.digest();

      sha256.reset();
      try {
        sha256.update(dataPrefix_.getBytes("UTF-8"));
      } catch (UnsupportedEncodingException ex) {
        // We don't expect this to happen.
        throw new Error("UTF-8 encoder not supported: " + ex.getMessage());
      }
      byte[] nameDigest = sha256.digest();

      sha256.reset();
      sha256.update(nameDigest);
      sha256.update(sequenceDigest);
      byte[] nodeDigest = sha256.digest();
      digest_ = Common.toHex(nodeDigest);
    }

    private static void
    int32ToLittleEndian(int value, byte[] result)
    {
      for (int i = 0; i < 4; i++) {
        result[i] = (byte)(value & 0xff);
        value >>= 8;
       }
    }

    private final String dataPrefix_;
    private final long sessionNo_;
    private long sequenceNo_;
    private String digest_;
  }

  /**
   * Update the digest tree and recompute the root digest.  If the combination
   * of dataPrefix and sessionNo already exists in the tree then update its
   * sequenceNo (only if the given sequenceNo is newer), otherwise add a new node.
   * @param dataPrefix The name prefix. This is encoded as UTF-8 to digest.
   * @param sessionNo The session number.
   * @param sequenceNo The new sequence number.
   * @return True if the digest tree is updated, false if not (because the
   * given sequenceNo is not newer than the existing sequence number).
   */
  public final boolean
  update(String dataPrefix, long sessionNo, long sequenceNo)
  {
    int nodeIndex = find(dataPrefix, sessionNo);
    Logger.getLogger(DigestTree.class.getName()).log(Level.FINE,
      "{0}, {1}",  new Object[]{dataPrefix, sessionNo});
    Logger.getLogger(DigestTree.class.getName()).log(Level.FINE,
      "DigestTree.update session {0}, nodeIndex {1}", new Object[]{sessionNo, nodeIndex});
    if (nodeIndex >= 0) {
      // Only update to a  newer status.
      if (digestNode_.get(nodeIndex).getSequenceNo() < sequenceNo)
        digestNode_.get(nodeIndex).setSequenceNo(sequenceNo);
      else
        return false;
    }
    else {
      Logger.getLogger(DigestTree.class.getName()).log(Level.FINE,
        "new comer {0}, session {1}, sequence {2}", new Object[]{dataPrefix, sessionNo, sequenceNo});
      // Insert into digestnode_ sorted.
      Node temp = new Node(dataPrefix, sessionNo, sequenceNo);
      // Find the index of the first node where it is not less than temp.
      int i = 0;
      while (i < digestNode_.size()) {
        if (!digestNode_.get(i).lessThan(temp))
          break;
        ++i;
      }
      digestNode_.add(i, temp);
    }

    recomputeRoot();
    return true;
  }

  public final int
  find(String dataPrefix, long sessionNo)
  {
    for (int i = 0; i < digestNode_.size(); ++i) {
      if (digestNode_.get(i).getDataPrefix().equals(dataPrefix) &&
          digestNode_.get(i).getSessionNo() == sessionNo)
        return i;
    }

    return -1;
  }

  public final int
  size() { return digestNode_.size(); }

  public final Node
  get(int i) { return digestNode_.get(i); }

  /**
   * Get the root digest.
   * @return The root digest as a hex string.
   */
  public final String
  getRoot() { return root_; }

  /**
   * Convert the hex character to an integer from 0 to 15, or -1 if not a hex character.
   */
  private static int
  fromHexChar(char c)
  {
    if (c >= '0' && c <= '9')
      return (int)c - (int)'0';
    else if (c >= 'A' && c <= 'F')
      return (int)c - (int)'A' + 10;
    else if (c >= 'a' && c <= 'f')
      return (int)c - (int)'a' + 10;
    else
      return -1;
  }

  /**
   * Convert the hex string to bytes and call messageDigest.update.
   * @param messageDigest The MessageDigest to update.
   * @param hex The hex string.
   */
  private static void
  updateHex(MessageDigest messageDigest, String hex)
  {
    byte[] data = new byte[hex.length() / 2];
    for (int i = 0; i < data.length; ++i)
      data[i] = (byte)((16 * fromHexChar(hex.charAt(2 * i)) +
                        fromHexChar(hex.charAt(2 * i + 1))) & 0xff);

    messageDigest.update(data);
  }

  /**
   * Set root_ to the digest of all digests in digestnode_. This sets root_
   * to the hex value of the digest.
   */
  private void
  recomputeRoot()
  {
    MessageDigest sha256;
    try {
      sha256 = MessageDigest.getInstance("SHA-256");
    }
    catch (NoSuchAlgorithmException exception) {
      // Don't expect this to happen.
      throw new Error
        ("MessageDigest: SHA-256 is not supported: " + exception.getMessage());
    }

    for (int i = 0; i < digestNode_.size(); ++i)
      updateHex(sha256, digestNode_.get(i).getDigest());
    byte[] digestRoot = sha256.digest();
    root_ = Common.toHex(digestRoot);
    Logger.getLogger(DigestTree.class.getName()).log(Level.FINE,
      "update root to: {0}", root_);
  }

  private final ArrayList<DigestTree.Node> digestNode_ = new ArrayList<DigestTree.Node>();
  private String root_;
  // This is to force an import of net.named_data.jndn.util.
  private static Common dummyCommon_ = new Common();
}
