/**
 * Copyright (C) 2019 Regents of the University of California.
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

package net.named_data.jndn.sync.detail;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.zip.Deflater;
import java.util.zip.DeflaterOutputStream;
import java.util.zip.InflaterInputStream;
import net.named_data.jndn.util.Blob;
import net.named_data.jndn.util.Common;

/**
 * InvertibleBloomLookupTable implements an Invertible Bloom Lookup Table (IBLT)
 * (Invertible Bloom Filter). This is used by FullPSync2017.
 */
public class InvertibleBloomLookupTable {
  /**
   * Create an InvertibleBloomLookupTable.
   * @param expectedNEntries the expected number of entries in the IBLT.
   */
  public InvertibleBloomLookupTable(int expectedNEntries)
  {
    // 1.5 times the expected number of entries gives a very low probability of
    // a decoding failure.
    int nEntries = expectedNEntries + expectedNEntries / 2;
    // Make nEntries exactly divisible by N_HASH.
    int remainder = nEntries % N_HASH;
    if (remainder != 0)
      nEntries += (N_HASH - remainder);

    hashTable_ = new ArrayList<HashTableEntry>(nEntries);
    for (int i = 0; i < nEntries; ++i)
      hashTable_.add(new HashTableEntry());
  }

  /**
   * Create an InvertibleBloomLookupTable of the given iblt.
   * @param iblt The InvertibleBloomLookupTable to copy.
   */
  public InvertibleBloomLookupTable(InvertibleBloomLookupTable iblt)
  {
    // Make a deep copy the hashTable_ array.
    hashTable_ = new ArrayList<HashTableEntry>(iblt.hashTable_.size());
    for (int i = 0; i < iblt.hashTable_.size(); ++i)
      hashTable_.add(new HashTableEntry(iblt.hashTable_.get(i)));
  }

  /**
   * Populate the hash table using the encoded array representation of the IBLT.
   * @param encoding The encoded representation of the IBLT.
   * @throws AssertionError if the size of the decoded values is not compatible
   * with this IBLT.
   */
  public final void
  initialize(Blob encoding) throws IOException
  {
    long[] values = decode(encoding);

    if (3 * hashTable_.size() != values.length)
      throw new AssertionError("The received Invertible Bloom Filter cannot be decoded");

    for (int i = 0; i < hashTable_.size(); i++) {
      HashTableEntry entry = hashTable_.get(i);
      if (values[i * 3] != 0) {
        entry.count_ = (int)(values[i * 3]);
        entry.keySum_ = values[(i * 3) + 1];
        entry.keyCheck_ = values[(i * 3) + 2];
      }
    }
  }

  public final void
  insert(long key) { update(INSERT, key); }

  public final void
  erase(long key) { update(ERASE, key); }

  /**
   * List all the entries in the IBLT.
   * This is called on a difference of two IBLTs: ownIBLT - receivedIBLT.
   * Entries listed in positive are in ownIBLT but not in receivedIBLT.
   * Entries listed in negative are in receivedIBLT but not in ownIBLT.
   * @param positive Add positive entries to this set. This first clears the set.
   * @param negative Add negative entries to this set. This first clears the set.
   * @return True if decoding is completed successfully.
   */
  public final boolean
  listEntries(HashSet<Long> positive, HashSet<Long> negative)
  {
    positive.clear();
    negative.clear();

    // Make a deep copy.
    InvertibleBloomLookupTable peeled = new InvertibleBloomLookupTable(this);

    int nErased = 0;
    do {
      nErased = 0;
      for (HashTableEntry entry : peeled.hashTable_) {
        if (entry.isPure()) {
          if (entry.count_ == 1)
            positive.add(entry.keySum_);
          else
            negative.add(entry.keySum_);

          peeled.update(-entry.count_, entry.keySum_);
          ++nErased;
        }
      }
    } while (nErased > 0);

    // If any buckets for one of the hash functions is not empty, then we didn't
    // peel them all.
    for (HashTableEntry entry : peeled.hashTable_) {
      if (!entry.isEmpty())
        return false;
    }

    return true;
  }

  /**
   * Get a new IBLT which is the difference of the other IBLT from this IBLT.
   * @param other The other IBLT.
   * @return A new IBLT of this - other.
   */
  public final InvertibleBloomLookupTable
  difference(InvertibleBloomLookupTable other)
  {
    if (hashTable_.size() != other.hashTable_.size())
      throw new Error("IBLT difference: Both tables must be the same size");

    InvertibleBloomLookupTable result = new InvertibleBloomLookupTable(this);
    for (int i = 0; i < hashTable_.size(); ++i) {
      HashTableEntry e1 = result.hashTable_.get(i);
      HashTableEntry e2 = other.hashTable_.get(i);
      e1.count_ -= e2.count_;
      e1.keySum_ ^= e2.keySum_;
      e1.keyCheck_ ^= e2.keyCheck_;
    }

    return result;
  }

  /**
   * Encode this IBLT to a Blob. This encodes this hash table from a uint32_t
   * array to a uint8_t array. We create a uin8_t array 12 times the size of
   * the uint32_t array. We put the first count in the first 4 cells, keySum in
   * the next 4, and keyCheck in the next 4. We repeat for all the other cells
   * of the hash table. Then we append this uint8_t array to the name.
   * @return The encoded Blob.
   */
  public final Blob
  encode() throws IOException
  {
    int nEntries = hashTable_.size();
    int unitSize = (32 * 3) / 8; // hard coding
    int tableSize = unitSize * nEntries;

    byte[] table = new byte[tableSize];

    for (int i = 0; i < nEntries; i++) {
      HashTableEntry entry = hashTable_.get(i);
      
      // table[i*12],   table[i*12+1], table[i*12+2], table[i*12+3] --> hashTable[i].count_

      table[(i * unitSize)]     = (byte)(0xFF & entry.count_);
      table[(i * unitSize) + 1] = (byte)(0xFF & (entry.count_ >> 8));
      table[(i * unitSize) + 2] = (byte)(0xFF & (entry.count_ >> 16));
      table[(i * unitSize) + 3] = (byte)(0xFF & (entry.count_ >> 24));

      // table[i*12+4], table[i*12+5], table[i*12+6], table[i*12+7] --> hashTable[i].keySum_

      table[(i * unitSize) + 4] = (byte)(0xFF & entry.keySum_);
      table[(i * unitSize) + 5] = (byte)(0xFF & (entry.keySum_ >> 8));
      table[(i * unitSize) + 6] = (byte)(0xFF & (entry.keySum_ >> 16));
      table[(i * unitSize) + 7] = (byte)(0xFF & (entry.keySum_ >> 24));

      // table[i*12+8], table[i*12+9], table[i*12+10], table[i*12+11] --> hashTable[i].keyCheck_

      table[(i * unitSize) + 8]  = (byte)(0xFF & entry.keyCheck_);
      table[(i * unitSize) + 9]  = (byte)(0xFF & (entry.keyCheck_ >> 8));
      table[(i * unitSize) + 10] = (byte)(0xFF & (entry.keyCheck_ >> 16));
      table[(i * unitSize) + 11] = (byte)(0xFF & (entry.keyCheck_ >> 24));
    }

    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    final int compressionLevel = 9;
    DeflaterOutputStream deflaterStream = new DeflaterOutputStream
      (outputStream, new Deflater(compressionLevel));

    // Use "try/finally instead of "try-with-resources" or "using"
    // which are not supported before Java 7.
    try {
      deflaterStream.write(table);
      deflaterStream.flush();
    } finally {
      deflaterStream.close();
    }

    return new Blob(outputStream.toByteArray(), false);
  }

  /**
   * Check if this IBLT has the same number of entries as the other IBLT and
   * that they are equal.
   * @param other The other OBLT to check.
   * @return true if this IBLT is equal to the other, otherwise false.
   */
  public final boolean
  equals(InvertibleBloomLookupTable other)
  {
    ArrayList<HashTableEntry> iblt1HashTable = hashTable_;
    ArrayList<HashTableEntry> iblt2HashTable = other.hashTable_;
    if (iblt1HashTable.size() != iblt2HashTable.size())
      return false;

    for (int i = 0; i < iblt1HashTable.size(); i++) {
      if (iblt1HashTable.get(i).count_ != iblt2HashTable.get(i).count_ ||
          iblt1HashTable.get(i).keySum_ != iblt2HashTable.get(i).keySum_ ||
          iblt1HashTable.get(i).keyCheck_ != iblt2HashTable.get(i).keyCheck_)
        return false;
    }

    return true;
  }

  public static final int N_HASH = 3;
  public static final int N_HASHCHECK = 11;

  private static class HashTableEntry {
    /** 
     * The default constructor.
     */
    public HashTableEntry() {}

    /**
     * The copy constructor.
     */
    public HashTableEntry(HashTableEntry entry) {
      count_ = entry.count_;
      keySum_ = entry.keySum_;
      keyCheck_ = entry.keyCheck_;
    }

    public final boolean
    isPure()
    {
      if (count_ == 1 || count_ == -1) {
        long check = Common.murmurHash3(N_HASHCHECK, keySum_);
        return keyCheck_ == check;
      }

      return false;
    }

    public final boolean
    isEmpty() { return count_ == 0 && keySum_ == 0 && keyCheck_ == 0; }

    public int count_ = 0;
    public long keySum_ = 0;
    public long keyCheck_ = 0;
  }

  /**
   * Update the entries in hashTable_.
   * @param plusOrMinus The amount to update the count.
   * @param key The key for computing the entry.
   */
  private void
  update(int plusOrMinus, long key)
  {
    int bucketsPerHash = hashTable_.size() / N_HASH;

    for (int i = 0; i < N_HASH; i++) {
      int startEntry = i * bucketsPerHash;
      long h = Common.murmurHash3(i, key);
      HashTableEntry entry = hashTable_.get(startEntry + (int)(h % bucketsPerHash));
      entry.count_ += plusOrMinus;
      entry.keySum_ ^= key;
      entry.keyCheck_ ^= Common.murmurHash3(N_HASHCHECK, key);
    }
  }

  /**
   * Decode the IBLT from the Blob. This converts the Blob into a byte array
   * which is then decoded to a long array.
   * @param encoding The encoded IBLT.
   * @return An int array representing the hash table of the IBLT.
   */
  private static long[]
  decode(Blob encoding) throws IOException
  {
    InflaterInputStream inflaterStream = new InflaterInputStream
      (new ByteArrayInputStream(encoding.getImmutableArray()));
    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    byte[] buffer = new byte[encoding.size()];

    while (true) {
      int count = inflaterStream.read(buffer);
      if (count <= 0)
        break;

      outputStream.write(buffer, 0, count);
    }

    byte[] ibltValues = outputStream.toByteArray();

    int nEntries = ibltValues.length / 4;
    long[] values = new long[nEntries];

    for (int i = 0; i < 4 * nEntries; i += 4) {
      // Temporarily use a long for an unsigned 32-bit integer.
      long t = (((long)ibltValues[i + 3] & 0xff) << 24) +
               (((long)ibltValues[i + 2] & 0xff) << 16) +
               (((long)ibltValues[i + 1] & 0xff) << 8)  +
                ((long)ibltValues[i] & 0xff);
      values[i / 4] = t;
    }

    return values;
  }

  private final ArrayList<HashTableEntry> hashTable_;

  private static final int INSERT = 1;
  private static final int ERASE = -1;
}
