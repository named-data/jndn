/**
 * Copyright (C) 2015-2016 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From ndn-cxx link.hpp https://github.com/named-data/ndn-cxx/blob/master/src/link.hpp
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

package net.named_data.jndn;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import net.named_data.jndn.encoding.EncodingException;
import net.named_data.jndn.encoding.WireFormat;
import net.named_data.jndn.util.Blob;

/**
 * A DelegationSet holds a list of DelegationSet.Delegation entries which is
 * used as the content of a Link instance. If you add elements with add(), then
 * the list is a set sorted by preference number then by name. But wireDecode
 * will add the elements from the wire encoding, preserving the given order and
 * possible duplicates (in which case a DelegationSet really holds a "list" and
 * not necessarily a "set").
 */
public class DelegationSet {
  /**
   * Create a DelegationSet with an empty list of delegations.
   */
  public DelegationSet()
  {
  }

  /**
   * Create a DelegationSet, copying values from the other DelegationSet.
   * @param delegationSet The DelegationSet to copy values from.
   */
  public DelegationSet(DelegationSet delegationSet)
  {
    delegations_.addAll(delegationSet.delegations_);
  }

  /**
   * A DelegationSet.Delegation holds a preference number and delegation name.
   */
  public static class Delegation {
    /**
     * Create a new DelegationSet.Delegation with the given values.
     * @param preference The preference number.
     * @param name The delegation name. This makes a copy of the name.
     */
    public Delegation(int preference, Name name)
    {
      preference_ = preference;
      name_ = new Name(name);
    }

    /**
     * Get the preference number.
     * @return The preference number.
     */
    public final int
    getPreference()
    {
      return preference_;
    }

    /**
     * Get the delegation name.
     * @return The delegation name. NOTE: You must not change the name object -
     * if you need to change it then make a copy.
     */
    public final Name
    getName()
    {
      return name_;
    }

    /**
     * Compare this Delegation with other according to the ordering, based first
     * on the preference number, then on the delegation name.
     * @param other The other Delegation to compare with.
     * @return 0 If they compare equal, -1 if this Delegation comes before other
     * in the ordering, or 1 if this Delegation comes after.
     */
    public final int
    compare(Delegation other)
    {
      if (preference_ < other.preference_)
        return -1;
      if (preference_ > other.preference_)
        return 1;

      return name_.compare(other.name_);
    }

    private final int preference_;
    private final Name name_;
  }

  /**
   * Add a new DelegationSet.Delegation to the list of delegations, sorted by
   * preference number then by name. If there is already a delegation with the
   * same name, update its preference, and remove any extra delegations with the
   * same name.
   * @param preference The preference number.
   * @param name The delegation name. This makes a copy of the name.
   */
  public final void
  add(int preference, Name name)
  {
    remove(name);

    Delegation newDelegation = new Delegation(preference, name);
    // Find the index of the first entry where it is not less than newDelegation.
    int i = 0;
    while (i < delegations_.size()) {
      if (delegations_.get(i).compare(newDelegation) >= 0)
        break;

      ++i;
    }

    delegations_.add(i, newDelegation);
  }

  /**
   * Add a new DelegationSet.Delegation to the end of the list of delegations,
   * without sorting or updating any existing entries. This is useful for adding
   * preferences from a wire encoding, preserving the supplied ordering and
   * possible duplicates.
   * @param preference The preference number.
   * @param name The delegation name. This makes a copy of the name.
   */
  public final void
  addUnsorted(int preference, Name name)
  {
    delegations_.add(new Delegation(preference, name));
  }

  /**
   * Remove every DelegationSet.Delegation with the given name.
   * @param name The name to match the name of the delegation(s) to be removed.
   * @return True if a DelegationSet.Delegation was removed, otherwise false.
   */
  public final boolean
  remove(Name name)
  {
    boolean wasRemoved = false;
    // Go backwards through the list so we can remove entries.
    for (int i = delegations_.size() - 1; i >= 0; --i) {
      if (delegations_.get(i).getName().equals(name)) {
        wasRemoved = true;
        delegations_.remove(i);
      }
    }

    return wasRemoved;
  }

  /**
   * Clear the list of delegations.
   */
  public final void
  clear() { delegations_.clear(); }

  /**
   * Get the number of delegation entries.
   * @return The number of delegation entries.
   */
  public final int
  size() { return delegations_.size(); }

  /**
   * Get the delegation at the given index, according to the ordering described
   * in add().
   * @param i The index of the component, starting from 0.
   * @return The delegation at the index.
   */
  public final Delegation
  get(int i)
  {
    return delegations_.get(i);
  }

  /**
   * Find the first delegation with the given name and return its index.
   * @param name Then name of the delegation to find.
   * @return The index of the delegation, or -1 if not found.
   */
  public final int
  find(Name name)
  {
    for (int i = 0; i < delegations_.size(); ++i) {
      if (delegations_.get(i).getName().equals(name))
        return i;
    }

    return -1;
  }

  /**
   * Encode this DelegationSet for a particular wire format.
   * @param wireFormat A WireFormat object used to encode this DelegationSet.
   * @return The encoded buffer.
   */
  public final Blob
  wireEncode(WireFormat wireFormat)
  {
    return wireFormat.encodeDelegationSet(this);
  }

  /**
   * Encode this DelegationSet for the default wire format
   * WireFormat.getDefaultWireFormat().
   * @return The encoded buffer.
   */
  public final Blob
  wireEncode()
  {
    return wireEncode(WireFormat.getDefaultWireFormat());
  }

  /**
   * Decode the input using a particular wire format and update this
   * DelegationSet, using addUnsorted() to preserve the given order and
   * possible duplicates.
   * @param input The input buffer to decode.  This reads from position() to
   * limit(), but does not change the position.
   * @param wireFormat A WireFormat object used to decode the input.
   * @throws EncodingException For invalid encoding.
   */
  public final void
  wireDecode(ByteBuffer input, WireFormat wireFormat) throws EncodingException
  {
    wireFormat.decodeDelegationSet(this, input, true);
  }

  /**
   * Decode the input using the default wire format
   * WireFormat.getDefaultWireFormat() and update this DelegationSet, using
   * addUnsorted() to preserve the given order and possible duplicates.
   * @param input The input buffer to decode.  This reads from position() to
   * limit(), but does not change the position.
   * @throws EncodingException For invalid encoding.
   */
  public final void
  wireDecode(ByteBuffer input) throws EncodingException
  {
    wireDecode(input, WireFormat.getDefaultWireFormat());
  }

  /**
   * Decode the input using a particular wire format and update this DelegationSet.
   * @param input The input blob to decode.
   * @param wireFormat A WireFormat object used to decode the input.
   * @throws EncodingException For invalid encoding.
   */
  public final void
  wireDecode(Blob input, WireFormat wireFormat) throws EncodingException
  {
    wireFormat.decodeDelegationSet(this, input.buf(), false);
  }

  /**
   * Decode the input using the default wire format
   * WireFormat.getDefaultWireFormat() and update this DelegationSet.
   * @param input The input blob to decode.
   * @throws EncodingException For invalid encoding.
   */
  public final void
  wireDecode(Blob input) throws EncodingException
  {
    wireDecode(input.buf());
  }

  private final ArrayList<Delegation> delegations_ = new ArrayList<Delegation>();
}
