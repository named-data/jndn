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

import net.named_data.jndn.encoding.EncodingException;
import net.named_data.jndn.encoding.WireFormat;
import net.named_data.jndn.util.Blob;

/**
 * The Link class extends Data and represents a Link instance where the Data
 * content is an encoded delegation set. The format is defined in "link.pdf"
 * attached to Redmine issue http://redmine.named-data.net/issues/2587 .
 */
public class Link extends Data {
  /**
   * Create a Link with default values and where the list of delegations is
   * empty and the meta info type is LINK.
   */
  public Link()
  {
    super();

    getMetaInfo().setType(ContentType.LINK);
  }

  /**
   * Create a Link with the given name and default values and where the list of
   * delegations is empty and the meta info type is LINK.
   * @param name The name which is copied.
   */
  public Link(Name name)
  {
    super(name);

    getMetaInfo().setType(ContentType.LINK);
  }

  /**
   * Create a Link, copying values from the other Data object. If the content
   * can be decoded using the default wire encoding, then update the list
   * of delegations.
   * @param data The Data object to copy values from.
   */
  public Link(Data data)
  {
    super(data);

    if (!getContent().isNull()) {
      try {
        delegations_.wireDecode(getContent());
        getMetaInfo().setType(ContentType.LINK);
      }
      catch (EncodingException ex) {
        delegations_.clear();
      }
    }
  }

  /**
   * Override to call the base class wireDecode then populate the list of
   * delegations from the content.
   * @param input The input byte array to be decoded as an immutable Blob.
   * @param wireFormat A WireFormat object used to decode the input.
   */
  public void
  wireDecode(Blob input, WireFormat wireFormat) throws EncodingException
  {
    super.wireDecode(input, wireFormat);
    if (getMetaInfo().getType() != ContentType.LINK)
      throw new EncodingException
        ("Link.wireDecode: MetaInfo ContentType is not LINK.");

    delegations_.wireDecode(getContent());
  }

  /**
   * Add a new delegation to the list of delegations, sorted by
   * preference number then by name. Re-encode this object's content using the
   * given wireFormat.
   * @param preference The preference number.
   * @param name The delegation name. This makes a copy of the name. If there
   * is already a delegation with the same name, this updates its preference.
   * @param wireFormat A WireFormat object used to encode the DelegationSet.
   * @return This Link so that you can chain calls to update values.
   */
  public final Link
  addDelegation(int preference, Name name, WireFormat wireFormat)
  {
    delegations_.add(preference, name);
    encodeContent(wireFormat);

    return this;
  }

  /**
   * Add a new delegation to the list of delegations, sorted by
   * preference number then by name. Re-encode this object's content using the
   * default wire format.
   * @param preference The preference number.
   * @param name The delegation name. This makes a copy of the name. If there
   * is already a delegation with the same name, this updates its preference.
   * @return This Link so that you can chain calls to update values.
   */
  public final Link
  addDelegation(int preference, Name name)
  {
    return addDelegation(preference, name, WireFormat.getDefaultWireFormat());
  }

  /**
   * Remove every delegation with the given name. Re-encode this object's
   * content using the given wireFormat.
   * @param name Then name to match the name of the delegation(s) to be removed.
   * @param wireFormat A WireFormat object used to encode the DelegationSet.
   * @return True if a delegation was removed, otherwise false.
   */
  public final boolean
  removeDelegation(Name name, WireFormat wireFormat)
  {
    boolean wasRemoved = delegations_.remove(name);
    if (wasRemoved)
      encodeContent(wireFormat);

    return wasRemoved;
  }

  /**
   * Remove every delegation with the given name. Re-encode this object's
   * content using the default wire format.
   * @param name Then name to match the name of the delegation(s) to be removed.
   * @return True if a delegation was removed, otherwise false.
   */
  public final boolean
  removeDelegation(Name name)
  {
    return removeDelegation(name, WireFormat.getDefaultWireFormat());
  }

  /**
   * Get the list of delegation for read only.
   * @return The list of delegation, which you should treat as read-only. To
   * modify it, call Link.addDelegation, etc.
   */
  public final DelegationSet
  getDelegations() { return delegations_; }

  /**
   * Encode the delegations_ and set this object's content. Also set the
   * meta info content type to LINK.
   * @param wireFormat A WireFormat object used to encode the DelegationSet.
   */
  private void
  encodeContent(WireFormat wireFormat)
  {
    setContent(delegations_.wireEncode(wireFormat));
    getMetaInfo().setType(ContentType.LINK);
  }

  private final DelegationSet delegations_ = new DelegationSet();
}
