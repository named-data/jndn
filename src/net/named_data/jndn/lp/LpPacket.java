/**
 * Copyright (C) 2016 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From ndn-cxx packet.hpp https://github.com/named-data/ndn-cxx/blob/master/src/lp/packet.hpp
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

package net.named_data.jndn.lp;

import java.util.ArrayList;
import net.named_data.jndn.util.Blob;

/**
 * An LpPacket represents an NDNLPv2 packet including header fields an an
 * optional fragment. This is an internal class which the application normally
 * would not use.
 * http://redmine.named-data.net/projects/nfd/wiki/NDNLPv2
 */
public class LpPacket {
  /**
   * Get the fragment wire encoding.
   * @return The wire encoding, or an isNull Blob if not specified.
   */
  public Blob
  getFragmentWireEncoding() { return fragmentWireEncoding_; }

  /**
   * Get the number of header fields. This does not include the fragment.
   * @return The number of header fields.
   */
  public int
  countHeaderFields() { return headerFields_.size(); }

  /**
   * Get the header field at the given index.
   * @param index The index, starting from 0. It is an error if index is greater
   * to or equal to countHeaderFields().
   * @return The header field at the index.
   */
  public Object
  getHeaderField(int index) { return headerFields_.get(index); }

  /**
   * Remove all header fields and set the fragment to an isNull Blob.
   */
  public void
  clear()
  {
     headerFields_ = new ArrayList();
     fragmentWireEncoding_ = new Blob();
  }

  /**
   * Set the fragment wire encoding.
   * @param fragmentWireEncoding The fragment wire encoding or an isNull Blob
   * if not specified.
   */
  public void
  setFragmentWireEncoding(Blob fragmentWireEncoding)
  {
    fragmentWireEncoding_ =
      (fragmentWireEncoding == null ? new Blob() : fragmentWireEncoding);
  }

  /**
   * Add a header field. To add the fragment, use setFragmentWireEncoding().
   * @param headerField The header field to add.
   */
  public void
  addHeaderField(Object headerField) { headerFields_.add(headerField); }

  private ArrayList headerFields_ = new ArrayList();
  private Blob fragmentWireEncoding_ = new Blob();
}
