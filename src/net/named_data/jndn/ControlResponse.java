/**
 * Copyright (C) 2016-2018 Regents of the University of California.
 * @author: Andrew Brown <andrew.brown@intel.com>
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

package net.named_data.jndn;

import java.nio.ByteBuffer;
import net.named_data.jndn.encoding.EncodingException;
import net.named_data.jndn.encoding.WireFormat;
import net.named_data.jndn.util.Blob;

/**
 * A ControlResponse holds a status code, status text and other fields for a
 * ControlResponse which is used, for example, in the response from sending a
 * register prefix control command to a forwarder. See
 * <a href="http://redmine.named-data.net/projects/nfd/wiki/ControlCommand">http://redmine.named-data.net/projects/nfd/wiki/ControlCommand</a>
 *
 * @author Andrew Brown, andrew.brown@intel.com
 * @author Jeff Thompson, jefft0@remap.ucla.edu
 */
public class ControlResponse {
  /**
   * Create a new ControlResponse where all values are unspecified.
   */
  public
  ControlResponse() {}

  /**
   * Create a new ControlResponse as a deep copy of the given ControlResponse.
   * @param controlResponse The ControlResponse to copy.
   */
  public
  ControlResponse(ControlResponse controlResponse)
  {
    statusCode_ = controlResponse.statusCode_;
    statusText_ = controlResponse.statusText_;
    bodyAsControlParameters_ = controlResponse.bodyAsControlParameters_ == null ?
      null : new ControlParameters(controlResponse.bodyAsControlParameters_);
  }

  /**
   * Encode this ControlResponse for a particular wire format.
   * @param wireFormat A WireFormat object used to encode this ControlResponse.
   * @return The encoded buffer.
   */
  public final Blob
  wireEncode(WireFormat wireFormat)
  {
    return wireFormat.encodeControlResponse(this);
  }

  /**
   * Encode this ControlResponse for the default wire format
   * WireFormat.getDefaultWireFormat().
   * @return The encoded buffer.
   */
  public final Blob
  wireEncode()
  {
    return wireEncode(WireFormat.getDefaultWireFormat());
  }

  /**
   * Decode the input using a particular wire format and update this ControlResponse.
   * @param input The input buffer to decode.  This reads from position() to
   * limit(), but does not change the position.
   * @param wireFormat A WireFormat object used to decode the input.
   * @throws EncodingException For invalid encoding.
   */
  public final void
  wireDecode(ByteBuffer input, WireFormat wireFormat) throws EncodingException
  {
    wireFormat.decodeControlResponse(this, input, true);
  }

  /**
   * Decode the input using the default wire format
   * WireFormat.getDefaultWireFormat() and update this ControlResponse.
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
   * Decode the input using a particular wire format and update this ControlResponse.
   * @param input The input blob to decode.
   * @param wireFormat A WireFormat object used to decode the input.
   * @throws EncodingException For invalid encoding.
   */
  public final void
  wireDecode(Blob input, WireFormat wireFormat) throws EncodingException
  {
    wireFormat.decodeControlResponse(this, input.buf(), false);
  }

  /**
   * Decode the input using the default wire format
   * WireFormat.getDefaultWireFormat() and update this ControlResponse.
   * @param input The input blob to decode.
   * @throws EncodingException For invalid encoding.
   */
  public final void
  wireDecode(Blob input) throws EncodingException
  {
    wireDecode(input.buf());
  }

  /**
   * Get the status code.
   * @return The status code. If not specified, return -1.
   */
  public final int
  getStatusCode() { return statusCode_; }

  /**
   * Get the status text.
   * @return The status text. If not specified, return "".
   */
  public final String
  getStatusText() { return statusText_; }

  /**
   * Get the control response body as a ControlParameters.
   * @return The ControlParameters, or null if the body is not specified or if
   * it is not a ControlParameters.
   */
  public final ControlParameters
  getBodyAsControlParameters() { return bodyAsControlParameters_; }

  /**
   * Set the status code.
   * @param statusCode The status code. If not specified, set to -1.
   * @return This ControlResponse so that you can chain calls to update values.
   */
  public final ControlResponse
  setStatusCode(int statusCode)
  {
    statusCode_ = statusCode;
    return this;
  }

  /**
   * Set the status text.
   * @param statusText The status text. If not specified, set to "".
   * @return This ControlResponse so that you can chain calls to update values.
   */
  public final ControlResponse
  setStatusText(String statusText)
  {
    statusText_ = statusText == null ? "" : statusText;;
    return this;
  }

  /**
   * Set the control response body as a ControlParameters.
   * @param controlParameters The ControlParameters for the body. This makes a
   * copy of the ControlParameters. If not specified or if the body is not a
   * ControlParameters, set to null.
   * @return This ControlResponse so that you can chain calls to update values.
   */
  public final ControlResponse
  setBodyAsControlParameters(ControlParameters controlParameters)
  {
    bodyAsControlParameters_ = controlParameters == null ?
      null : new ControlParameters(controlParameters);
    return this;
  }

  private int statusCode_ = -1;
  private String statusText_ = "";
  private ControlParameters bodyAsControlParameters_ = null;
}
