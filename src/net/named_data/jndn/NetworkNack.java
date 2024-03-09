/**
 * Copyright (C) 2016-2019 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From ndn-cxx nack.hpp https://github.com/named-data/ndn-cxx/blob/master/ndn-cxx/lp/nack.hpp
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
import net.named_data.jndn.encoding.tlv.Tlv;
import net.named_data.jndn.encoding.tlv.TlvDecoder;
import net.named_data.jndn.encoding.tlv.TlvEncoder;
import net.named_data.jndn.lp.LpHeaderFiled;
import net.named_data.jndn.lp.LpPacket;

/**
 * NetworkNack represents a network Nack packet and includes a Nack reason.
 */
public class NetworkNack extends LpHeaderFiled {
  @Override
  public int getFieldType() {
    return Tlv.LpPacket_Nack;
  }

  @Override
  public void wireEncode(TlvEncoder encoder) {
    int reason;
    if (getReason() == Reason.NONE ||
        getReason() == Reason.CONGESTION ||
        getReason() == Reason.DUPLICATE ||
        getReason() == Reason.NO_ROUTE)
      // The Reason enum is set up with the correct integer for each NDN-TLV Reason.
      reason = getReason().getNumericType();
    else if (getReason() == Reason.OTHER_CODE)
      reason = getOtherReasonCode();
    else
      // We don't expect this to happen.
      throw new Error("unrecognized getReason() value");

    int nackSaveLength = encoder.getLength();
    encoder.writeNonNegativeIntegerTlv(Tlv.LpPacket_NackReason, reason);
    encoder.writeTypeAndLength
        (getFieldType(), encoder.getLength() - nackSaveLength);
  }

  @Override
  public void wireDecode(TlvDecoder decoder, int fieldType, int fieldLength, int fieldEndOffset) throws EncodingException {
    int code = (int) decoder.readOptionalNonNegativeIntegerTlv
        (Tlv.LpPacket_NackReason, fieldEndOffset);
    // The enum numeric values are the same as this wire format, so use as is.
    if (code < 0 || code == NetworkNack.Reason.NONE.getNumericType())
      // This includes an omitted NackReason.
      setReason(NetworkNack.Reason.NONE);
    else if (code == NetworkNack.Reason.CONGESTION.getNumericType())
      setReason(NetworkNack.Reason.CONGESTION);
    else if (code == NetworkNack.Reason.DUPLICATE.getNumericType())
      setReason(NetworkNack.Reason.DUPLICATE);
    else if (code == NetworkNack.Reason.NO_ROUTE.getNumericType())
      setReason(NetworkNack.Reason.NO_ROUTE);
    else {
      // Unrecognized reason.
      setReason(NetworkNack.Reason.OTHER_CODE);
      setOtherReasonCode(code);
    }
  }

  /**
   * A NetworkNack.Reason specifies the reason in a NetworkNack packet. If the
   * reason code in the packet is not a recognized enum value, then we use
   * Reason.OTHER_CODE and you can call getOtherReasonCode(). We do this to keep
   * the recognized reason values independent of packet encoding formats.
   */
  public static enum Reason {
    NONE      (0),
    CONGESTION(50),
    DUPLICATE (100),
    NO_ROUTE  (150),
    OTHER_CODE(0x7fff);

    Reason (int type)
    {
      type_ = type;
    }

    public final int
    getNumericType() { return type_; }

    private final int type_;
  }

  /**
   * Get the network Nack reason.
   * @return The reason enum value. If this is Reason.OTHER_CODE, then call
   * getOtherReasonCode() to get the unrecognized reason code.
   */
  public Reason
  getReason() { return reason_; }

  /**
   * Get the reason code from the packet which is other than a recognized
   * Reason enum value. This is only meaningful if getReason() is
   * Reason.OTHER_CODE.
   * @return The reason code.
   */
  public int
  getOtherReasonCode() { return otherReasonCode_; }

  /**
   * Set the network Nack reason.
   * @param reason The network Nack reason enum value. If the packet's reason
   * code is not a recognized Reason enum value, use Reason.OTHER_CODE and call
   * setOtherReasonCode().
   * @return This NetworkNack so that you can chain calls to update values.
   */
  public NetworkNack
  setReason(Reason reason)
  {
    reason_ = reason;
    return this;
  }

  /**
   * Set the packet's reason code to use when the reason enum is
   * Reason.OTHER_CODE. If the packet's reason code is a recognized enum value,
   * just call setReason().
   * @param otherReasonCode The packet's unrecognized reason code, which must be
   * non-negative.
   * @return This NetworkNack so that you can chain calls to update values.
   */
  public NetworkNack
  setOtherReasonCode(int otherReasonCode)
  {
    if (otherReasonCode < 0)
      throw new Error("NetworkNack other reason code must be non-negative");
    otherReasonCode_ = otherReasonCode;
    return this;
  }

  /**
   * Get the first header field in lpPacket which is a NetworkNack. This is
   * an internal method which the application normally would not use.
   * @param lpPacket The LpPacket with the header fields to search.
   * @return The first NetworkNack header field, or null if not found.
   */
  static public NetworkNack
  getFirstHeader(LpPacket lpPacket)
  {
    for (int i = 0; i < lpPacket.countHeaderFields(); ++i) {
      Object field = lpPacket.getHeaderField(i);
      if (field instanceof NetworkNack)
        return (NetworkNack)field;
    }

    return null;
  }

  private Reason reason_ = Reason.NONE;
  private int otherReasonCode_ = -1;
}
