package net.named_data.jndn.lp;

import net.named_data.jndn.encoding.EncodingException;
import net.named_data.jndn.encoding.tlv.TlvDecoder;
import net.named_data.jndn.encoding.tlv.TlvEncoder;

/**
 * LpHeaderField represents the base class of LpHeaderFields define in NDNLPv2 packet.
 * http://redmine.named-data.net/projects/nfd/wiki/NDNLPv2
 */
public abstract class LpHeaderFiled {

    /**
     * Get LpHeaderField's TLV-TYPE value
     *
     * @return TLV-TYPE value
     */
    public abstract int
    getFieldType();

    /**
     * Use encoder to encode current LpHeaderField to LpPacket
     *
     * @param encoder a encoder, already encode previous LpPacket_Fragment and some LpHeaderFields (If it exists)
     *                which's TLV_TYPE code bigger then this LpHeaderFields.
     */
    public abstract void
    wireEncode(TlvEncoder encoder);

    /**
     * Use decoder to decode a LpHeaderField
     *
     * @param decoder        a decoder
     * @param fieldType      current decode LpHeaderField's TLV_TYPE
     * @param fieldLength    current decode LpHeaderField's fieldLength
     * @param fieldEndOffset current decode LpHeaderField's fieldEndOffset
     * @throws EncodingException
     */
    public abstract void
    wireDecode(TlvDecoder decoder, int fieldType, int fieldLength, int fieldEndOffset) throws EncodingException;
}