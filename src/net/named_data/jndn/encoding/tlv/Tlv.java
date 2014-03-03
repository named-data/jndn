/**
 * Copyright (C) 2014 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * See COPYING for copyright and distribution information.
 */

package net.named_data.jndn.encoding.tlv;

/**
 * The Tlv class defines type codes for the NDN-TLV wire format. 
 */
public class Tlv {
    public final int Interest =         5;
    public final int Data =             6;
    public final int Name =             7;
    public final int NameComponent =    8;
    public final int Selectors =        9;
    public final int Nonce =            10;
    public final int Scope =            11;
    public final int InterestLifetime = 12;
    public final int MinSuffixComponents = 13;
    public final int MaxSuffixComponents = 14;
    public final int PublisherPublicKeyLocator = 15;
    public final int Exclude =          16;
    public final int ChildSelector =    17;
    public final int MustBeFresh =      18;
    public final int Any =              19;
    public final int MetaInfo =         20;
    public final int Content =          21;
    public final int SignatureInfo =    22;
    public final int SignatureValue =   23;
    public final int ContentType =      24;
    public final int FreshnessPeriod =  25;
    public final int FinalBlockId =     26;
    public final int SignatureType =    27;
    public final int KeyLocator =       28;
    public final int KeyLocatorDigest = 29;
    public final int FaceInstance =     128;
    public final int ForwardingEntry =  129;
    public final int StatusResponse =   130;
    public final int Action =           131;
    public final int FaceID =           132;
    public final int IPProto =          133;
    public final int Host =             134;
    public final int Port =             135;
    public final int MulticastInterface = 136;
    public final int MulticastTTL =     137;
    public final int ForwardingFlags =  138;
    public final int StatusCode =       139;
    public final int StatusText =       140;

    public final int SignatureType_DigestSha256 = 0;
    public final int SignatureType_SignatureSha256WithRsa = 1;
}
