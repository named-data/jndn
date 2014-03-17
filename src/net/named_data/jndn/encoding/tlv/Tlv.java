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
    public static final int Interest =         5;
    public static final int Data =             6;
    public static final int Name =             7;
    public static final int NameComponent =    8;
    public static final int Selectors =        9;
    public static final int Nonce =            10;
    public static final int Scope =            11;
    public static final int InterestLifetime = 12;
    public static final int MinSuffixComponents = 13;
    public static final int MaxSuffixComponents = 14;
    public static final int PublisherPublicKeyLocator = 15;
    public static final int Exclude =          16;
    public static final int ChildSelector =    17;
    public static final int MustBeFresh =      18;
    public static final int Any =              19;
    public static final int MetaInfo =         20;
    public static final int Content =          21;
    public static final int SignatureInfo =    22;
    public static final int SignatureValue =   23;
    public static final int ContentType =      24;
    public static final int FreshnessPeriod =  25;
    public static final int FinalBlockId =     26;
    public static final int SignatureType =    27;
    public static final int KeyLocator =       28;
    public static final int KeyLocatorDigest = 29;
    public static final int FaceInstance =     128;
    public static final int ForwardingEntry =  129;
    public static final int StatusResponse =   130;
    public static final int Action =           131;
    public static final int FaceID =           132;
    public static final int IPProto =          133;
    public static final int Host =             134;
    public static final int Port =             135;
    public static final int MulticastInterface = 136;
    public static final int MulticastTTL =     137;
    public static final int ForwardingFlags =  138;
    public static final int StatusCode =       139;
    public static final int StatusText =       140;

    public static final int SignatureType_DigestSha256 = 0;
    public static final int SignatureType_SignatureSha256WithRsa = 1;
}
