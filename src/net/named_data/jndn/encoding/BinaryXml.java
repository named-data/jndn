/**
 * Copyright (C) 2013-2014 Regents of the University of California.
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
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 * A copy of the GNU General Public License is in the file COPYING.
 */

package net.named_data.jndn.encoding;

public class BinaryXml {
  public static final int EXT = 0x00;   
  public static final int TAG = 0x01; 
  public static final int DTAG = 0x02; 
  public static final int ATTR = 0x03; 
  public static final int DATTR = 0x04; 
  public static final int BLOB = 0x05; 
  public static final int UDATA = 0x06; 
  public static final int CLOSE = 0x0;

  public static final int TT_BITS = 3;
  public static final int TT_MASK = ((1 << TT_BITS) - 1);
  public static final int TT_VALUE_BITS = 4;
  public static final int TT_VALUE_MASK = ((1 << (TT_VALUE_BITS)) - 1);
  public static final int REGULAR_VALUE_BITS = 7;
  public static final int REGULAR_VALUE_MASK = ((1 << REGULAR_VALUE_BITS) - 1);
  public static final int TT_FINAL = 0x80;

  public static final int DTag_Any = 13;
  public static final int DTag_Name = 14;
  public static final int DTag_Component = 15;
  public static final int DTag_Certificate = 16;
  public static final int DTag_Collection = 17;
  public static final int DTag_CompleteName = 18;
  public static final int DTag_Content = 19;
  public static final int DTag_SignedInfo = 20;
  public static final int DTag_ContentDigest = 21;
  public static final int DTag_ContentHash = 22;
  public static final int DTag_Count = 24;
  public static final int DTag_Header = 25;
  public static final int DTag_Interest = 26;  /* 20090915 */
  public static final int DTag_Key = 27;
  public static final int DTag_KeyLocator = 28;
  public static final int DTag_KeyName = 29;
  public static final int DTag_Length = 30;
  public static final int DTag_Link = 31;
  public static final int DTag_LinkAuthenticator = 32;
  public static final int DTag_NameComponentCount = 33;  /* DeprecatedInInterest */
  public static final int DTag_RootDigest = 36;
  public static final int DTag_Signature = 37;
  public static final int DTag_Start = 38;
  public static final int DTag_Timestamp = 39;
  public static final int DTag_Type = 40;
  public static final int DTag_Nonce = 41;
  public static final int DTag_Scope = 42;
  public static final int DTag_Exclude = 43;
  public static final int DTag_Bloom = 44;
  public static final int DTag_BloomSeed = 45;
  public static final int DTag_AnswerOriginKind = 47;
  public static final int DTag_InterestLifetime = 48;
  public static final int DTag_Witness = 53;
  public static final int DTag_SignatureBits = 54;
  public static final int DTag_DigestAlgorithm = 55;
  public static final int DTag_BlockSize = 56;
  public static final int DTag_FreshnessSeconds = 58;
  public static final int DTag_FinalBlockID = 59;
  public static final int DTag_PublisherPublicKeyDigest = 60;
  public static final int DTag_PublisherCertificateDigest = 61;
  public static final int DTag_PublisherIssuerKeyDigest = 62;
  public static final int DTag_PublisherIssuerCertificateDigest = 63;
  public static final int DTag_ContentObject = 64;  /* 20090915 */
  public static final int DTag_WrappedKey = 65;
  public static final int DTag_WrappingKeyIdentifier = 66;
  public static final int DTag_WrapAlgorithm = 67;
  public static final int DTag_KeyAlgorithm = 68;
  public static final int DTag_Label = 69;
  public static final int DTag_EncryptedKey = 70;
  public static final int DTag_EncryptedNonceKey = 71;
  public static final int DTag_WrappingKeyName = 72;
  public static final int DTag_Action = 73;
  public static final int DTag_FaceID = 74;
  public static final int DTag_IPProto = 75;
  public static final int DTag_Host = 76;
  public static final int DTag_Port = 77;
  public static final int DTag_MulticastInterface = 78;
  public static final int DTag_ForwardingFlags = 79;
  public static final int DTag_FaceInstance = 80;
  public static final int DTag_ForwardingEntry = 81;
  public static final int DTag_MulticastTTL = 82;
  public static final int DTag_MinSuffixComponents = 83;
  public static final int DTag_MaxSuffixComponents = 84;
  public static final int DTag_ChildSelector = 85;
  public static final int DTag_RepositoryInfo = 86;
  public static final int DTag_Version = 87;
  public static final int DTag_RepositoryVersion = 88;
  public static final int DTag_GlobalPrefix = 89;
  public static final int DTag_LocalName = 90;
  public static final int DTag_Policy = 91;
  public static final int DTag_Namespace = 92;
  public static final int DTag_GlobalPrefixName = 93;
  public static final int DTag_PolicyVersion = 94;
  public static final int DTag_KeyValueSet = 95;
  public static final int DTag_KeyValuePair = 96;
  public static final int DTag_IntegerValue = 97;
  public static final int DTag_DecimalValue = 98;
  public static final int DTag_StringValue = 99;
  public static final int DTag_BinaryValue = 100;
  public static final int DTag_NameValue = 101;
  public static final int DTag_Entry = 102;
  public static final int DTag_ACL = 103;
  public static final int DTag_ParameterizedName = 104;
  public static final int DTag_Prefix = 105;
  public static final int DTag_Suffix = 106;
  public static final int DTag_Root = 107;
  public static final int DTag_ProfileName = 108;
  public static final int DTag_Parameters = 109;
  public static final int DTag_InfoString = 110;
  public static final int DTag_StatusResponse = 112;
  public static final int DTag_StatusCode = 113;
  public static final int DTag_StatusText = 114;
  public static final int DTag_SyncNode = 115;
  public static final int DTag_SyncNodeKind = 116;
  public static final int DTag_SyncNodeElement = 117;
  public static final int DTag_SyncVersion = 118;
  public static final int DTag_SyncNodeElements = 119;
  public static final int DTag_SyncContentHash = 120;
  public static final int DTag_SyncLeafCount = 121;
  public static final int DTag_SyncTreeDepth = 122;
  public static final int DTag_SyncByteCount = 123;
  public static final int DTag_SyncConfigSlice = 124;
  public static final int DTag_SyncConfigSliceList = 125;
  public static final int DTag_SyncConfigSliceOp = 126;
  public static final int DTag_SyncNodeDeltas = 127;
  public static final int DTag_SequenceNumber = 256;
  public static final int DTag_NDNProtocolDataUnit = 20587744; // the encoded empty element, viewed as a string is "NDN\202\000"
}
