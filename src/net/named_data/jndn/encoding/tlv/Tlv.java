/**
 * Copyright (C) 2014-2018 Regents of the University of California.
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

package net.named_data.jndn.encoding.tlv;

/**
 * The Tlv class defines type codes for the NDN-TLV wire format.
 */
public class Tlv {
  public static final int Interest =         5;
  public static final int Data =             6;
  public static final int Name =             7;
  public static final int ImplicitSha256DigestComponent = 1;
  public static final int ParametersSha256DigestComponent = 2;
  public static final int NameComponent =    8;
  public static final int Selectors =        9;
  public static final int Nonce =            10;
  // public static final int <Unassigned> =  11;
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
  public static final int ForwardingHint =   30;
  public static final int SelectedDelegation = 32;
  public static final int CanBePrefix =      33;
  public static final int HopLimit =         34;
  public static final int Parameters =       35;
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
  public static final int SignatureType_SignatureSha256WithEcdsa = 3;
  public static final int SignatureType_SignatureHmacWithSha256 = 4;

  public static final int ContentType_Default = 0;
  public static final int ContentType_Link = 1;
  public static final int ContentType_Key = 2;

  public static final int NfdCommand_ControlResponse = 101;
  public static final int NfdCommand_StatusCode =      102;
  public static final int NfdCommand_StatusText =      103;

  public static final int ControlParameters_ControlParameters =   104;
  public static final int ControlParameters_FaceId =              105;
  public static final int ControlParameters_Uri =                 114;
  public static final int ControlParameters_LocalUri =            129;
  public static final int ControlParameters_LocalControlFeature = 110;
  public static final int ControlParameters_Origin =              111;
  public static final int ControlParameters_Cost =                106;
  public static final int ControlParameters_Capacity =            131;
  public static final int ControlParameters_Count =               132;
  public static final int ControlParameters_BaseCongestionMarkingInterval = 135;
  public static final int ControlParameters_DefaultCongestionThreshold = 136;
  public static final int ControlParameters_Mtu =                 137;
  public static final int ControlParameters_Flags =               108;
  public static final int ControlParameters_Mask =                112;
  public static final int ControlParameters_Strategy =            107;
  public static final int ControlParameters_ExpirationPeriod =    109;

  public static final int LpPacket_LpPacket = 100;
  public static final int LpPacket_Fragment = 80;
  public static final int LpPacket_Sequence = 81;
  public static final int LpPacket_FragIndex = 82;
  public static final int LpPacket_FragCount = 83;
  public static final int LpPacket_Nack = 800;
  public static final int LpPacket_NackReason = 801;
  public static final int LpPacket_NextHopFaceId = 816;
  public static final int LpPacket_IncomingFaceId = 817;
  public static final int LpPacket_CachePolicy = 820;
  public static final int LpPacket_CachePolicyType = 821;
  public static final int LpPacket_CongestionMark =  832;
  public static final int LpPacket_IGNORE_MIN = 800;
  public static final int LpPacket_IGNORE_MAX = 959;

  public static final int Link_Preference = 30;
  public static final int Link_Delegation = 31;

  public static final int Encrypt_EncryptedContent = 130;
  public static final int Encrypt_EncryptionAlgorithm = 131;
  public static final int Encrypt_EncryptedPayload = 132;
  public static final int Encrypt_InitialVector = 133;
  public static final int Encrypt_EncryptedPayloadKey = 134;

  public static final int SafeBag_SafeBag = 128;
  public static final int SafeBag_EncryptedKeyBag = 129;

  // For RepetitiveInterval.
  public static final int Encrypt_StartDate = 134;
  public static final int Encrypt_EndDate = 135;
  public static final int Encrypt_IntervalStartHour = 136;
  public static final int Encrypt_IntervalEndHour = 137;
  public static final int Encrypt_NRepeats = 138;
  public static final int Encrypt_RepeatUnit = 139;
  public static final int Encrypt_RepetitiveInterval = 140;
  public static final int Encrypt_RepeatUnit_NONE = 0;
  public static final int Encrypt_RepeatUnit_DAY = 1;
  public static final int Encrypt_RepeatUnit_MONTH = 2;
  public static final int Encrypt_RepeatUnit_YEAR = 3;

  // For Schedule.
  public static final int Encrypt_WhiteIntervalList = 141;
  public static final int Encrypt_BlackIntervalList = 142;
  public static final int Encrypt_Schedule = 143;

  public static final int ValidityPeriod_ValidityPeriod = 253;
  public static final int ValidityPeriod_NotBefore = 254;
  public static final int ValidityPeriod_NotAfter = 255;
}
