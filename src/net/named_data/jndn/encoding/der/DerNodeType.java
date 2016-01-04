/**
 * Copyright (C) 2014-2015 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From PyNDN der.py by Adeola Bannis <thecodemaiden@gmail.com>.
 * @author: Originally from code in ndn-cxx by Yingdi Yu <yingdi@cs.ucla.edu>
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

package net.named_data.jndn.encoding.der;

/**
 * The NodeType enum defines the known DER node types.
 */
public enum DerNodeType {
    Eoc(0),
    Boolean(1),
    Integer(2),
    BitString(3),
    OctetString(4),
    Null(5),
    ObjectIdentifier(6),
    ObjectDescriptor(7),
    Unused8(8),
    Real(9),
    Enumerated(10),
    Unused11(11),
    Utf8String(12),
    RelativeOid(13),
    Unused14(14),
    Unused15(15),
    Unused16(16),
    Unused17(17),
    NumericString(18),
    PrintableString(19),
    T61String(20),
    VideoTexString(21),
    Ia5String(22),
    UtcTime(23),
    GeneralizedTime(24),
    GraphicString(25),
    VisibleString(26),
    GeneralString(27),
    UniversalString(28),
    CharacterString(29),
    BmpString(30),
    Unused31(31),
    Unused32(32),
    Unused33(33),
    Unused34(34),
    Unused35(35),
    Unused36(36),
    Unused37(37),
    Unused38(38),
    Unused39(39),
    External(40),
    Unused41(41),
    Unused42(42),
    EmbeddedPdv(43),
    Unused44(44),
    Unused45(45),
    Unused46(46),
    Unused47(47),
    Sequence(48),
    Set(49);

  DerNodeType (int type)
  {
    type_ = type;
  }

  public final int
  getNumericType() { return type_; }

  private final int type_;
}
