/**
 * Copyright (C) 2014 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * @author: From PyNDN der.py by Adeola Bannis <thecodemaiden@gmail.com>.
 * @author: Originally from code in NDN-CPP by Yingdi Yu <yingdi@cs.ucla.edu>
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
public enum NodeType {
    Eoc(0),
    Boolean(1),
    Integer(2),
    BitString(3),
    OctetString(4),
    Null(5),
    ObjectIdentifier(6),
    ObjectDescriptor(7),
    External(40),
    Real(9),
    Enumerated(10),
    EmbeddedPdv(43),
    Utf8String(12),
    RelativeOid(13),
    Sequence(48),
    Set(49),
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
    BmpString(30);

  NodeType (int type)
  {
    type_ = type;
  }

  public final int
  getNumericType() { return type_; }

  public static NodeType
  fromNumericType(int type)
  {
    NodeType[] array = NodeType.values();
    for(int i = 0; i < array.length; ++i) {
      if (array[i].getNumericType() == type)
        return array[i];
    }

    return null;
  }

  private final int type_;
}
