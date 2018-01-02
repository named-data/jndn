------------------------------------------------------
jNDN:  A Named Data Networking client library for Java
------------------------------------------------------

jNDN is a new implementation of a Named Data Networking client library written in Java.
It is wire format compatible with the NDN-TLV encoding.

jNDN conforms to the NDN Common Client Libraries API and your application should
follow this public API:
http://named-data.net/doc/ndn-ccl-api/ .

See the file [INSTALL.md](https://github.com/named-data/jndn/blob/master/INSTALL.md) for build and install instructions.

If you are new to the NDN community of software generally, read the
[Contributor's Guide](https://github.com/named-data/NFD/blob/master/CONTRIBUTING.md).
Proposed code contributions should use a
[GitHub pull request](https://github.com/named-data/jndn/pulls).

Please submit any bugs or issues to the jNDN issue tracker:
http://redmine.named-data.net/projects/jndn/issues

---

The library currently requires a remote NDN daemon, and has been tested with the
NFD forwarder: https://github.com/named-data/NFD

License
-------
This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Lesser General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
A copy of the GNU Lesser General Public License is in the file COPYING.
