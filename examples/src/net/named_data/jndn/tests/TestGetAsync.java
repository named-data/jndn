/**
 * Copyright (C) 2013-2017 Regents of the University of California.
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

package net.named_data.jndn.tests;

import java.nio.ByteBuffer;
import net.named_data.jndn.Data;
import net.named_data.jndn.Face;
import net.named_data.jndn.Interest;
import net.named_data.jndn.Name;
import net.named_data.jndn.OnData;
import net.named_data.jndn.OnTimeout;

class Counter implements OnData, OnTimeout {
  public void
  onData(Interest interest, Data data)
  {
    ++callbackCount_;
    System.out.println
      ("Got data packet with name " + data.getName().toUri());
    ByteBuffer content = data.getContent().buf();
    for (int i = content.position(); i < content.limit(); ++i)
      System.out.print((char)content.get(i));
    System.out.println("");
  }

  public int callbackCount_ = 0;

  public void onTimeout(Interest interest)
  {
    ++callbackCount_;
    System.out.println("Time out for interest " + interest.getName().toUri());
  }
}

public class TestGetAsync {
  public static void
  main(String[] args)
  {
    try {
      Face face = new Face("memoria.ndn.ucla.edu");

      Counter counter = new Counter();

      // Try to fetch anything.
      Name name1 = new Name("/");
      System.out.println("Express name " + name1.toUri());
      face.expressInterest(name1, counter, counter);

      // Try to fetch using a known name.
      Name name2 = new Name("/ndn/edu/ucla/remap/demo/ndn-js-test/hello.txt/%FDX%DC5%1F");
      System.out.println("Express name " + name2.toUri());
      face.expressInterest(name2, counter, counter);

      // Expect this to time out.
      Name name3 = new Name("/test/timeout");
      System.out.println("Express name " + name3.toUri());
      face.expressInterest(name3, counter, counter);

      // The main event loop.
      while (counter.callbackCount_ < 3) {
        face.processEvents();

        // We need to sleep for a few milliseconds so we don't use 100% of
        //   the CPU.
        Thread.sleep(5);
      }
    }
    catch (Exception e) {
       System.out.println("exception: " + e.getMessage());
    }
  }
}
