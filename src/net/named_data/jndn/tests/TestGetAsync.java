/**
 * Copyright (C) 2013-2014 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * See COPYING for copyright and distribution information.
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
      Face face = new Face("aleph.ndn.ucla.edu");
      
      Counter counter = new Counter();

      Name name1 = new Name("/ndn/edu/ucla/remap/ndn-js-test/howdy.txt/%FD%052%A1%DF%5E%A4");
      System.out.println("Express name " + name1.toUri());
      face.expressInterest(name1, counter, counter); 

      // Try to get anything.
      Name name2 = new Name("/");
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
