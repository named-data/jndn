/**
 * Copyright (C) 2013-2014 Regents of the University of California.
 * @author: Jeff Thompson <jefft0@remap.ucla.edu>
 * See COPYING for copyright and distribution information.
 */

package net.named_data.jndn.tests;

import java.nio.ByteBuffer;
import net.named_data.jndn.Data;
import net.named_data.jndn.Interest;
import net.named_data.jndn.Name;
import net.named_data.jndn.Node;
import net.named_data.jndn.OnData;
import net.named_data.jndn.encoding.TlvWireFormat;
import net.named_data.jndn.transport.TcpTransport;

class Counter implements OnData {
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
}

public class TestGetAsync {
  public static void 
  main(String[] args) 
  {
    try {
      // Face face("borges.metwi.ucla.edu");
      Node node = new Node
       (new TcpTransport(), new TcpTransport.ConnectionInfo("borges.metwi.ucla.edu"));
      
      Counter counter = new Counter();

      Name name1 = new Name("/");
      System.out.println("Express name " + name1.toUri());
      // face.expressInterest
      //   (name1, bind(&Counter::onData, &counter, _1, _2), 
      //    bind(&Counter::onTimeout, &counter, _1));
      {
        Interest interest = new Interest(name1, 4000.0);
        node.expressInterest(interest, counter, null, TlvWireFormat.get());
      }

      // The main event loop.
      while (counter.callbackCount_ < 1) {
        //face.processEvents();
        {
          node.processEvents();
        }
        // We need to sleep for a few milliseconds so we don't use 100% of 
        //   the CPU.
        Thread.sleep(5);
      }
    }
    catch (Throwable e) {
       System.out.println("exception: " + e.getMessage());
    }
  }
}
