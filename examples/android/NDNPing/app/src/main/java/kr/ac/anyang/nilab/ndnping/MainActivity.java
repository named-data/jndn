/*
 * Copyright (C) 2014 Regents of the University of California.
 * @author: Euihyun Jung <jung@anyang.ac.kr>
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

package kr.ac.anyang.nilab.ndnping;

import kr.ac.anyang.nilab.ndnping.R;

import java.io.BufferedReader;

import java.nio.ByteBuffer;

import java.nio.charset.Charset;

import net.named_data.jndn.Data;

import net.named_data.jndn.Face;

import net.named_data.jndn.Interest;

import net.named_data.jndn.Name;

import net.named_data.jndn.OnData;

import net.named_data.jndn.OnTimeout;

import android.app.Activity;

import android.app.ProgressDialog;

import android.os.Bundle;

import android.os.Handler;

import android.os.Message;

import android.util.Log;

import android.view.View;

import android.widget.Button;

import android.widget.TextView;

public class MainActivity extends Activity {

	private TextView _tv_console;

	private Button _btn_action;

	private static final String TAG = "NDN";

	private ProgressDialog _proDlg;

	@Override
	protected void onCreate(Bundle savedInstanceState) {

		super.onCreate(savedInstanceState);

		setContentView(R.layout.activity_main);

		this._tv_console = (TextView) findViewById(R.id.tv_console);

		this._btn_action = (Button) findViewById(R.id.btn_action);

		this._btn_action.setOnClickListener(btnClickListener);

	}

	// Button Click Event Listener

	View.OnClickListener btnClickListener = new View.OnClickListener() {

		@Override
		public void onClick(View v) {

			// TODO Auto-generated method stub

			_proDlg = ProgressDialog.show(MainActivity.this, "", "waiting...");

			NetThread thread = new NetThread();

			thread.start();

		}

	};

	private class PingTimer implements OnData, OnTimeout {

		private long startTime;

		public void onData(Interest interest, Data data)

		{
			++callbackCount_;

			Log.i(TAG, "Got data packet with name " + data.getName().toUri());

			long elapsedTime = System.currentTimeMillis() - this.startTime;

			String name = data.getName().toUri();

			String pingTarget = name.substring(0, name.lastIndexOf("/"));

			String contentStr = pingTarget + ": " + String.valueOf(elapsedTime) + " ms";

			Log.i(TAG, "Content " + contentStr);

			// Send a result to Screen

			Message msg = new Message();

			msg.what = 200; // Result Code ex) Success code: 200 , Fail Code:
							// 400 ...

			msg.obj = contentStr; // Result Object

			actionHandler.sendMessage(msg);

		}

		public int callbackCount_ = 0;

		public void onTimeout(Interest interest)

		{

			++callbackCount_;

			Log.i(TAG, "Time out for interest " + interest.getName().toUri());

		}

		public void startUp() {

			startTime = System.currentTimeMillis();

		}

	}

	private class NetThread extends Thread {

		public NetThread() {

		}

		@Override
		public void run() {

			try {

				Face face = new Face("spurs.cs.ucla.edu");

				PingTimer timer = new PingTimer();

				String pingName = "/ndn/org/caida/ping/"
						+ Math.floor(Math.random() * 100000);

				Name name = new Name(pingName);

				Log.i(TAG, "Express name " + name.toUri());

				timer.startUp();

				face.expressInterest(name, timer, timer);

				// The main event loop.

				while (timer.callbackCount_ < 1) {

					face.processEvents();

					// We need to sleep for a few milliseconds so we don't use
					// 100% of

					// the CPU.

					Thread.sleep(5);

				}

			}

			catch (Exception e) {

				Log.i(TAG, "exception: " + e.getMessage());

				e.printStackTrace();

			}

		}

	}

	// UI controller

	private Handler actionHandler = new Handler() {

		public void handleMessage(Message msg) {

			String viewMsg = "Empty";

			switch (msg.what) { // Result Code

			case 200: // Result Code Ex) Success: 200

				viewMsg = (String) msg.obj; // Result Data..

				break;

			default:

				viewMsg = "Error Code: " + msg.what;

				break;

			}

			if (_proDlg != null)
				_proDlg.dismiss();

			_tv_console.setText(viewMsg);

		}

	};

}
