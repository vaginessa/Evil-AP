package com.nibiru.evil_ap.proxy;

import android.content.Intent;
import android.net.VpnService;
import android.os.ParcelFileDescriptor;
import android.util.Log;

import com.nibiru.evil_ap.R;
import com.nibiru.evil_ap.SharedClass;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.nio.ByteBuffer;
import java.nio.channels.DatagramChannel;
import java.security.KeyStore;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;

/**
 * Created by Nibiru on 2017-02-12.
 */
public class ProxyVpnService extends VpnService{
    /**************************************CLASS FIELDS********************************************/
    protected final String TAG = getClass().getSimpleName();
    private ServerSocket mSocketHTTP;
    private SSLServerSocket mSocketHTTPS;
    private Thread mThread;
    private ParcelFileDescriptor mInterface;
    //Configure a builder for the interface.
    Builder builder = new Builder();
    // don't really care if this ends up in repo...
    private static char ksPass[] = "KeyStorePass".toCharArray();
    private static char ctPass[] = "KeyStorePass".toCharArray();
    /**************************************CLASS METHODS*******************************************/
    // Services interface
    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        // create okhttp client with ability to protect sockets
        SharedClass.getInstance().setClient(getSharedPreferences("Config",0), this);
        // create server sockets
        try {
            mSocketHTTP = new ServerSocket();
            mSocketHTTPS = getSSLSocket(getResources().openRawResource(R.raw.evil_ap));
        } catch (Exception e) {
            e.printStackTrace();
        }
        // Start a new session by creating a new thread.
        //https://github.com/guardianproject/OrbotVPN/blob/master/src/org/torproject/android/vpn/OrbotVpnService.java
        //http://www.thegeekstuff.com/2014/06/android-vpn-service/
        mThread = new Thread(new Runnable() {
            @Override
            public void run() {
                try {
                    // Allocate the buffer for a single packet
                    ByteBuffer packet = ByteBuffer.allocate(32767);

                    // Configure the TUN and get the interface
                    mInterface = builder.setSession("ProxyVpnService")
                            .addAddress("192.168.0.1", 24)
                            .addDnsServer("8.8.8.8")
                            .addRoute("0.0.0.0", 0).establish();
                    // Packets to be sent are queued in this input stream
                    FileInputStream in = new FileInputStream(mInterface.getFileDescriptor());
                    // Packets received need to be written to this output stream
                    FileOutputStream out = new FileOutputStream(mInterface.getFileDescriptor());

                    // The UDP channel can be used to pass/get ip package to/from server
                    //DatagramChannel tunnel = DatagramChannel.open();
                    // Connect to the server, localhost is used for demonstration only
                    //tunnel.connect(new InetSocketAddress("127.0.0.1", 8087));
                    //d. Protect this socket, so package send by it will not be feedback to the vpn service.
                    //protect(tunnel.socket());
                    // Use a loop to pass packets
                    while (true) {
                        // Read the outgoing packet from the input stream.
                        int length = in.read(packet.array());
                        if (length > 0) {
                            Log.d(TAG,"got outgoing packet; length=" + length);
                            // Write the outgoing packet to the tunnel.
                            packet.limit(length);
                            //mTunnel.write(packet);
                            packet.clear();
                        }
                        //put packet to tunnel
                        //get packet from tunnel
                        //return packet with out
                        //sleep is a must
                        Thread.sleep(100);
                    }

                } catch (Exception e) {
                    // Catch any exception
                    e.printStackTrace();
                } finally {
                    try {
                        if (mInterface != null) {
                            mInterface.close();
                            mInterface = null;
                        }
                    } catch (Exception e) {

                    }
                }
            }

        }, "MyVpnRunnable");

        //start the service
        mThread.start();
        return START_STICKY;
    }

    @Override
    public void onDestroy() {
        if (mThread != null) {
            mThread.interrupt();
        }
        super.onDestroy();
    }

    private SSLServerSocket getSSLSocket(InputStream keyStore) throws Exception{
        KeyStore ks = KeyStore.getInstance("BKS"); //Bouncy Castle Key Store
        ks.load(keyStore, ksPass); //authenticate with keystore
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(ks, ctPass); //authenticate with certificate
        SSLContext sc = SSLContext.getInstance("TLS");
        sc.init(kmf.getKeyManagers(), null, null);
        SSLServerSocketFactory ssf = sc.getServerSocketFactory();
        return (SSLServerSocket) ssf.createServerSocket();
    }

    private void debugPacket(ByteBuffer packet) {
        /*
        for(int i = 0; i < length; ++i)
        {
            byte buffer = packet.get();
            Log.d(TAG, "byte:"+buffer);
        }*/
        int buffer = packet.get();
        int version;
        int headerlength;
        version = buffer >> 4;
        headerlength = buffer & 0x0F;
        headerlength *= 4;
        Log.d(TAG, "IP Version:"+version);
        Log.d(TAG, "Header Length:"+headerlength);

        String status = "";
        status += "Header Length:"+headerlength;

        buffer = packet.get();      //DSCP + EN
        buffer = packet.getChar();  //Total Length

        Log.d(TAG, "Total Length:"+buffer);

        buffer = packet.getChar();  //Identification
        buffer = packet.getChar();  //Flags + Fragment Offset
        buffer = packet.get();      //Time to Live
        buffer = packet.get();      //Protocol

        Log.d(TAG, "Protocol:"+buffer);

        status += "  Protocol:"+buffer;

        buffer = packet.getChar();  //Header checksum

        String sourceIP  = "";
        buffer = packet.get();  //Source IP 1st Octet
        sourceIP += buffer;
        sourceIP += ".";

        buffer = packet.get();  //Source IP 2nd Octet
        sourceIP += buffer;
        sourceIP += ".";

        buffer = packet.get();  //Source IP 3rd Octet
        sourceIP += buffer;
        sourceIP += ".";

        buffer = packet.get();  //Source IP 4th Octet
        sourceIP += buffer;

        Log.d(TAG, "Source IP:"+sourceIP);

        status += "   Source IP:"+sourceIP;

        String destIP  = "";
        buffer = packet.get();  //Destination IP 1st Octet
        destIP += buffer;
        destIP += ".";

        buffer = packet.get();  //Destination IP 2nd Octet
        destIP += buffer;
        destIP += ".";

        buffer = packet.get();  //Destination IP 3rd Octet
        destIP += buffer;
        destIP += ".";

        buffer = packet.get();  //Destination IP 4th Octet
        destIP += buffer;

        Log.d(TAG, "Destination IP:"+destIP);

        status += "   Destination IP:"+destIP;
        /*
        msgObj = mHandler.obtainMessage();
        msgObj.obj = status;
        mHandler.sendMessage(msgObj);
        */

        //Log.d(TAG, "version:"+packet.getInt());
        //Log.d(TAG, "version:"+packet.getInt());
        //Log.d(TAG, "version:"+packet.getInt());

    }
}
