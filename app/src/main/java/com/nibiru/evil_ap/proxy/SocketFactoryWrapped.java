package com.nibiru.evil_ap.proxy;

import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;

import javax.net.SocketFactory;

/**
 * Created by Nibiru on 2017-02-12.
 */

public class SocketFactoryWrapped extends SocketFactory {
    /**************************************CLASS FIELDS********************************************/
    protected final String TAG = getClass().getSimpleName();
    ProxyVpnService mProxyVPN;
    /**************************************CLASS METHODS*******************************************/
    public SocketFactoryWrapped(ProxyVpnService proxyVpnService) {
        mProxyVPN = proxyVpnService;
    }

    //Wrapped socket factory to avoid VPN loop, protect all outgoing sockets
    @Override
    public Socket createSocket(String host, int port) throws IOException {
        InetAddress address = InetAddress.getByName(host);
        Socket socket = new Socket( address.getHostAddress(), port );
        mProxyVPN.protect(socket);
        return socket;
    }

    @Override
    public Socket createSocket(String host, int port, InetAddress localHost, int localPort) throws IOException {
        InetAddress address = InetAddress.getByName(host);
        Socket socket = new Socket( address.getHostAddress(), port );
        mProxyVPN.protect(socket);
        return socket;
    }

    @Override
    public Socket createSocket(InetAddress host, int port) throws IOException {
        Socket socket = new Socket( host, port );
        mProxyVPN.protect(socket);
        return socket;
    }

    @Override
    public Socket createSocket(InetAddress address, int port, InetAddress localAddress, int localPort) throws IOException {
        Socket socket = new Socket( address, port );
        mProxyVPN.protect(socket);
        return socket;
    }
}