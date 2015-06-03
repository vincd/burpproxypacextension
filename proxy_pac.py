# -*- coding: utf-8 -*-

from burp import ITab, IBurpExtender, IExtensionStateListener

from javax.swing import JTable, JPanel, JSplitPane, JScrollPane, JButton, JTextField, JToggleButton
from javax.swing.table import AbstractTableModel
from java.awt.event import ActionListener

from java.io import PrintWriter
from java.net import URI, Proxy
from java.util import List, ArrayList

import socket
import urlparse
import threading
from select import select
from httplib import HTTPResponse
from SocketServer import ThreadingMixIn
from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler

import sys
from os import listdir
from os.path import join

extends_jars = lambda path: [join(path, jar) for jar in listdir(path) if jar.endswith(".jar")]
sys.path.extend(extends_jars(sys.path[-1]))

from com.btr.proxy.selector.pac import PacProxySelector, UrlPacScriptSource

NET_TIMEOUT = 5
BUFLEN = 4066

EXTENSION_NAME = "Proxy PAC"
TAB_CAPTION = "Proxy PAC"
DEFAULT_PROXY_PAC_HOST = "localhost"
DEFAULT_PROXY_PAC_PORT = 9090

# pipe two sockets
def pipe_sockets(s1, s2):
    count = 0

    while count < NET_TIMEOUT:
        count += 1
        socks = [s1, s2]
        (recv, _, error) = select(socks, [], socks, 1)

        if error: break

        if recv:
            count = 0
            for s in recv:
                data = s.recv(BUFLEN)

                if len(data) > 0:
                    if s == s1:
                        s2.send(data)
                    else:
                        s1.send(data)

# custom exception when HTTP scheme is not supported
class UnsupportedSchemeException(Exception):
    pass

# proxy handler class for every incoming HTTP request
class ProxyHandler(BaseHTTPRequestHandler):
    def __init__(self, request, client_address, server):
        # is the request CONNECT
        self._is_connect = False
        # is the proxy DIRECT
        self._is_direct = True

        BaseHTTPRequestHandler.__init__(self, request, client_address, server)

    def _connect_to_host(self):
        # Get hostname and port to connect to
        if self._is_connect:
            self._hostname, self._port = self.path.split(':')
            self._path = '/'
        else:
            u = urlparse.urlparse(self.path)
            if u.scheme != 'http':
                raise UnsupportedSchemeException('Unknown scheme %s' % repr(u.scheme))

            self._hostname = u.hostname
            self._port = u.port or 80
            self._path = urlparse.urlunparse(
                urlparse.ParseResult(
                    scheme='',
                    netloc='',
                    params=u.params,
                    path=u.path or '/',
                    query=u.query,
                    fragment=u.fragment
                )
            )

        # find the proxy to connect to
        proxies = self.server._extender.find_proxy(self.path)
        # create a new socket
        self._proxy_sock = socket.socket()
        self._proxy_sock.settimeout(10)

        for proxy in proxies:
            # try to connect to the first accessible proxy
            try:
                if proxy.type() == Proxy.Type.DIRECT:
                    self._is_direct = True
                    self._proxy_sock.connect((self._hostname, int(self._port)))
                    self.server._extender.log_selected_proxy(self.path, "DIRECT")
                else:
                    self._is_direct = False
                    self._proxy_sock.connect((proxy.address().getHostName(), proxy.address().getPort()))
                    self.server._extender.log_selected_proxy(self.path, "%s:%s" % (proxy.address().getHostName(), proxy.address().getPort()))

                break
            except:
                pass

    # handles CONNECT HTTP requests
    def do_CONNECT(self):
        self._is_connect = True
        self._connect_to_host()

        if self._is_direct:
            # if the proxy is direct, then we should tell the client that the connection is successfull
            self.send_response(200, 'Connection established')
            self.end_headers()
        else:
            # if we connect to an other proxy, then just send packets
            req = self._build_request()
            self._proxy_sock.sendall(req)

        # act as a "passe-through"
        pipe_sockets(self.request, self._proxy_sock)

    # handles HTTP requests
    def do_COMMAND(self):
        if not self._is_connect:
            try:
                self._connect_to_host()
            except Exception, e:
                self.send_error(500, str(e))
                return

        req = self._build_request()
        self._proxy_sock.sendall(req)

        h = HTTPResponse(self._proxy_sock)
        h.begin()

        del h.msg['Transfer-Encoding']

        res = '%s %s %s\r\n' % (self.request_version, h.status, h.reason)
        res += '%s\r\n' % h.msg
        res += h.read()

        h.close()

        self.request.sendall(res)
        pipe_sockets(self.request, self._proxy_sock)
        self._proxy_sock.close()

    # rebuild the HTTP request
    def _build_request(self):
        req = '%s %s %s\r\n' % (self.command, self.path, self.request_version)
        req += '%s\r\n' % self.headers

        if 'Content-Length' in self.headers:
            req += self.rfile.read(int(self.headers['Content-Length']))

        return req

    def __getattr__(self, item):
        if item.startswith('do_'):
            return self.do_COMMAND

# This classe is a HTTP Server, that handle request as a proxy
class HTTPProxy(HTTPServer):
    def __init__(self, extender, server_address, RequestHandlerClass=ProxyHandler, bind_and_activate=True):
        HTTPServer.__init__(self, server_address, RequestHandlerClass)
        # add extender to get proxy infos and logger
        self._extender = extender

# Threaded HTTP proxy server
class ThreadedHTTPProxyServer(ThreadingMixIn, HTTPProxy):
    daemon_threads = True
    allow_reuse_address = True

# A Proxy class that start and stop the server
class ProxyServer():
    def __init__(self, extender, address):
        self._address = address
        self._extender = extender

    def start(self):
        self._proxyServer = ThreadedHTTPProxyServer(self._extender, self._address)

        self._server_thread = threading.Thread(target=self._proxyServer.serve_forever)
        self._server_thread.start()

    def stop(self):
        self._proxyServer.server_close()
        try:
            self._proxyServer.shutdown()
        except:
            pass

# custom JTable to log HTTP requests and their proxies
class Table(JTable):
    def __init__(self, extender):
        self._extender = extender
        self.setModel(extender)

class LogEntry:
    def __init__(self, count, url, destination):
        self._count = count
        self._url = url
        self._destination = destination

# Custom Tab to configure the proxy
class ProxyPacTab(ITab, ActionListener, AbstractTableModel):
    BUTTON_START = "Start proxy PAC"
    BUTTON_STOP = "Stop proxy PAC"
    BUTTON_LOAD_PAC = "Load PAC file"

    # columns on the log Table
    COLUMN_NAME = ("No", "URL", "Destination")

    def __init__(self, caption, extender):
        self._caption = caption
        self._extender = extender

        # create the log and a lock on which to synchronize when adding log entries
        self._log = ArrayList()
        self._lock = threading.Lock()

        self._build_ui_component()

    def getTabCaption(self):
        return self._caption

    def getUiComponent(self):
        return self._splitpane

    # event called when a button is clicked
    def actionPerformed(self, e):
        if e.getActionCommand() == self.BUTTON_START:
            # this is the start proxy button
            if self._extender.start_pac_server(self._text_host.getText(), int(self._text_port.getText())):
                self._start_button.setText(self.BUTTON_STOP)
            else:
                # the proxy failed to start, so we don't selecte it
                self._start_button.setSelected(True)
        elif e.getActionCommand() == self.BUTTON_STOP:
            # this is the stop proxy button
            self._extender.stop_pac_server()
            self._start_button.setText(self.BUTTON_START)
        elif e.getActionCommand() == self._button_load_pac.getText():
            # this is the load PAC button
            self._extender.load_pac(self._text_pac_path.getText())

    def getRowCount(self):
        return self._log.size()

    def getColumnCount(self):
        return len(self.COLUMN_NAME)

    def getColumnName(self, columnIndex):
        return self.COLUMN_NAME[columnIndex] if columnIndex < self.getColumnCount() else ""

    def getValueAt(self, rowIndex, columnIndex):
        logEntry = self._log.get(rowIndex)

        if logEntry:
            if columnIndex == 0:
                return str(logEntry._count)
            elif columnIndex == 1:
                return logEntry._url
            elif columnIndex == 2:
                return logEntry._destination

        return ""

    def log_url(self, url, destination):
        self._lock.acquire()
        row = self._log.size()
        self._log.add(LogEntry(row, url, destination))
        self.fireTableRowsInserted(row, row)
        self._lock.release()

    def set_proxy_host(self, host):
        self._text_host.setText(host)

    def set_proxy_port(self, port):
        self._text_port.setText(str(port))

    def set_proxy_pac_path(self, path):
        self._text_pac_path.setText(path)

    # build the UI
    def _build_ui_component(self):
        self._splitpane = JSplitPane(JSplitPane.VERTICAL_SPLIT)

        logTable = Table(self)
        scrollPane = JScrollPane(logTable)
        self._splitpane.setLeftComponent(scrollPane)

        panelOptions = JPanel()

        panelProxy = JPanel()
        panelOptions.add(panelProxy)

        panelPac = JPanel()
        panelOptions.add(panelPac)

        self._start_button = JToggleButton(self.BUTTON_START)
        self._start_button.addActionListener(self)
        self._text_host = JTextField(15)
        self._text_host.setText("")
        self._text_port = JTextField(5)
        self._text_port.setText("")

        panelProxy.add(self._start_button)
        panelProxy.add(self._text_host)
        panelProxy.add(self._text_port)

        self._button_load_pac = JButton(self.BUTTON_LOAD_PAC)
        self._button_load_pac.addActionListener(self)
        self._text_pac_path = JTextField(40)
        self._text_pac_path.setText("")

        panelPac.add(self._button_load_pac)
        panelPac.add(self._text_pac_path)

        self._splitpane.setRightComponent(panelOptions)

        map(self._extender._callbacks.customizeUiComponent, [
            self._splitpane, logTable, scrollPane,
            panelOptions, panelProxy, panelPac,
            self._start_button, self._button_load_pac,
            self._text_host, self._text_port, self._text_pac_path
        ])

# THE Burp Extender class!
class BurpExtender(IBurpExtender, IExtensionStateListener):
    EXTENSION_SAVE_HOST = "ProxyPacHostname"
    EXTENSION_SAVE_PORT = "ProxyPacPort"
    EXTENSION_SAVE_PAC_PATH = "PacPath"
    EXTENSION_CHECK_INFINITE_LOOP = "InfiteLoop"

    # main function, we init stuff like proxy address and PAC path
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._stdout = PrintWriter(callbacks.getStdout(), True)

        callbacks.setExtensionName(EXTENSION_NAME)
        callbacks.registerExtensionStateListener(self)

        self._proxy_pac_tab = ProxyPacTab(TAB_CAPTION, self)
        callbacks.addSuiteTab(self._proxy_pac_tab)

        self._pac_server = None
        self._proxy_pac_host = self._callbacks.loadExtensionSetting(self.EXTENSION_SAVE_HOST)
        if not self._proxy_pac_host: self._proxy_pac_host = DEFAULT_PROXY_PAC_HOST
        self._proxy_pac_tab.set_proxy_host(self._proxy_pac_host)

        self._proxy_pac_port = self._callbacks.loadExtensionSetting(self.EXTENSION_SAVE_PORT)
        if not self._proxy_pac_port: self._proxy_pac_port = DEFAULT_PROXY_PAC_PORT
        self._proxy_pac_tab.set_proxy_port(self._proxy_pac_port)

        pac_path = self._callbacks.loadExtensionSetting(self.EXTENSION_SAVE_PAC_PATH)
        self._pac_proxy_selector = None

        if pac_path:
            self._proxy_pac_tab.set_proxy_pac_path(pac_path)
            self.load_pac(pac_path)

        self.log("%s successfully loaded!" % EXTENSION_NAME)
        self.log("Check upstream proxy configuration to add proxy to %s:%s" % (self._proxy_pac_host, self._proxy_pac_port))

    # log a message
    def log(self, *args):
        self._stdout.println(" ".join(args))

    # add a message to the Alert tab
    def alert(self, *args):
        self._callbacks.issueAlert(" ".join(args))

    # start the proxy server
    # if we succed then, we remember the proxy address
    def start_pac_server(self, host, port):
        self.stop_pac_server()

        self._pac_server = ProxyServer(self, (host, port))
        try:
            self._pac_server.start()
            self.alert("PAC service started on %s:%s" % (self._proxy_pac_host, self._proxy_pac_port))
        except socket.error, e:
            self.alert("%s:%s address already in use" % (self._proxy_pac_host, self._proxy_pac_port))
            return False

        # save proxy address
        self._proxy_pac_host = host
        self._proxy_pac_port = port
        self._callbacks.saveExtensionSetting(self.EXTENSION_SAVE_HOST, host)
        self._callbacks.saveExtensionSetting(self.EXTENSION_SAVE_PORT, str(port))

        return True

    # stop the proxy server
    def stop_pac_server(self):
        if self._pac_server:
            self._pac_server.stop()
            self.alert("PAC service stoped on %s:%s" % (self._proxy_pac_host, self._proxy_pac_port))
            self._pac_server = None

    # function called when the extension is unload
    # stop the proxy server
    def extensionUnloaded(self):
        self.stop_pac_server()

    # load a new PAC file from an URI (path or URL)
    def load_pac(self, path):
        try:
            self._pac_proxy_selector = PacProxySelector(UrlPacScriptSource(path))
        except:
            self.alert("An error occured while loading PAC file...")

        self.alert("PAC file %s successfully loaded" % path)
        self._callbacks.saveExtensionSetting(self.EXTENSION_SAVE_PAC_PATH, path)

    def log_selected_proxy(self, path, destination):
        self._proxy_pac_tab.log_url(path, destination)

    # find the proxy, if there is no available proxy then return a NO_PROXY object
    # this object mean a DIRECT connection
    def find_proxy(self, url):
        if self._pac_proxy_selector:
            return self._pac_proxy_selector.select(URI(url))
        else:
            return [Proxy.NO_PROXY]
