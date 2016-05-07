from socket import *
import optparse
import threading
import nmap

screenLock = threading.Semaphore(value = 1)

def nmapScan(tgtHost, tgtPort):
    try:
        nmScan = nmap.PortScanner()

        screenLock.acquire()

        nmScan.scan(hosts=tgtHost, ports=tgtPort)
        state = nmScan[tgtHost]['tcp'][int(tgtPort)]['state']

        print "[*] nmap scan on: " + tgtHost + " tcp/" + tgtPort + " " + state
    finally:
        screenLock.release()

def connScan(tgtHost, tgtPort):
    try:
        connSkt = socket(AF_INET, SOCK_STREAM)
        connSkt.connect( (tgtHost, tgtPort) )
        connSkt.send('Violent Python\r\n')
        results = connSkt.recv(100)

        screenLock.acquire();
        print '[+]%d/tcp open' % tgtPort
        print '[+] ' + str(results)
        
    except:
        screenLock.acquire();
        print '[-]%d/tcp closed'% tgtPort
    finally:
        screenLock.release();
        connSkt.close()

def portScan(tgtHost, tgtPorts):
    try:
        tgtIP = gethostbyname(tgtHost)
    except:
        screenLock.acquire();
        print "[-] Cannot resolve '%s': Unknown host" % tgtHost
        screenLock.release();
        return

    try:
        tgtName = gethostbyaddr(tgtIP)

        screenLock.acquire();
        print '\n[+] Scan Results for: ' + tgtName[0]
        screenLock.release();
    except:
        screenLock.acquire();
        print '\n[+] Scan Results for: ' + tgtIP
        screenLock.release();


    setdefaulttimeout(1)
    for tgtPort in list(tgtPorts):
        t = threading.Thread(target=connScan, args=(tgtHost, int(tgtPort)))
        t.start()

        nmt = threading.Thread(target=nmapScan, args=(tgtHost, int(tgtPort)))
        nmt.start()


def main():
    parser = optparse.OptionParser('usage %prog -H <target host> -p <target port>')
    parser.add_option('-H', dest='tgtHost', type='string', help='string host')
    parser.add_option('-p', dest='tgtPort', type='string', help='string: comma separated list of ports')

    (options, args) = parser.parse_args()
    tgtHost = options.tgtHost
    tgtPorts = str(options.tgtPort).split(',')

    if (tgtHost == None) | (tgtPorts[0] == None):
        screenLock.acquire();
        print 'ya fanny'
        screenLock.release();
        exit(0)

    portScan(tgtHost, tgtPorts)

main();