import nmap

target=input("Введите IP-адрес для сканирования")
def nmap_scan(target):
    nm = nmap.PortScanner()
    nm.scan(hosts=target, arguments='-sP')


    for host in nm.all_hosts():
        print('Host: %s (%s)' % (host, nm[host].hostname()))
        print('State: %s' % nm[host].state())

        for proto in nm[host].all_protocols():
            print('Protocol: %s' % proto)

            lport = nm[host][proto].keys()
            lport = sorted(lport)
            for port in lport:
                print('port : %ststate : %s' % (port, nm[host][proto][port]['state']))

print('Сканирование завершено')    