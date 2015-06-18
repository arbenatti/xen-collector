#!/usr/bin/python

import XenAPI, re, json
from docopt import docopt
import urllib
from xml.dom import minidom
from xml.parsers.expat import ExpatError
from RRDUpdates import RRDUpdates

def main():
	usage="""
Usage:
    xen-collector.py [options] -m <method> -V <host>

Options:
    -h, --help                                  Display this usage info
    -v, --version                               Display version and exit
    -m <method>, --method <method>              The method to be processed during the client request
    -V <host>, --xen-host <host>            The vSphere host to send the request to
    -n <name>, --name <name>                    Name of the object, e.g. XEN hostname, datastore URL, etc.
    -p <properties>, --properties <properties>  Name of the property as defined by the vSphere Web SDK
    -k <key>, --key <key>                       Provide additional key for data filtering

Examples:
    xen-collector.py -m vm.discover -V vc01.example.org
    xen-collector.py -m vm.discover -V vc01.example.org -p runtime.powerState
    xen-collector.py -m vm.get -V vc01.example.org -n vm01.example.org -p summary.overallStatus
    xen-collector.py -m vm.diks.get -V vc01.example.org -n vm01.example.org -k /var
    xen-collector.py -m vm.process.get -V vc01.example.org -n vm01.example.org -U user -P pass

"""

	args = docopt(usage)

	msg = {
        	'method': args['--method'],
        	'hostname': args['--xen-host'],
		'name': args['--name'],
        	'properties': args['--properties'],
        	'key': args['--key'],
	}

	hostname, username, password = "192.168.10.1", "root", "server9090"
	session=XenAPI.Session('https://'+hostname)
	session.login_with_password(username, password)
	sx=session.xenapi
	rrd_updates = RRDUpdates()
	rrd_updates.refresh(session._session,{})

	getAll(sx, rrd_updates)

	if (msg['method'] == 'vm.get') and (msg['properties']):
		print vmget(sx, msg['hostname'], msg['name'], msg['properties'], msg['key'])
	if (msg['method'] == 'host.get') and (msg['properties']):
		print hostget(sx, msg['hostname'], msg['properties'], msg['key'])

	session.logout()

def getAll(xenHostSession, rrd_updates):
	global hostsList, perf_mon, host_perf_mon
	hostsList = {}
	perf_mon = {}
	host_perf_mon = {}
	for host in xenHostSession.host.get_all():
		vms = {}
		for vm in xenHostSession.host.get_resident_VMs(host):
			if not(xenHostSession.VM.get_is_control_domain(vm)):
				uuid = xenHostSession.VM.get_uuid(vm)
				perf_mon[uuid] = {}
				for param in rrd_updates.get_vm_param_list(uuid):
					perf_mon[uuid][param] = " ".join(["%s" % (rrd_updates.get_vm_data(uuid,param,row)) for row in range(rrd_updates.get_nrows())])

				vms[xenHostSession.VM.get_name_label(vm)] = vm

		hostsList[host] = vms
		for param in rrd_updates.get_host_param_list():
        		host_perf_mon[param] = " ".join(["%s" % (rrd_updates.get_host_data(param,row)) for row in range(rrd_updates.get_nrows())])

	return hostsList, perf_mon

def vmget(xenHostSession, xenhost, vm, prop, key):
	for host in hostsList.keys():
		if xenHostSession.host.get_hostname(host) == xenhost:
			if prop == 'powerState':
				return xenHostSession.VM.get_power_state(hostsList[host][vm])

			elif prop == 'memoryTotalMB':
				metrics = xenHostSession.VM.get_metrics(hostsList[host][vm])
				return (float(xenHostSession.VM_metrics.get_memory_actual(metrics))/1024)/1024

			elif prop == 'memoryFreeMB':
				if 'memory_internal_free' in perf_mon[xenHostSession.VM.get_uuid(hostsList[host][vm])]:
					return (float(perf_mon[xenHostSession.VM.get_uuid(hostsList[host][vm])]['memory_internal_free'])/1024)/1024

			elif prop == 'CPU.Total':
				metrics = xenHostSession.VM.get_metrics(hostsList[host][vm])
				return xenHostSession.VM_metrics.get_VCPUs_number(metrics)

			elif prop == 'CPU.Utilisation':
				metrics = xenHostSession.VM.get_metrics(hostsList[host][vm])
				cpu_total = xenHostSession.VM_metrics.get_VCPUs_number(metrics)
	#			cpu_info1 = []
				cpu_info = 0
				for i in range(int(cpu_total)):
					cpu = 'cpu%i' %i
					cpu_info += float(perf_mon[xenHostSession.VM.get_uuid(hostsList[host][vm])][cpu])
	#				cpu_info1.insert(i, perf_mon[xenHostSession.VM.get_uuid(hostsList[host][vm])][cpu])
	#			print cpu_info1
				return float(cpu_info)/(i+1)

			elif prop == 'OS':
				metrics = xenHostSession.VM.get_guest_metrics(hostsList[host][vm])
				try:
					return xenHostSession.VM_guest_metrics.get_os_version(metrics)['name']
				except:
					return None

			elif prop == 'net.discoverer':
				VIFs = xenHostSession.VM.get_VIFs(hostsList[host][vm])
				vifs = []
				i = 0
				for vif in VIFs:
					vifs.insert(i, {"{#VIFNAME}":"vif_"+xenHostSession.VIF.get_device(vif)})
					i+=1

				data = {"data":vifs}
				return json.dumps(data)

			elif prop == 'net.received':
				if key+'_rx' in perf_mon[xenHostSession.VM.get_uuid(hostsList[host][vm])]:
					return float(perf_mon[xenHostSession.VM.get_uuid(hostsList[host][vm])][key+'_rx'])

			elif prop == 'net.transmitted':
				if key+'_tx' in perf_mon[xenHostSession.VM.get_uuid(hostsList[host][vm])]:
					return float(perf_mon[xenHostSession.VM.get_uuid(hostsList[host][vm])][key+'_tx'])

			elif prop == 'disk.discoverer':
				VBDs = xenHostSession.VM.get_VBDs(hostsList[host][vm])
				vbds = []
				i = 0
				for vbd in VBDs:
					info_type = xenHostSession.VBD.get_type(vbd)
					if info_type != 'CD': vbds.insert(i, {"{#VBDNAME}":"vbd_"+xenHostSession.VBD.get_device(vbd)})
					i+=1

				data = {"data":vbds}
				return json.dumps(data)

			elif prop == 'disk.read':
				if key+'_read' in perf_mon[xenHostSession.VM.get_uuid(hostsList[host][vm])]:
					return float(perf_mon[xenHostSession.VM.get_uuid(hostsList[host][vm])][key+'_read'])

			elif prop == 'disk.write':
				if key+'_write' in perf_mon[xenHostSession.VM.get_uuid(hostsList[host][vm])]:
					return float(perf_mon[xenHostSession.VM.get_uuid(hostsList[host][vm])][key+'_write'])

def hostget(xenHostSession, xenhost, prop, key):
	for host in hostsList.keys():
		if xenHostSession.host.get_hostname(host) == xenhost:
			if prop == 'CPU.Total':
				return xenHostSession.host.get_cpu_info(host)['cpu_count']

			elif prop == 'CPU.Utilisation':
				return host_perf_mon['cpu_avg']

			elif prop == 'loadavg':
				return host_perf_mon['loadavg']

			elif prop == 'memoryTotalMB':
				return float(host_perf_mon['memory_total_kib'])/1024

			elif prop == 'memoryFreeMB':
				return float(host_perf_mon['memory_free_kib'])/1024

			elif prop == 'net.discoverer':
				PIFs = xenHostSession.host.get_PIFs(host)
                                pifs = []
                                i = 0
                                for pif in PIFs:
					device = xenHostSession.PIF.get_device(pif)
                                        pifs.insert(i, {"{#PIFNAME}":"pif_"+device})
                                        i+=1

                                data = {"data":pifs}
                                return json.dumps(data)

			elif prop == 'net.transmitted':
				if key+'_tx' in host_perf_mon:
					return float(host_perf_mon[key+'_tx'])

			elif prop == 'net.received':
				if key+'_rx' in host_perf_mon:
					return float(host_perf_mon[key+'_rx'])

if __name__ == '__main__':
	main()
