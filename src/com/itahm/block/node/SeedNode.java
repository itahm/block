package com.itahm.block.node;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.util.ArrayList;

import org.snmp4j.CommunityTarget;
import org.snmp4j.PDU;
import org.snmp4j.ScopedPDU;
import org.snmp4j.Snmp;
import org.snmp4j.Target;
import org.snmp4j.UserTarget;
import org.snmp4j.event.ResponseEvent;
import org.snmp4j.mp.SnmpConstants;
import org.snmp4j.smi.Integer32;
import org.snmp4j.smi.OID;
import org.snmp4j.smi.OctetString;
import org.snmp4j.smi.UdpAddress;
import org.snmp4j.smi.VariableBinding;

import com.itahm.util.Listenable;
import com.itahm.util.Listener;

public class SeedNode implements Runnable, Listenable {
	public static final int TIMEOUT = 5000;
	
	public enum Protocol {
		ICMP, TCP, SNMP;
	}
	
	interface Testable {
		public void test();
	}
	
	public final long id;
	public final String ip;
	public String profileName;
	private final ArrayList<Listener> listenerList = new ArrayList<>();
	private final Thread thread;
	private Testable target;
	
	public SeedNode(long id, String ip) {
		this.id = id;
		this.ip = ip;
		
		this.thread  = new Thread(this);
	
		this.thread.setName("ITAhM SeedNode");
		this.thread.setDaemon(true);
	}
	
	@Override
	public void addEventListener(Listener listener) {
		this.listenerList.add(listener);
	}
	
	@Override
	public void removeEventListener(Listener listener) {
		this.listenerList.remove(listener);
	}

	@Override
	public void fireEvent(Object ...args) {
		for (Listener listener: this.listenerList) {
			listener.onEvent(this, args);
		}
	}
	
	public void test(Protocol protocol) {
		test(protocol, null);
	}
	
	public void test(Protocol protocol, Snmp snmp, Arguments ...args) {
		switch(protocol) {
		case ICMP:
			this.target = new Testable() {

				@Override
				public void test() {
					try {
						if (InetAddress.getByName(ip).isReachable(TIMEOUT)) {
							fireEvent(protocol, true);
							
							return;
						};
					} catch (IOException e) {
					}
					
					fireEvent(protocol, false);
				}
			};
			
			break;
		case TCP:
			this.target = new Testable() {

				@Override
				public void test() {
					String [] address = ip.split(":");
					
					if (address.length == 2) {
						try (Socket socket = new Socket()) {
							socket.connect(new InetSocketAddress(
								InetAddress.getByName(address[0]),
								Integer.parseInt(address[1])), TIMEOUT);
							
							fireEvent(protocol, true);
							
							return;
						} catch (IOException ioe) {
						}
					}
					
					fireEvent(protocol, false);
				}
				
			};
			
			break;
		case SNMP:
			this.target = new Testable() {

				@Override
				public void test() {
					Target<UdpAddress> target;
					PDU request;
					UdpAddress udp;
					int version;
					
					for (Arguments argument : args) {
						switch(argument.version.toUpperCase()) {
						case "V3":
							target = new UserTarget<>();
							
							target.setSecurityName(new OctetString(argument.security));
							target.setSecurityLevel(argument.level);
							
							request = new ScopedPDU();
							
							version = SnmpConstants.version3;
							
							break;
						case "V2C":
							target = new CommunityTarget<>();
								
							((CommunityTarget<UdpAddress>)target).setCommunity(new OctetString(argument.security));
							
							request = new PDU();
							
							version = SnmpConstants.version2c;
							
							break;
							
						default:
							target = new CommunityTarget<>();
							
							((CommunityTarget<UdpAddress>)target).setCommunity(new OctetString(argument.security));
							
							request = new PDU();
							
							version = SnmpConstants.version1;	
						}
						
						target.setVersion(version);
						target.setTimeout(TIMEOUT);
						target.setRetries(0);
						
						request.setType(PDU.GETNEXT);
						request.add(new VariableBinding(new OID("1.3.6.1.2.1")));
						request.setRequestID(new Integer32(0));
						
						udp = new UdpAddress(argument.port);
							
						try {
							udp.setInetAddress(InetAddress.getByName(ip));
							
							target.setAddress(udp);
							
							if (onResponse(snmp.send(request, target))) {
								fireEvent(protocol, argument.name);
									
								return;
							}
						} catch (IOException ioe) {
							ioe.printStackTrace();
						}
					}
					
					fireEvent(protocol, null);
				}
				
				private boolean onResponse(ResponseEvent<UdpAddress> event) {
					if (event == null) {
						return false;
					}
					
					Object source = event.getSource();
					
					if (source instanceof Snmp.ReportHandler) {
						return false;
					}
					
					PDU response = event.getResponse();
					
					if (response == null) {
						return false;
					}
					
					else if (!((event.getPeerAddress() instanceof UdpAddress))) {
						return false;
					}
					
					if (response.getErrorStatus() != SnmpConstants.SNMP_ERROR_SUCCESS) {
						return false;
					}
					
					return true;
				}
			};
		}
		
		this.thread.start();
	}
	
	@Override
	public void run() {
		this.target.test();
	}

	public static class Arguments {
		private final int port;
		private final String version;
		private final int level;
		private final String security;
		private final String name;
		
		public Arguments(String name, int port, String version, String security, int level) {
			this.name = name;
			this.port = port;
			this.version = version;
			this.security = security;
			this.level = level;
		}
	}
}
