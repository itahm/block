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
import org.snmp4j.smi.Address;
import org.snmp4j.smi.Integer32;
import org.snmp4j.smi.OID;
import org.snmp4j.smi.OctetString;
import org.snmp4j.smi.UdpAddress;
import org.snmp4j.smi.VariableBinding;

import com.itahm.json.JSONObject;
import com.itahm.util.Listener;

public class SeedNode implements Runnable {
	public static final int TIMEOUT = 10000;
	
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
	
		this.thread.setName("ITAhM TempNode");
		//this.thread.setDaemon(true);
	}
	
	public void addEventListener(Listener listener) {
		this.listenerList.add(listener);
	}
	
	public void removeEventListener(Listener listener) {
		this.listenerList.remove(listener);
	}

	public void fireEvent(Object ...args) {
		for (Listener listener: this.listenerList) {
			listener.onEvent(this, args);
		}
	}
	
	public void test(Protocol protocol) {
		test(protocol, null);
	}
	
	public void test(Protocol protocol, Snmp snmp, JSONObject ...args) {
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
					
					for (JSONObject profile : args) {
						switch(profile.getString("version").toLowerCase()) {
						case "v3":
							target = new UserTarget<>();
							
							target.setSecurityName(new OctetString(profile.getString("user")));
							target.setSecurityLevel(profile.getInt("level"));
							
							request = new ScopedPDU();
							
							version = SnmpConstants.version3;
							
							break;
						case "v2c":
							target = new CommunityTarget<>();
								
							((CommunityTarget<UdpAddress>)target).setCommunity(new OctetString(profile.getString("community")));
							
							request = new PDU();
							
							version = SnmpConstants.version2c;
							
							break;
							
						default:
							target = new CommunityTarget<>();
							
							((CommunityTarget<UdpAddress>)target).setCommunity(new OctetString(profile.getString("community")));
							
							request = new PDU();
							
							version = SnmpConstants.version1;	
						}
						
						target.setVersion(version);
						target.setRetries(0);
						target.setTimeout(TIMEOUT);
						
						request.setType(PDU.GETNEXT);
						request.add(new VariableBinding(new OID(new int [] {1,3,6,1,2,1})));
						
						udp = new UdpAddress(profile.getInt("udp"));
							
						try {
							udp.setInetAddress(InetAddress.getByName(ip));
							
							target.setAddress(udp);
							
							request.setRequestID(new Integer32(0));
							
							if (onResponse(snmp.send(request, target))) {
								fireEvent(protocol, profile.getString("name"));
								
								return;
							}
						} catch (IOException ioe) {
							System.err.print(ioe);
						}
					}

					fireEvent(protocol, null);
				}
				
				private boolean onResponse(ResponseEvent<UdpAddress> event) {
					Object source = event.getSource();
					PDU response = event.getResponse();
					Address address = event.getPeerAddress();
					
					return (event != null &&
						!(source instanceof Snmp.ReportHandler) &&
						(address instanceof UdpAddress) &&
						((UdpAddress)address).getInetAddress().getHostAddress().equals(ip) &&
						response != null &&
						response.getErrorStatus() == SnmpConstants.SNMP_ERROR_SUCCESS);
				}
			};
		}
		
		this.thread.start();
	}
	
	@Override
	public void run() {
		this.target.test();
	}
	
	
	
	public static void main(String ...args) {
		SeedNode t = new SeedNode(0, "192.168.100.20");
		
		t.addEventListener(new Listener() {

			@Override
			public void onEvent(Object caller, Object... event) {
				System.out.println(caller);
				System.out.println(event[0]);
				System.out.println(event[1]);
			}
			
		});
		
		t.test(Protocol.ICMP);
	}
	
}
