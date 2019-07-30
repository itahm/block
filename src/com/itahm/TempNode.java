package com.itahm;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;

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
import org.snmp4j.smi.OctetString;
import org.snmp4j.smi.UdpAddress;
import org.snmp4j.smi.VariableBinding;

import com.itahm.json.JSONObject;

public class TempNode {
	private final Thread thread;
	
	enum Protocol {
		ICMP, TCP, SNMP;
	}
	
	public static abstract class Tester implements Runnable {
		public final String id;
		public final String ip;
		
		public Tester (String id, String ip) {
			this.id = id;
			this.ip = ip;
		}
	}

	public TempNode(String id, String ip, Protocol protocol) {
		switch(protocol) {
		case ICMP:
			this.thread = new Thread(new ICMP(id, ip));
			
			break;
		case TCP:
			this.thread  = new Thread(new TCP(id, ip));
			
			break;
		case SNMP:
			this.thread  = new Thread(new SNMP(id, ip));
		
			break;
		default:
			this.thread  = null;
		}
		
		if (this.thread != null) {
			this.thread.setName("ITAhM TempNode");
			this.thread.setDaemon(true);
			this.thread.start();
		}
	}
	
	public static class TCP extends Tester {
		public TCP(String id, String ip) {
			super(id, ip);
		}

		@Override
		public void run() {
			String [] address = ip.split(":");
			
			if (address.length == 2) {
				try (Socket socket = new Socket()) {
					socket.connect(new InetSocketAddress(
						InetAddress.getByName(address[0]),
						Integer.parseInt(address[1])), Agent.Config.timeout());
					
					Agent.node().onDetect(this, true);
					
					return;
				} catch (IOException ioe) {
				}
			}
			
			try {
				Agent.node().onDetect(this, false);
			} catch (IOException ioe) {
				System.err.print(ioe);
			}
		}
	}
	
	public static class ICMP extends Tester {
		public ICMP(String id, String ip) {
			super(id, ip);
		}
		
		@Override
		public void run() {
			try {
				if (InetAddress.getByName(super.ip).isReachable(Agent.Config.timeout())) {
					Agent.node().onDetect(this, true);
					
					return;
				};
			} catch (IOException e) {
			}
			
			try {
				Agent.node().onDetect(this, false);
			} catch (IOException ioe) {
				System.err.print(ioe);
			}
		}
	}
	
	public static class SNMP extends Tester {
		public String profile;
		
		public SNMP(String id, String ip) {
			super(id, ip);
		}
		
		boolean onResponse(ResponseEvent event) {
			Object source = event.getSource();
			PDU response = event.getResponse();
			Address address = event.getPeerAddress();
			
			return (event != null &&
				!(source instanceof Snmp.ReportHandler) &&
				(address instanceof UdpAddress) &&
				((UdpAddress)address).getInetAddress().getHostAddress().equals(this.ip) &&
				response != null &&
				response.getErrorStatus() == SnmpConstants.SNMP_ERROR_SUCCESS);
		}
		
		@Override
		public void run() {
			JSONObject
				table = Agent.db().get("profile").json(),
				profile;
			Target target;
			PDU request;
			String name;
			UdpAddress udp;
			int version;
			
			for (Object key : table.keySet()) {
				name = (String)key;
				
				profile = table.getJSONObject(name);
				
				switch(profile.getString("version").toLowerCase()) {
				case "v3":
					target = new UserTarget();
					
					target.setSecurityName(new OctetString(profile.getString("user")));
					target.setSecurityLevel(profile.getInt("level"));
					
					request = new ScopedPDU();
					
					version = SnmpConstants.version3;
					
					break;
				case "v2c":
					target = new CommunityTarget();
						
					((CommunityTarget)target).setCommunity(new OctetString(profile.getString("community")));
					
					request = new PDU();
					
					version = SnmpConstants.version2c;
					
					break;
					
				default:
					target = new CommunityTarget();
					
					((CommunityTarget)target).setCommunity(new OctetString(profile.getString("community")));
					
					request = new PDU();
					
					version = SnmpConstants.version1;	
				}
				
				target.setVersion(version);
				target.setRetries(0);
				target.setTimeout(Agent.Config.timeout());
				
				request.setType(PDU.GETNEXT);
				request.add(new VariableBinding(ITAhMNode.OID_mib2));
				
				udp = new UdpAddress(profile.getInt("udp"));
					
				try {
					udp.setInetAddress(InetAddress.getByName(this.ip));
					
					target.setAddress(udp);
					
					request.setRequestID(new Integer32(0));
					
					if (onResponse(Agent.node().send(request, target))) {
						this.profile = name;
						
						Agent.node().onDetect(this, true);
						
						return;
					}
				} catch (IOException ioe) {
					System.err.print(ioe);
				}
			}
	
			try {
				Agent.node().onDetect(this, false);
			} catch (IOException ioe) {
				System.err.print(ioe);
			}
		}
	}
	
}
