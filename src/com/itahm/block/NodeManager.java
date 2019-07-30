package com.itahm.block;

import java.io.IOException;
import java.util.Iterator;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.snmp4j.Snmp;
import org.snmp4j.mp.MPv3;
import org.snmp4j.mp.SnmpConstants;
import org.snmp4j.security.AuthMD5;
import org.snmp4j.security.AuthSHA;
import org.snmp4j.security.PrivDES;
import org.snmp4j.security.SecurityLevel;
import org.snmp4j.security.SecurityModels;
import org.snmp4j.security.SecurityProtocols;
import org.snmp4j.security.USM;
import org.snmp4j.security.UsmUser;
import org.snmp4j.smi.OID;
import org.snmp4j.smi.OctetString;
import org.snmp4j.smi.Variable;
import org.snmp4j.transport.DefaultUdpTransportMapping;

import com.itahm.block.command.Commander;
import com.itahm.block.node.Event;
import com.itahm.block.node.ICMPNode;
import com.itahm.block.node.Node;
import com.itahm.block.node.SNMPDefaultNode;
import com.itahm.block.node.SNMPV3Node;
import com.itahm.block.node.TCPNode;
import com.itahm.json.JSONObject;
import com.itahm.util.Listener;

public class NodeManager extends Snmp implements Listener {

	private final Commander agent;
	private final Map<Long, Node> nodeList = new ConcurrentHashMap<>();
	private Boolean isClosed = false;
	
	public NodeManager(Commander commander) throws IOException {
		super(new DefaultUdpTransportMapping());
		
		agent = commander;
		
		SecurityModels.getInstance()
			.addSecurityModel(new USM(SecurityProtocols.getInstance(), new OctetString(MPv3.createLocalEngineID()), 0));
	}
	
	public void stop() throws IOException {
		synchronized(this.isClosed) {
			if (this.isClosed) {
				return;
			}
		
			System.out.println("Stop Node manager.");
			
			for (Iterator<Long> it = this.nodeList.keySet().iterator(); it.hasNext(); ) {
				this.nodeList.get(it.next()).close(true);
				
				it.remove();
				
				System.out.print("-");
			}
			
			System.out.println();
			
			super.getUSM().removeAllUsers();
			
			super.close();
		}
	}
	
	public void addUSMUser(JSONObject profile) {
		switch (profile.getInt("level")) {
		case SecurityLevel.AUTH_PRIV:
			super.getUSM().addUser(new UsmUser(new OctetString(profile.getString("user")),
				profile.has("sha")? AuthSHA.ID: AuthMD5.ID,
				new OctetString(profile.getString(profile.has("sha")? "sha": "md5")),
				PrivDES.ID,
				new OctetString(profile.getString("des"))));
			
			break;
		case SecurityLevel.AUTH_NOPRIV:
			super.getUSM().addUser(new UsmUser(new OctetString(profile.getString("user")),
				profile.has("sha")? AuthSHA.ID: AuthMD5.ID,
				new OctetString(profile.getString(profile.has("sha")? "sha": "md5")),
				null, null));
			
			break;
		default:
			super.getUSM().addUser(new UsmUser(new OctetString(profile.getString("user")),
				null, null, null, null));	
		}
	}
	
	public void removeUSMUser(String user) {
		super.getUSM().removeAllUsers(new OctetString(user));
	}
	
	public void removeNode(long id) {
		Node node = this.nodeList.remove(id);
		
		if (node != null) {
			node.close();
		}
	}
	
	public void createNode(JSONObject monitor) throws IOException {
		Node node = null;
		long id = monitor.getLong("id");
		String 
			protocol = monitor.getString("protocol"),
			ip = monitor.getString("ip");
		
		switch (protocol) {
		case "icmp":
			node = new ICMPNode(id, ip);
			
			break;
		case "tcp":
			node = new TCPNode(id, ip);
			
			break;
		default:
			JSONObject profile = agent.getProfileByName(protocol);
			
			switch(profile.getString("version")) {
			case "v3":
				node = new SNMPV3Node(this, id, ip,
					profile.getInt("udp"),
					profile.getString("user"),
					profile.getInt("level"));
				
				break;
			case "v2c":
				node = new SNMPDefaultNode(this, id, ip,
					profile.getInt("udp"),
					profile.getString("community"));
				
				break;
			default:
				node = new SNMPDefaultNode(this, id, ip,
					profile.getInt("udp"),
					profile.getString("community"),
					SnmpConstants.version1);
			}
		}
		
		if (node != null) {
			this.nodeList.put(id, node);
			
			node.addEventListener(this);
			
			//node.setHealth();
			node.ping(0);
		}
	}
	

	@Override
	public void onEvent(Object caller, Object... args) {
		if (caller instanceof Node) {
			switch ((Event)args[0]) {
			case PING:
				onPingEvent((Node)caller, (long)args[1]);
				
				break;
			case SNMP:
				onSNMPEvent((Node)caller, (int)args[1]);
				
				break;
			case RESOURCE:
				onResourceEvent((Node)caller, (OID)args[1], (OID)args[2], (Variable)args[3]);
				
				break;
			}
		}
	}
	
	private void onPingEvent(Node node, long rtt) {
		if (this.agent.action01(node.id, rtt)) {
			node.ping(rtt > -1? 1/* TODO snmpInterval*/: 0);
		}
	}
	
	private void onSNMPEvent(Node node, int status) {
		this.agent.action02(node.id, status);
	}
	
	private void onResourceEvent(Node node, OID oid, OID index, Variable variable) {
		this.agent.action03(node.id, oid, index, variable);
	}

}
