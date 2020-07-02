package com.itahm.nms;

import java.io.Closeable;
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

import com.itahm.nms.node.Event;
import com.itahm.nms.node.ICMPNode;
import com.itahm.nms.node.Node;
import com.itahm.nms.node.SNMPDefaultNode;
import com.itahm.nms.node.SNMPV3Node;
import com.itahm.nms.node.SeedNode;
import com.itahm.nms.node.TCPNode;
import com.itahm.nms.node.SeedNode.Arguments;
import com.itahm.nms.node.SeedNode.Protocol;
import com.itahm.service.NMS;
import com.itahm.util.Listener;

public class NodeManager extends Snmp implements Listener, Closeable {
	
	private final NodeEventReceivable agent;
	private final Map<Long, Node> nodeMap = new ConcurrentHashMap<>();
	private Boolean isClosed = false;
	private long interval;
	private int retry;
	private int timeout;
	
	public NodeManager(NodeEventReceivable agent, long interval, int timeout, int retry) throws IOException {
		super(new DefaultUdpTransportMapping());
		
		this.agent = agent;
		
		this.interval = interval;
		this.retry = retry;
		this.timeout = timeout;
		
		SecurityModels.getInstance()
			.addSecurityModel(new USM(SecurityProtocols.getInstance(), new OctetString(MPv3.createLocalEngineID()), 0));
		
		super.listen();
		
		System.out.println("NodeManager up.");
	}
	
	public void addUSMUser(String user, int level, String authProtocol, String authKey, String privProtocol, String privKey) {
		switch (level) {
		case SecurityLevel.AUTH_PRIV:
			super.getUSM().addUser(new UsmUser(new OctetString(user),
				authProtocol.equals("sha")? AuthSHA.ID: AuthMD5.ID,
				new OctetString(authKey),
				PrivDES.ID,
				new OctetString(privKey)));
			
			break;
		case SecurityLevel.AUTH_NOPRIV:
			super.getUSM().addUser(new UsmUser(new OctetString(user),
					authProtocol.equals("sha")? AuthSHA.ID: AuthMD5.ID,
				new OctetString(authKey),
				null, null));
			
			break;
		default:
			super.getUSM().addUser(new UsmUser(new OctetString(user),
				null, null, null, null));	
		}
	}
	
	@Override
	public void close() throws IOException {
		synchronized(this.isClosed) {
			if (this.isClosed) {
				return;
			}
		
			super.close();
			
			System.out.println("Request stop NodeManager.");
			
			long count = 0;
			
			for (Iterator<Long> it = this.nodeMap.keySet().iterator(); it.hasNext(); ) {
				this.nodeMap.get(it.next()).close();
				
				it.remove();
				
				System.out.print("-");
				
				if (++count %20 == 0) {
					System.out.println();
				}
			}
			
			System.out.println();
		}
		
		System.out.println("NodeManager down.");
	}
	
	private void createNode(long id, Node node) throws IOException {
		if (NMS.LIMIT > 0 && this.nodeMap.size() >= NMS.LIMIT) {
			throw new IOException(String.format("Your license [%d] is limited", NMS.LIMIT));
		}
		
		this.nodeMap.put(id, node);
		
		node.addEventListener(this);
		
		node.setRetry(this.retry);
		node.setTimeout(this.timeout);
		
		node.ping(0);
	}
	
	/**
	 * 
	 * @param id
	 * @param ip
	 * @param port
	 * @param version
	 * @param security
	 * @param level
	 * @throws IOException
	 */
	public void createSNMPNode(long id, String ip, int port, String version, String security, int level) throws IOException {
		switch(version) {
		case "v3":
			createNode(id, new SNMPV3Node(this, id, ip, port, security, level));
		case "v2c":
			createNode(id, new SNMPDefaultNode(this, id, ip, port, security, SnmpConstants.version2c));
		default:
			createNode(id, new SNMPDefaultNode(this, id, ip, port, security, SnmpConstants.version1));
		}
	}
	
	/**
	 * 
	 * @param id
	 * @param ip
	 * @param protocol
	 * @throws IOException
	 */
	public void createSimpleNode(long id, String ip, String protocol) throws IOException {
		switch (protocol.toUpperCase()) {
		case "ICMP":
			createNode(id, new ICMPNode(id, ip));
		case "TCP":
			createNode(id, new TCPNode(id, ip));
		default:
			throw new IOException(String.format("Not supported protocol [%s]", protocol));
		}
	}
	
	@Override
	public void onEvent(Object caller, Object... args) {
		synchronized(this.isClosed) {
			if (this.isClosed) {
				return;
			}
		}
		
		if (caller instanceof Node) {
			switch ((Event)args[0]) {
			case CLOSE:
				
				break;
			case PING:
				onPingEvent((Node)caller, (long)args[1]);
				
				break;
			case SNMP:
				onSNMPEvent((Node)caller, args[1]);
				
				break;
			case RESOURCE:
				onResourceEvent((Node)caller, (OID)args[1], (OID)args[2], (Variable)args[3]);
				
				break;
			}
		}
		else if (caller instanceof SeedNode) {
			SeedNode seedNode = (SeedNode)caller;
			
			this.agent.informTestEvent(seedNode.id, seedNode.ip, (Protocol)args[0], args[1]);
		}
	}
	
	private void onPingEvent(Node node, long rtt) {
		this.agent.informPingEvent(node.id, rtt,
			node instanceof ICMPNode? "icmp": node instanceof TCPNode? "tcp": "");
		
		node.ping(rtt > -1? this.interval: 0);
	}
	
	private void onResourceEvent(Node node, OID oid, OID index, Variable variable) {
		this.agent.informResourceEvent(node.id, oid, index, variable);
	}

	private void onSNMPEvent(Node node, Object code) {
		if (code instanceof Exception) {
			((Exception)code).printStackTrace();
		} else if (code instanceof Integer){
			this.agent.informSNMPEvent(node.id, (int)code);
		}
	}
	
	public void removeNode(long id) {
		Node node = this.nodeMap.remove(id);
		
		if (node != null) {
			node.close();
		}
	}
	
	public void removeUSMUser(String user) {
		super.getUSM().removeAllUsers(new OctetString(user));
	}
	
	public void setInterval(long l) {
		this.interval = l;	
	}
	
	public void setRetry(int i) {
		this.retry = i;
		
		for (long id : this.nodeMap.keySet()) {
			this.nodeMap.get(id).setRetry(i);
		}
	}
	
	public void setTimeout(int i) {
		this.timeout = i;
		
		for (long id : this.nodeMap.keySet()) {
			this.nodeMap.get(id).setTimeout(i);
		}
	}
	
	public void testNode(long id, String ip, String protocol, Arguments... args) {
		SeedNode seed = new SeedNode(id, ip);
		
		seed.addEventListener(this);
		
		switch(protocol.toUpperCase()) {
		case "ICMP":
			seed.test(SeedNode.Protocol.ICMP);
			
			break;
		case "TCP":
			seed.test(SeedNode.Protocol.TCP);
			
			break;
		default:
			seed.test(SeedNode.Protocol.SNMP, this, args);
		}
	}

}
