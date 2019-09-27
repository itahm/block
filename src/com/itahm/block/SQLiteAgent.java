package com.itahm.block;

import java.io.IOException;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.sql.Types;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;
import java.util.concurrent.ConcurrentHashMap;

import org.snmp4j.mp.SnmpConstants;
import org.snmp4j.smi.OID;
import org.snmp4j.smi.Variable;
import org.sqlite.SQLiteConfig;
import org.sqlite.SQLiteOpenMode;

import com.itahm.block.Bean.*;
import com.itahm.block.NodeManager;
import com.itahm.block.SmartSearch.Profile;
import com.itahm.block.SMTP;
import com.itahm.block.node.PDUManager;
import com.itahm.block.node.SeedNode.Arguments;
import com.itahm.block.node.SeedNode.Protocol;
import com.itahm.json.JSONArray;
import com.itahm.json.JSONObject;
import com.itahm.util.Listenable;
import com.itahm.util.Listener;
import com.itahm.util.Network;

public class SQLiteAgent implements Commander, Agent, Listener, Listenable {
	
	private final String MD5_ROOT = "63a9f0ea7bb98050796b649e85481845";
	
	private Boolean isClosed = false;
	private Long nextNodeID = Long.valueOf(1);
	private Long nextLinkID = Long.valueOf(1);
	private Long nextEventID = Long.valueOf(1);
	private final String db;
	private final Properties properties;
	private final ArrayList<Listener> listenerList = new ArrayList<>();
	private final Map<Long, Boolean> statusMap = new ConcurrentHashMap<>();
	private final Map<Long, Integer> snmpMap = new ConcurrentHashMap<>();
	private final static Map<String, Rule> ruleMap = new HashMap<>();
	private final NodeManager nodeManager;
	private final Config config = new Config();
	
	{
		try {
			Class.forName("org.sqlite.JDBC");
		} catch (ClassNotFoundException cnfe) {
			System.err.print(cnfe);
		}
		
		ruleMap.put("1.3.6.1.2.1.1.1", new Rule("1.3.6.1.2.1.1.1", "sysDescr", "DisplayString", false, false));
		ruleMap.put("1.3.6.1.2.1.1.2", new Rule("1.3.6.1.2.1.1.2", "sysObjectID", "OBJECT IDENTIFIER", false, false));
		ruleMap.put("1.3.6.1.2.1.1.3", new Rule("1.3.6.1.2.1.1.3", "sysUpTime", "TimeTicks", false, false));
		ruleMap.put("1.3.6.1.2.1.1.5", new Rule("1.3.6.1.2.1.1.5", "sysName", "DisplayString", false, false));
		ruleMap.put("1.3.6.1.2.1.2.2.1.2", new Rule("1.3.6.1.2.1.2.2.1.2", "ifDescr", "DisplayString", false, false));
		ruleMap.put("1.3.6.1.2.1.2.2.1.3", new Rule("1.3.6.1.2.1.2.2.1.3", "ifType", "INTEGER", false, false));
		ruleMap.put("1.3.6.1.2.1.2.2.1.5", new Rule("1.3.6.1.2.1.2.2.1.5", "ifSpeed", "Gauge", false, false));
		ruleMap.put("1.3.6.1.2.1.2.2.1.6", new Rule("1.3.6.1.2.1.2.2.1.6", "ifPhysAddress", "PhysAddress", false, false));
		ruleMap.put("1.3.6.1.2.1.2.2.1.7", new Rule("1.3.6.1.2.1.2.2.1.7", "ifAdminStatus", "INTEGER", false, false));
		ruleMap.put("1.3.6.1.2.1.2.2.1.8", new Rule("1.3.6.1.2.1.2.2.1.8", "ifOperStatus", "INTEGER", false, true));
		ruleMap.put("1.3.6.1.2.1.2.2.1.10", new Rule("1.3.6.1.2.1.2.2.1.10", "ifInOctets", "Counter", true, false));
		ruleMap.put("1.3.6.1.2.1.2.2.1.14", new Rule("1.3.6.1.2.1.2.2.1.14", "ifInErrors", "Counter", true, false));
		ruleMap.put("1.3.6.1.2.1.2.2.1.16", new Rule("1.3.6.1.2.1.2.2.1.16", "ifOutOctets", "Counter", true, false));
		ruleMap.put("1.3.6.1.2.1.2.2.1.20", new Rule("1.3.6.1.2.1.2.2.1.20", "ifOutErrors", "Counter", true, false));
		ruleMap.put("1.3.6.1.2.1.25.1.1", new Rule("1.3.6.1.2.1.25.1.1", "hrSystemUptime", "TimeTicks", false, false));
		ruleMap.put("1.3.6.1.2.1.25.2.3.1.2", new Rule("1.3.6.1.2.1.25.2.3.1.2", "hrStorageType", "OBJECT IDENTIFIER", false, false));
		ruleMap.put("1.3.6.1.2.1.25.2.3.1.3", new Rule("1.3.6.1.2.1.25.2.3.1.3", "hrStorageDescr", "DisplayString", false, false));
		ruleMap.put("1.3.6.1.2.1.25.2.3.1.4", new Rule("1.3.6.1.2.1.25.2.3.1.4", "hrStorageAllocationUnits", "INTEGER", false, false));
		ruleMap.put("1.3.6.1.2.1.25.2.3.1.5", new Rule("1.3.6.1.2.1.25.2.3.1.5", "hrStorageSize", "INTEGER", false, false));
		ruleMap.put("1.3.6.1.2.1.25.2.3.1.6", new Rule("1.3.6.1.2.1.25.2.3.1.6", "hrStorageUsed", "INTEGER", true, false));
		ruleMap.put("1.3.6.1.2.1.25.2.3.1.6", new Rule("1.3.6.1.2.1.25.2.3.1.6", "hrProcessorLoad", "INTEGER", true, false));
		ruleMap.put("1.3.6.1.2.1.31.1.1.1.1", new Rule("1.3.6.1.2.1.31.1.1.1.1", "ifName", "DisplayString", false, false));
		ruleMap.put("1.3.6.1.2.1.31.1.1.1.6", new Rule("1.3.6.1.2.1.31.1.1.1.6", "ifHCInOctets", "Counter64", true, false));
		ruleMap.put("1.3.6.1.2.1.31.1.1.1.10", new Rule("1.3.6.1.2.1.31.1.1.1.10", "ifHCOutOctets", "Counter64", true, false));
		ruleMap.put("1.3.6.1.2.1.31.1.1.1.15", new Rule("1.3.6.1.2.1.31.1.1.1.15", "ifHighSpeed ", "Gauge32", false, false));
		ruleMap.put("1.3.6.1.2.1.31.1.1.1.18", new Rule("1.3.6.1.2.1.31.1.1.1.18", "ifAlias", "DisplayString", false, false));
		
		PDUManager.setPDU(ruleMap.keySet());
	}
	
	public SQLiteAgent(Path root) throws Exception {
		System.out.println("Commander: Agent v1.0");
		
		SQLiteConfig sqlConfig = new SQLiteConfig();
		
		sqlConfig.setOpenMode(SQLiteOpenMode.FULLMUTEX);
		
		db = "jdbc:sqlite:"+ root.resolve("sql.db").toString();
		properties = sqlConfig.toProperties();
		
		try (Connection c = DriverManager.getConnection(db, properties)) {
			long start = System.currentTimeMillis();
			
			c.setAutoCommit(false);
			
			try {
				/**
				 * ACCOUNT
				 */
				try (Statement stmt = c.createStatement()) {
					stmt.executeUpdate("CREATE TABLE IF NOT EXISTS account"+
						" (username TEXT NOT NULL"+
						", password TEXT NOT NULL"+
						", level INTEGER NOT NULL DEFAULT 0"+
						", PRIMARY KEY(username));");
				}
				/**END**/
				
				/**
				 * CONFIG
				 */
				try (Statement stmt = c.createStatement()) {
					stmt.executeUpdate("CREATE TABLE IF NOT EXISTS config"+
						" (key TEXT NOT NULL"+
						", value TEXT NOT NULL"+
						", PRIMARY KEY(key));");
				}
				/**END**/
				
				/**
				 * EVENT
				 */
				try (Statement stmt = c.createStatement()) {
					stmt.executeUpdate("CREATE TABLE IF NOT EXISTS event"+
						" (event_id INTEGER PRIMARY KEY"+
						", id INTEGER NOT NULL"+
						", timestamp INTEGER NOT NULL"+
						", origin TEXT NOT NULL"+
						", level INTEGER NOT NULL"+
						", message TEXT NOT NULL"+
						", name TEXT NOT NULL"+
						", date INTEGER NOT NULL);");
				}
				
				try (Statement stmt = c.createStatement()) {
					stmt.executeUpdate("CREATE INDEX IF NOT EXISTS event_index ON event (date);");
				}
				
				try (Statement stmt = c.createStatement()) {
					try (ResultSet rs = stmt.executeQuery("SELECT COALESCE(MAX(event_id), 0) FROM event;")) {
						if (rs.next()) {
							nextEventID = rs.getLong(1) +1;
						}
					}
				}
				/**END**/
				
				/**
				 * ICON
				 */
				try (Statement stmt = c.createStatement()) {
					stmt.executeUpdate("CREATE TABLE IF NOT EXISTS icon"+
						" (type TEXT NOT NULL"+
						", _group TEXT NOT NULL"+
						", src TEXT NOT NULL"+
						", disabled TEXT NOT NULL"+
						", PRIMARY KEY(type));");
				}
				/**END**/
				
				/**
				 * LINK
				 */
				try (Statement stmt = c.createStatement()) {
					stmt.executeUpdate("CREATE TABLE IF NOT EXISTS link"+
						" (id INTEGER PRIMARY KEY"+
						", node_from INTEGER NOT NULL"+
						", node_to  INTEGER NOT NULL"+
						", index_from INTEGER DEFAULT NULL"+
						", index_to INTEGER DEFAULT  NULL"+
						", extra TEXT DEFAULT NULL, UNIQUE(node_from, index_from), UNIQUE(node_to, index_to));");
				}
				
				try (Statement stmt = c.createStatement()) {
					try (ResultSet rs = stmt.executeQuery("SELECT COALESCE(MAX(id), 0) FROM link;")) {
						if (rs.next()) {
							nextLinkID = rs.getLong(1) +1;
						}
					}
				}
				/**END**/
				
				/**
				 * MONITOR
				 */
				try (Statement stmt = c.createStatement()) {
					stmt.executeUpdate("CREATE TABLE IF NOT EXISTS monitor"+
						" (id INTEGER NOT NULL"+
						", ip TEXT NOT NULL"+
						", protocol TEXT NOT NULL"+
						", status INTEGER NOT NULL DEFAULT 1"+
						", snmp INTEGER NOT NULL DEFAULT 0"+
						", PRIMARY KEY (id));");
				}
				/**END**/
				
				/**
				 * NODE
				 */
				try (Statement stmt = c.createStatement()) {
					stmt.executeUpdate("CREATE TABLE IF NOT EXISTS node"+
						" (id INTEGER PRIMARY KEY"+
						", name TEXT DEFAULT NULL"+
						", type TEXT DEFAULT NULL"+
						", ip TEXT DEFAULT NULL UNIQUE"+
						", label TEXT DEFAULT NULL"+
						", extra TEXT DEFAULT NULL);");
				}
				
				try (Statement stmt = c.createStatement()) {
					stmt.executeUpdate("CREATE INDEX IF NOT EXISTS node_index ON node (ip);");
				}
				
				try (Statement stmt = c.createStatement()) {
					try (ResultSet rs = stmt.executeQuery("SELECT COALESCE(MAX(id), 0)FROM node")) {
						if (rs.next()) {
							nextNodeID = rs.getLong(1) +1;
						}
					}
				}
				/**END**/

				/**
				 * PATH
				 */
				try (Statement stmt = c.createStatement()) {
					stmt.executeUpdate("CREATE TABLE IF NOT EXISTS path"+
						" (node_from INTEGER NOT NULL"+
						", node_to INTEGER NOT NULL"+
						", type TEXT DEFAULT NULL"+
						", color TEXT DEFAULT NULL"+
						", size INTEGER DEFAULT 0"+
						", UNIQUE(node_from, node_to));");
				}
				/**END**/
				
				/**
				 * POSITION
				 */
				try (Statement stmt = c.createStatement()) {
					stmt.executeUpdate("CREATE TABLE IF NOT EXISTS position"+
						" (name TEXT NOT NULL DEFAULT 'position'"+
						", position TEXT NOT NULL DEFAULT '{}'"+
						", PRIMARY KEY(name));");
				}
				/**END**/
				
				/**
				 * PROFILE
				 */
				try (Statement stmt = c.createStatement()) {
					stmt.executeUpdate("CREATE TABLE IF NOT EXISTS profile"+
						" (name TEXT PRIMARY KEY"+
						", protocol TEXT NOT NULL"+
						", port INTEGER NOT NULL"+
						", version TEXT NOT NULL"+
						", security TEXT NOT NULL"+
						", level INTEGER DEFAULT NULL"+
						", auth_protocol TEXT DEFAULT NULL"+
						", auth_key TEXT DEFAULT NULL"+
						", priv_protocol TEXT DEFAULT NULL"+
						", priv_key TEXT DEFAULT NULL);");
				}
				
				/**END**/
				
				/**
				 * RESOURCE
				 */
				try (Statement stmt = c.createStatement()) {
					stmt.executeUpdate("CREATE TABLE IF NOT EXISTS resource"+
						" (id INTEGER NOT NULL"+
						", oid TEXT NOT NULL"+
						", _index TEXT NOT NULL"+
						", value TEXT NOT NULL"+
						", timestamp INTEGER DEFAULT NULL"+
						", date INTEGER NOT NULL);");
				}
				
				try (Statement stmt = c.createStatement()) {
					stmt.executeUpdate("CREATE INDEX IF NOT EXISTS idx ON resource (date);");
				}
				/**END**/
				
				/**
				 * RULE
				 */
				try (Statement stmt = c.createStatement()) {
					stmt.executeUpdate("CREATE TABLE IF NOT EXISTS rule"+
						" (oid TEXT PRIMARY KEY"+
						", name TEXT NOT NULL"+
						", syntax TEXT NOT NULL"+
						", method TEXT"+
						", rolling INTEGER NOT NULL DEFAULT 0"+
						", on_change INTEGER NOT NULL DEFAULT 0);");
				}
				/**END**/
				
				/**
				 * SETTING
				 */
				try (Statement stmt = c.createStatement()) {
					stmt.executeUpdate("CREATE TABLE IF NOT EXISTS setting"+
						" (key TEXT PRIMARY KEY"+
						", value TEXT DEFAULT NULL);");
				}
				/**END**/
				
				/**
				 * USER
				 */
				try (Statement stmt = c.createStatement()) {
					stmt.executeUpdate("CREATE TABLE IF NOT EXISTS user"+
						" (name TEXT DEFAULT NULL"+
						", email TEXT DEFAULT NULL"+
						", sms TEXT DEFAULT NULL"+
						", PRIMARY KEY(name));");
				}
				/**END**/
				
				c.commit();
				
				System.out.format("Database initialized in %dms.\n", System.currentTimeMillis() - start);
			} catch(Exception e) {
				c.rollback();
				
				throw e;
			} finally {
				c.setAutoCommit(true);
			}
		}
		
		if (getAccount().length() == 0) {
			addAccount("root", new JSONObject()
				.put("username", "root")
				.put("password", MD5_ROOT)
				.put("level", 0));
		}
		
		if (getProfile().length() == 0) {
			addProfile("public", new JSONObject()
				.put("name", "public")
				.put("protocol", "udp")
				.put("port", 161)
				.put("version", "v2c")
				.put("security", "public"));
		}
		
		nodeManager = new NodeManager(this, config.requestInterval, config.timeout, config.retry);
		
		addUSM();
		
		initNode();
	}
	
	@Override
	public boolean addAccount(String username, JSONObject account) {
		try(Connection c = DriverManager.getConnection(this.db, this.properties)) {
			try (PreparedStatement pstmt = c.prepareStatement("INSERT INTO account (username, password, level)"+
				" VALUES (?, ?, ?);")) {
				pstmt.setString(1, account.getString("username"));
				pstmt.setString(2, account.getString("password"));
				pstmt.setInt(3, account.getInt("level"));
				
				pstmt.executeUpdate();
			}
		} catch (SQLException sqle) {
			System.err.print(sqle);
			
			return false;
		}
		
		return true;
	}

	@Override
	public void addEventListener(Listener listener) {
		this.listenerList.add(listener);	
	}
	
	@Override
	public JSONObject addIcon(String type, JSONObject icon) {
		try (Connection c = DriverManager.getConnection(this.db, this.properties)) {
			try (PreparedStatement pstmt = c.prepareStatement("INSERT INTO icon"+
				" (type, _group, src, disabled)"+
				" VALUES (?, ?, ?, ?);")) {
				pstmt.setString(1, icon.getString("type"));
				pstmt.setString(2, icon.getString("group"));
				pstmt.setString(3, icon.getString("src"));
				pstmt.setString(4, icon.getString("disabled"));
				
				pstmt.executeUpdate();
			}
			
		} catch (SQLException sqle) {
			System.err.print(sqle);
			
			return null;
		}
		
		return icon;
	}

	@Override
	public boolean addLink(long nodeFrom, long nodeTo) {
		if (nodeFrom >= nodeTo) {
			return false;
		}
		
		try (Connection c = DriverManager.getConnection(this.db, this.properties)) {			
			synchronized(this.nextLinkID) {
				try (PreparedStatement pstmt = c.prepareStatement("INSERT INTO link (id, node_from, node_to) values (?, ?, ?);")) {
					pstmt.setLong(1, this.nextLinkID);
					pstmt.setLong(2, nodeFrom);
					pstmt.setLong(3, nodeTo);
					
					pstmt.executeUpdate();
				}
				
				this.nextLinkID++;
			}
		} catch (SQLException sqle) {
			System.err.print(sqle);
			
			return false;
		}
		
		return true;
	}
	
	private void initNode() throws IOException {
		try(Connection c = DriverManager.getConnection(this.db, this.properties)) {
			try (Statement stmt = c.createStatement()) {
				try (ResultSet rs = stmt.executeQuery("SELECT id, ip, m.protocol, port, version, security, level, status, snmp"+
					" FROM monitor m LEFT JOIN profile p ON m.protocol = p.name;")) {
					long id;
					
					while (rs.next()) {
						System.out.print("!");
					
						id = rs.getLong(1);
						
						switch(rs.getString(3).toUpperCase()) {
						case "ICMP":
						case "TCP":
							this.nodeManager.createNode(id, rs.getString(2), rs.getString(3));
							
							break;
						default:
							this.nodeManager.createNode(id, rs.getString(2), rs.getInt(4), rs.getString(5), rs.getString(6), rs.getInt(7));
							
							this.snmpMap.put(id, rs.getInt(9));
						}
						
						this.statusMap.put(id, rs.getInt(8) > 0);
					}
					
					System.out.println();
				}
			}
		} catch (SQLException sqle) {
			System.err.print(sqle);
		} catch (Exception e) {
			System.err.print(e);
		}
	}
	
	@Override
	public JSONObject addNode(JSONObject node) {
		try (Connection c = DriverManager.getConnection(this.db, this.properties)) {
			synchronized(this.nextNodeID) {		
				try (PreparedStatement pstmt = c.prepareStatement("INSERT INTO node (id, name, type, ip, label, extra) values (?, ?, ?, ?, ?, ?);")) {
					pstmt.setLong(1, this.nextNodeID);
					
					if (node.has("name")) {
						pstmt.setString(2, node.getString("name"));
					}
					else {
						pstmt.setNull(2, Types.NULL);
					}
					
					if (node.has("type")) {
						pstmt.setString(3, node.getString("type"));
					}
					else {
						pstmt.setNull(3, Types.NULL);
					}
					
					if (node.has("ip")) {
						pstmt.setString(4, node.getString("ip"));
					}
					else {
						pstmt.setNull(4, Types.NULL);
					}
					
					if (node.has("label")) {
						pstmt.setString(5, node.getString("label"));
					}
					else {
						pstmt.setNull(5, Types.NULL);
					}
					
					if (node.has("extra")) {
						pstmt.setString(6, node.getString("extra"));
					}
					else {
						pstmt.setNull(6, Types.NULL);
					}
					
					pstmt.executeUpdate();
				}
				
				node.put("id", this.nextNodeID);
				
				this.nextNodeID++;
				
				return node;
			}
		} catch (SQLException sqle) {
			System.err.print(sqle);
		}
		
		return null;
	}


	@Override
	public boolean addPath(long nodeFrom, long nodeTo) {
		if (nodeFrom >= nodeTo) {
			return false;
		}
		
		try (Connection c = DriverManager.getConnection(this.db, this.properties)) {
			try (PreparedStatement pstmt = c.prepareStatement("INSERT INTO path (node_from, node_to) values (?, ?);")) {
				pstmt.setLong(1, nodeFrom);
				pstmt.setLong(2, nodeTo);
				
				pstmt.executeUpdate();
			}
		} catch (SQLException sqle) {
			System.err.print(sqle);
			
			return false;
		}
		
		return true;
	}
	
	@Override
	public boolean addProfile(String name, JSONObject profile) {
		try (Connection c = DriverManager.getConnection(this.db, this.properties)) {
			try (PreparedStatement pstmt = c.prepareStatement("INSERT INTO profile"+
				" (name, protocol, port, version, security, auth_protocol, auth_key, priv_protocol, priv_key)"+
				" VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);")) {
				pstmt.setString(1, profile.getString("name"));
				pstmt.setString(2, profile.getString("protocol"));
				pstmt.setInt(3, profile.getInt("port"));
				pstmt.setString(4, profile.getString("version"));
				pstmt.setString(5, profile.getString("security"));
				pstmt.setString(6, profile.has("authProtocol")? profile.getString("authProtocol"): null);
				pstmt.setString(7, profile.has("authKey")? profile.getString("authKey"): null);
				pstmt.setString(8, profile.has("privProtocol")? profile.getString("privProtocol"): null);
				pstmt.setString(9, profile.has("privKey")? profile.getString("privKey"): null);
				
				pstmt.executeUpdate();
			}
		} catch (SQLException sqle) {
			System.err.print(sqle);
			
			return false;
		}
		
		return true;
	}
	
	@Override
	public boolean addUser(String name, JSONObject user) {
		try (Connection c = DriverManager.getConnection(this.db, this.properties)) {
			try (PreparedStatement pstmt = c.prepareStatement("INSERT INTO user (name, email, sms) VALUES"+
				" (?, ?, ?);")) {
				pstmt.setString(1, name);
				pstmt.setString(2, user.has("email")? user.getString("email"): null);
				pstmt.setString(3, user.has("sms")? user.getString("sms"): null);
				
				pstmt.executeUpdate();
			}
		} catch (SQLException sqle) {
			System.err.print(sqle);
			
			return false;
		}
		
		return true;
	}

	private void addUSM() {
		try (Connection c = DriverManager.getConnection(this.db, this.properties)) {
			try (Statement stmt = c.createStatement()) {
				try (ResultSet rs = stmt.executeQuery("SELECT security, level, auth_protocol, auth_key, priv_protocol, priv_key FROM profile WHERE version='v3';")) {
					while (rs.next()) {
						this.nodeManager.addUSMUser(rs.getString(1), rs.getInt(2), rs.getString(3), rs.getString(4), rs.getString(5), rs.getString(6));	
					}
				}
			}
		} catch (SQLException sqle) {
			System.err.print(sqle);
		}
	}
	
	@Override
	public void close() {
		synchronized(this.isClosed) {
			if (this.isClosed) {
				return;
			}
		}
		
		try {
			this.nodeManager.stop();
		} catch (IOException ioe) {
			System.err.print(ioe);
		}
	}
	
	@Override
	public void fireEvent(Object ...args) {
		for (Listener listener: this.listenerList) {
			listener.onEvent(this, args);
		}
	}
	
	@Override
	public JSONObject getAccount() {
		try (Connection c = DriverManager.getConnection(this.db, this.properties)) {
			try (Statement stmt = c.createStatement()) {
				JSONObject accountData = new JSONObject();
				
				try (ResultSet rs = stmt.executeQuery("SELECT username, password, level FROM account;")) {
					while (rs.next()) {
						accountData.put(rs.getString(1), new JSONObject()
							.put("username", rs.getString(1))
							.put("password", rs.getString(2))
							.put("level", rs.getInt(3)));
					}
				}
				
				return accountData;
			}
		} catch (SQLException sqle) {
			System.err.print(sqle);
		}
		
		return null;
	}

	@Override
	public JSONObject getAccount(String username) {
		try (Connection c = DriverManager.getConnection(this.db, this.properties)) {
			try (PreparedStatement pstmt = c.prepareStatement("SELECT username, password, level FROM account WHERE username=?;")) {
				pstmt.setString(1, username);
				
				try (ResultSet rs = pstmt.executeQuery()) {
					if (rs.next()) {
						return new JSONObject()
							.put("username", rs.getString(1))
							.put("password", rs.getString(2))
							.put("level", rs.getInt(3));
					}
				}
			}
		} catch (SQLException sqle) {
			System.err.print(sqle);
		}
		
		return null;
	}

	@Override
	public JSONObject getConfig() {
		return this.config.getJSONObject();
	}
	
	@Override
	public void getDataByID(long id) {
		// TODO Auto-generated method stub
		
	}
	/*
	private Connection DriverManager.getConnection(this.db, this.properties) throws SQLException {
	    return DriverManager.getConnection(this.db, this.properties);
	}
	*/
	@Override
	public JSONObject getEvent(long eventID) {
		try (Connection c =  DriverManager.getConnection(this.db, this.properties)) {
			try (PreparedStatement pstmt = c.prepareStatement("SELECT id, timestamp, origin, level, message, name FROM event WHERE event_id=?;")) {
				pstmt.setLong(1, eventID);
				
				try (ResultSet rs = pstmt.executeQuery()) {
					if (rs.next()) {
						JSONObject event = new JSONObject()
							.put("eventID", eventID)
							.put("id", rs.getLong(1))
							.put("timestamp", rs.getLong(2))
							.put("origin", rs.getString(3))
							.put("level", rs.getInt(4))
							.put("message", rs.getString(5))
							.put("name", rs.getString(6));
						
						return event;
					}
				}
			} 
		} catch (SQLException sqle) {
			System.err.print(sqle);
		}
		
		return null;
	}


	@Override
	public JSONObject getEventByDate(long date) {
		Calendar calendar = Calendar.getInstance();
		
		calendar.setTimeInMillis(date);
		
		calendar.set(Calendar.HOUR_OF_DAY, 0);
		calendar.set(Calendar.MINUTE, 0);
		calendar.set(Calendar.SECOND, 0);
		calendar.set(Calendar.MILLISECOND, 0);
	
		try (Connection c = DriverManager.getConnection(this.db, this.properties)) {
			try (PreparedStatement pstmt = c.prepareStatement("SELECT id, timestamp, origin, leDriverManager.getConnection(this.db, this.properties)e, event_id"+
				" FROM EVENT where date=?;")) {
				pstmt.setLong(1, calendar.getTimeInMillis());
				
				try (ResultSet rs = pstmt.executeQuery()) {
					JSONObject
						eventData = new JSONObject(),
						event;
					
					while(rs.next()) {
						event = new JSONObject()
							.put("id", rs.getLong(1))
							.put("timestamp", rs.getLong(2))
							.put("origin", rs.getString(3))
							.put("level", rs.getInt(4))
							.put("message", rs.getString(5))
							.put("name", rs.getString(6))
							.put("eventID", rs.getLong(7));
						
						eventData.put(Long.toString(rs.getLong(7)), event);
					}
					
					return eventData;
				}
			} 
		} catch (SQLException sqle) {
			System.err.print(sqle);
		}
		
		return null;
	}

	@Override
	public JSONObject getIcon() {
		try (Connection c = DriverManager.getConnection(this.db, this.properties)) {
			try (Statement stmt = c.createStatement()) {
				JSONObject iconData = new JSONObject();
				
				try (ResultSet rs = stmt.executeQuery("SELECT type, _group, src, disabled FROM icon;")) {
					while (rs.next()) {
						iconData.put(rs.getString(1), new JSONObject()
							.put("type", rs.getString(1))
							.put("group", rs.getString(2))
							.put("src", rs.getString(3))
							.put("disabled", rs.getString(4)));
					}
				}
				
				return iconData;
			}
		} catch (SQLException sqle) {
			System.err.print(sqle);
			
			return null;
		}
	}

	@Override
	public JSONObject getIcon(String type) {
		try (Connection c = DriverManager.getConnection(this.db, this.properties)) {
			try (PreparedStatement pstmt = c.prepareStatement("SELECT type, _group, src, disabled FROM icon where type=?;")) {
				pstmt.setString(1,  type);
				
				try (ResultSet rs = pstmt.executeQuery()) {
					if (rs.next()) {
						new JSONObject()
							.put("type", rs.getString(1))
							.put("group", rs.getString(2))
							.put("src", rs.getString(3))
							.put("disabled", rs.getString(4));
					}
				}
			}
		} catch (SQLException sqle) {
			System.err.print(sqle);
		}
		
		return null;
	}
	
	@Override
	public JSONObject getLink() {		
		try (Connection c = DriverManager.getConnection(this.db, this.properties)) {
			try (Statement stmt = c.createStatement()) {
				JSONObject
					linkData = new JSONObject(),
					link;
				
				try (ResultSet rs = stmt.executeQuery("SELECT id, node_from, node_to, COALESCE(index_from, 0), COALESCE(index_to, 0), extra FROM link;")) {
					while (rs.next()) {
						link = new JSONObject()
							.put("id", rs.getLong(1))
							.put("nodeFrom", rs.getLong(2))
							.put("nodeTo", rs.getLong(3));
						
						if (rs.getLong(4) > 0) {
							link.put("indexFrom", rs.getLong(4));
						}
							
						if (rs.getLong(5) > 0) {
							link.put("indexTo", rs.getLong(5));
						}
						
						if (rs.getString(6) != null) {
							link.put("extra", new JSONObject(rs.getString(6)));
						}
						
						linkData.put(Long.toString(rs.getLong(1)), link);
					}
				}
				
				return linkData;
			}
		} catch (SQLException sqle) {
			System.err.print(sqle);
		}
		
		return null;
	}

	@Override
	public JSONObject getLink(long nodeFrom, long nodeTo) {
		try (Connection c = DriverManager.getConnection(this.db, this.properties)) {
			try (PreparedStatement pstmt = c.prepareStatement("SELECT id, node_from, node_to, COALESCE(index_from, 0), COALESCE(index_to, 0), extra"+
				" FROM link WHERE node_from=? AND node_to=?;")) {
				pstmt.setLong(1,  nodeFrom);
				pstmt.setLong(2,  nodeTo);
				
				try (ResultSet rs = pstmt.executeQuery()) {
					if (rs.next()) {
						JSONObject link = new JSONObject()
								.put("id", rs.getLong(1))
								.put("nodeFrom", rs.getLong(2))
								.put("nodeTo", rs.getLong(3));
							
							if (rs.getLong(4) > 0) {
								link.put("indexFrom", rs.getLong(4));
							}
								
							if (rs.getLong(5) > 0) {
								link.put("indexTo", rs.getLong(5));
							}
							
							if (rs.getString(6) != null) {
								link.put("extra", new JSONObject(rs.getString(6)));
							}
					}
				}
			}
		} catch (SQLException sqle) {
			System.err.print(sqle);
		}
		
		return null;
	}
	
	@Override
	public JSONObject getInformation() {
		Calendar c = Calendar.getInstance();
		JSONObject body = new JSONObject();
		
		c.set(Calendar.DATE, c.get(Calendar.DATE) -1);
		c.set(Calendar.HOUR_OF_DAY, 0);
		c.set(Calendar.MINUTE, 0);
		c.set(Calendar.SECOND, 0);
		c.set(Calendar.MILLISECOND, 0);
		/*
		body
			.put("version", Agent.Config.version)
			.put("load", Agent.node().calcLoad())
			.put("resource", Agent.node().getResourceCount())
			.put("usage", Util.getDirectorySize(root.toPath().resolve("node"), Long.toString(c.getTimeInMillis())))
			.put("path", root.getAbsoluteFile().toString())
			.put("expire", Agent.Config.expire());
		 */
		return body;
	}


	@Override
	public JSONObject getNode() {
		try (Connection c = DriverManager.getConnection(this.db, this.properties)) {
			try (Statement stmt = c.createStatement()) {
				JSONObject
					nodeData = new JSONObject(),
					node;
				
				try (ResultSet rs = stmt.executeQuery("SELECT n.id, name, type, n.ip, label, m.protocol"+
					" FROM node n LEFT JOIN monitor m USING(id);")) {
					while (rs.next()) {
						node = new JSONObject()
							.put("id", rs.getLong(1));
						
						if (rs.getString(2) != null) {
							node.put("name", rs.getString(2));
						}
						
						if (rs.getString(3) != null) {
							node.put("type", rs.getString(3));
						}
						
						if (rs.getString(4) != null) {
							node.put("ip", rs.getString(4));
						}
						
						if (rs.getString(5) != null) {
							node.put("label", rs.getString(5));
						}
						
						if (rs.getString(6) != null) {
							node.put("protocol", rs.getString(6));
						}
						
						nodeData.put(Long.toString(rs.getLong(1)), node);
					}
					
					return nodeData;
				}
			}
		} catch (SQLException sqle) {
			System.err.print(sqle);
		}
		
		return null;
	}

	@Override
	public JSONObject getNode(long id, boolean snmp) {
		try (Connection c = DriverManager.getConnection(this.db, this.properties)) {
			try (PreparedStatement pstmt = c.prepareStatement("SELECT n.id, name, type, n.ip, label, m.protocol"+
				" FROM node n LEFT JOIN monitor m USING(id) where n.id=?;")) {
				pstmt.setLong(1, id);
				
				try (ResultSet rs = pstmt.executeQuery()) {
					if (rs.next()) {
						JSONObject node = new JSONObject()
							.put("id", rs.getLong(1));
						
						if (rs.getString(2) != null) {
							node.put("name", rs.getString(2));
						}
						
						if (rs.getString(3) != null) {
							node.put("type", rs.getString(3));
						}
						
						if (rs.getString(4) != null) {
							node.put("ip", rs.getString(4));
						}
						
						if (rs.getString(5) != null) {
							node.put("label", rs.getString(5));
						}
						
						if (rs.getString(6) != null) {
							node.put("protocol", rs.getString(6));
						}
						
						return node;
					}
				}
			}
		} catch (SQLException sqle) {
			System.err.print(sqle);
		}
		
		return null;
	}

	@Override
	public JSONObject getPath() {
		try (Connection c = DriverManager.getConnection(this.db, this.properties)) {
			try (Statement stmt = c.createStatement()) {
				JSONObject
					pathData = new JSONObject(),
					path;
				
				try (ResultSet rs = stmt.executeQuery("SELECT node_from, node_to, type, color, COALESCE(size, 0) FROM path;")) {
					while (rs.next()) {
						path = new JSONObject();
						
						if (pathData.has(Long.toString(rs.getLong(1)))) {
							pathData.getJSONObject(Long.toString(rs.getLong(1)))
								.put(Long.toString(rs.getLong(2)), path);
						}
						else {
							pathData.put(Long.toString(rs.getLong(1)), new JSONObject()
								.put(Long.toString(rs.getLong(2)), path));
						}
						
						if (rs.getString(3) != null) {
							path.put("type", rs.getString(3));
						}
						
						if (rs.getString(4) != null) {
							path.put("color", rs.getString(4));
						}
						
						if (rs.getInt(5) > 0) {
							path.put("size", rs.getInt(5));
						}
					}
					
					return pathData;
				}
			}
		} catch (SQLException sqle) {
			System.err.print(sqle);
		}
		
		return null;
	}

	@Override
	public JSONObject getPath(long nodeFrom, long nodeTo) {
		try (Connection c = DriverManager.getConnection(this.db, this.properties)) {
			try (PreparedStatement pstmt = c.prepareStatement("SELECT type, color, COALESCE(size, 0)"+
				" FROM path WHERE node_from=? AND node_to=?;")) {
				pstmt.setLong(1, nodeFrom);
				pstmt.setLong(2, nodeTo);
				
				try (ResultSet rs = pstmt.executeQuery()) {
					if (rs.next()) {
						JSONObject path = new JSONObject()
							.put("nodeFrom", nodeFrom)
							.put("nodeTo", nodeTo);
							
						
						if (rs.getString(1) != null) {
							path.put("type", rs.getString(1));
						}
						
						if (rs.getString(2) != null) {
							path.put("color", rs.getString(2));
						}
						
						if (rs.getInt(3) > 0) {
							path.put("size", rs.getInt(3));
						}
						
						return path;
					}
				}
			}
		} catch (SQLException sqle) {
			System.err.print(sqle);
		}
			return null;
	}
	
	@Override
	public JSONObject getPosition(String name) {
		try (Connection c = DriverManager.getConnection(this.db, this.properties)) {
			try (PreparedStatement pstmt = c.prepareStatement("SELECT position FROM position WHERE name=?;")) {
				pstmt.setString(1, name);
				
				try (ResultSet rs = pstmt.executeQuery()) {
					if (rs.next()) {
						return new JSONObject(rs.getString(1));
					}
				}
			} 
		} catch (SQLException sqle) {
			System.err.print(sqle);
		}
		
		return null;
	}
	@Override
	public JSONObject getProfile() {
		try (Connection c = DriverManager.getConnection(this.db, this.properties)) {
			try (Statement stmt = c.createStatement()) {
				JSONObject
					profileData = new JSONObject(),
					profile;
				
				try (ResultSet rs = stmt.executeQuery("SELECT name, protocol, port, version, security, auth_protocol, auth_key, priv_protocol, priv_key"+
					" FROM profile;")) {
					while (rs.next()) {
						profile = new JSONObject()
							.put("name", rs.getString(1))
							.put("protocol", rs.getString(2))
							.put("port", rs.getInt(3))
							.put("version", rs.getString(4))
							.put("security", rs.getString(5));
						
						if (rs.getString(6) != null) {
							profile.put("authProtocol", rs.getString(6));
						}
						
						if (rs.getString(7) != null) {
							profile.put("authKey", rs.getString(7));
						}
						
						if (rs.getString(8) != null) {
							profile.put("privProtocol", rs.getString(8));
						}
						
						if (rs.getString(9) != null) {
							profile.put("privKey", rs.getString(9));
						}
						
						profileData.put(rs.getString(1), profile);
					}
					
					return profileData;
				}
			}
		} catch (SQLException sqle) {
			System.err.print(sqle);
		}
		
		return null;
	}
	
	@Override
	public JSONObject getProfile(String name) {
		try (Connection c = DriverManager.getConnection(this.db, this.properties)) {
			try (PreparedStatement pstmt = c.prepareStatement("SELECT protocol, port, version, security, auth_protocol, auth_key, priv_protocol, priv_key"+ 
				" FOM profile WHERE name=?;")) {
				pstmt.setString(1, name);
				
				try (ResultSet rs = pstmt.executeQuery()) {
					if (rs.next()) {
						JSONObject profile = new JSONObject()
							.put("name", rs.getString(1))
							.put("protocol", rs.getString(2))
							.put("port", rs.getInt(3))
							.put("version", rs.getString(4))
							.put("security", rs.getString(5));
					
						if (rs.getString(6) != null) {
							profile.put("authProtocol", rs.getString(6));
						}
						
						if (rs.getString(7) != null) {
							profile.put("authKey", rs.getString(7));
						}
						
						if (rs.getString(8) != null) {
							profile.put("privProtocol", rs.getString(8));
						}
						
						if (rs.getString(9) != null) {
							profile.put("privKey", rs.getString(9));
						}
						
						return profile;
					}
				}
			}
		} catch (SQLException sqle) {
			System.err.print(sqle);
		}
		
		return null;
	}
	
	@Override
	public JSONObject getSetting() {
		try (Connection c = DriverManager.getConnection(this.db, this.properties)) {
			try (Statement stmt = c.createStatement()) {
				JSONObject settingData = new JSONObject();
				
				try (ResultSet rs = stmt.executeQuery("SELECT key, value FROM setting;")) {
					while (rs.next()) {
						settingData.put(rs.getString(1), rs.getString(2));
					}
				}
				
				return settingData;
			}
		} catch (SQLException sqle) {
			System.err.print(sqle);
		}
		
		return null;
	}

	@Override
	public JSONObject getSetting(String key) {
		try (Connection c = DriverManager.getConnection(this.db, this.properties)) {
			try (PreparedStatement pstmt = c.prepareStatement("SELECT key, value FROM setting WHERE key=?;")) {
				pstmt.setString(1, key);
				
				try (ResultSet rs = pstmt.executeQuery()) {
					if (rs.next()) {
						new JSONObject()
							.put("key", rs.getString(1))
							.put("value", rs.getString(2));
					}
				}
			}
		} catch (SQLException sqle) {
			System.err.print(sqle);
		}
		
		return null;
	}

	@Override
	public JSONObject getTop(JSONArray list, JSONObject resources) {
		return new JSONObject();
	}

	@Override
	public JSONObject getTraffic(JSONObject traffic) {
		// TODO Auto-generated method stub
		return traffic;
	}

	@Override
	public JSONObject getUser() {
		try (Connection c = DriverManager.getConnection(this.db, this.properties)) {
			try (Statement stmt = c.createStatement()) {
				JSONObject userData = new JSONObject();
				
				try (ResultSet rs = stmt.executeQuery("SELECT name, email, sms FROM user;")) {
					while (rs.next()) {
						userData.put(rs.getString(1), new JSONObject()
							.put("name", rs.getString(1))
							.put("email", rs.getString(2))
							.put("sms", rs.getString(3)));
					}
				}
				
				return userData;
			}
		} catch (SQLException sqle) {
			System.err.print(sqle);
		}
		
		return null;
	}
	
	@Override
	public JSONObject getUser(String name) {
		try (Connection c = DriverManager.getConnection(this.db, this.properties)) {
			try (PreparedStatement pstmt = c.prepareStatement("SELECT name, email, sms FROM user WHERE name=?;")) {
				pstmt.setString(1, name);
				
				try (ResultSet rs = pstmt.executeQuery()) {
					if (rs.next()) {
						return new JSONObject()
							.put("name", rs.getString(1))
							.put("email", rs.getString(2))
							.put("sms", rs.getString(3));
					}
				}
			}
		} catch (SQLException sqle) {
			System.err.print(sqle);
		}
		
		return null;
	}
	
	public void informPingEvent(long id, long rtt, String protocol) {
		String
			name,
			message;
		Boolean status = this.statusMap.get(id);
		
		if (status == null || status == rtt > -1) {
			return;
		}
		
		try(Connection c = DriverManager.getConnection(this.db, this.properties)) {
			synchronized(this.nextEventID) {
				try (PreparedStatement pstmt = c.prepareStatement("SELECT name, ip FROM node WHERE id=?;")) {
					pstmt.setLong(1, id);
					
					try (ResultSet rs = pstmt.executeQuery()) {
						if (!rs.next()) {
							return;
						}
						
						name = rs.getString(1) != null? rs.getString(1): rs.getString(2) != null? rs.getString(2): "";
					}
				}
				
				message = String.format("%s %s �쓳�떟 %s.", name, protocol.toUpperCase(), status? "�젙�긽": "�뾾�쓬");
				
				try (PreparedStatement pstmt = c.prepareStatement("UPDATE monitor SET status=? WHERE id=?;")) {
					pstmt.setInt(1, status? 1: 0);
					pstmt.setLong(2, id);
					
					pstmt.executeUpdate();
				}
				
				sendEvent(this.nextEventID, "status", id, status? 0: 2, name, message);
				
				this.nextEventID++;
			
				this.statusMap.put(id, !status);
			}
		}
		catch(SQLException sqle) {
			System.err.print(sqle);
		}
	}
	
	public void informSNMPEvent(long id, int code) {
		String
			name,
			message;
		Integer old = this.snmpMap.get(id);
		
		if (old == null || old == code) {
			return;
		}
			
		try(Connection c = DriverManager.getConnection(this.db, this.properties)) {
			synchronized(this.nextEventID) {
				try (PreparedStatement pstmt = c.prepareStatement("SELECT name, ip FROM node WHERE id=?;")) {
					pstmt.setLong(1, id);
					
					try (ResultSet rs = pstmt.executeQuery()) {
						if (!rs.next()) {
							return;
						}
						
						name = rs.getString(1) != null? rs.getString(1): rs.getString(2) != null? rs.getString(2): "";
					}
				}
				
				message = String.format("%s SNMP �쓳�떟 %s.", name, code == SnmpConstants.SNMP_ERROR_SUCCESS? "�젙�긽":
					code == SnmpConstants.SNMP_ERROR_TIMEOUT? "�뾾�쓬":
					("�삤瑜섏퐫�뱶 "+ code));
				
				try (PreparedStatement pstmt = c.prepareStatement("UPDATE monitor SET snmp=? WHERE id=?;")) {
					pstmt.setInt(1, code);
					pstmt.setLong(2, id);
					
					pstmt.executeUpdate();
				}
				
				sendEvent(this.nextEventID, "snmp", id, code == 0? 0: 1, name, message);
				
				this.nextEventID++;
				
				this.snmpMap.put(id, code);
			}
		}
		catch(SQLException sqle) {
			System.err.print(sqle);
		}
	}
	
	public void informResourceEvent(long id, OID oid, OID index, Variable variable) {
		try(Connection c = DriverManager.getConnection(this.db, this.properties)) {
			Calendar calendar = Calendar.getInstance();
						
			try (PreparedStatement pstmt = c.prepareStatement("INSERT INTO resource (id, oid, _index, value, timestamp, date)"+
				" VALUES (?, ?, ?, ?, ?, ?);")) {
				pstmt.setLong(1, id);
				pstmt.setString(2, oid.toDottedString());
				pstmt.setString(3, oid.toDottedString());
				pstmt.setString(4, variable.toString());
				pstmt.setLong(5, calendar.getTimeInMillis());
				pstmt.setString(6, variable.toString());
				
				pstmt.executeUpdate();
			}
		} catch (SQLException sqle) {
			System.err.print(sqle);
		}
	}
	
	public void informTestEvent(long id, String ip, Protocol protocol, Object result) {
		String
			name,
			message;
		boolean status;
			
		try(Connection c = DriverManager.getConnection(this.db, this.properties)) {
			synchronized(this.nextEventID) {				
				try (PreparedStatement pstmt = c.prepareStatement("SELECT name FROM node WHERE id=?;")) {
					pstmt.setLong(1, id);
					
					try (ResultSet rs = pstmt.executeQuery()) {
						if (!rs.next()) {
							return;
						}
						
						name = rs.getString(1) == null? ip: rs.getString(1);
					}
				}
				
				switch (protocol) {
				case ICMP:
					status = (Boolean)result;
					
					if (status && registerICMPNode(id, ip)) {
						message = String.format("%s ICMP �벑濡� �꽦怨�.", name);
					}
					else {
						
						message = String.format("%s ICMP �벑濡� �떎�뙣.", name);
					}
					
					break;
				case TCP:
					status = (Boolean)result;
					
					if (status && registerTCPNode(id, ip)) {
						message = String.format("%s ICMP �벑濡� �꽦怨�.", name);
					}
					else {
						message = String.format("%s ICMP �벑濡� �떎�뙣.", name);
					}
					
					break;
				default:
					status = result != null;
					
					if (status && registerSNMPNode(id, ip, (String)result)) {
						message = String.format("%s SNMP �벑濡� �꽦怨�.", name);
					}
					else {
						message = String.format("%s SNMP �벑濡� �떎�뙣.", name);
					}
				}
				
				sendEvent(this.nextEventID, "register", id, status? 0: 1, name, message);
				
				this.nextEventID++;
			}
		}
		catch (SQLException sqle) {
			System.err.print(sqle);
		}
	}
	
	@Override
	public void onEvent(Object caller, Object ...event) {
		if (caller instanceof SMTP) {
			// event = exception
			// SMTP �삤瑜�. + ((Exception)event).getMessage()
		}
		else if (caller instanceof SmartSearch) {
			onSearchEvent((String)event[0], (String)event[1]);
		}
	}

	private void onSearchEvent(String ip, String profile) {
		try (Connection c = DriverManager.getConnection(db)) {
			synchronized(this.nextEventID) {
				synchronized(this.nextNodeID) {
					String name = null;
					long id;
					
					try (PreparedStatement pstmt = c.prepareStatement("SELECT id, name FROM node WHERE ip=?;")) {
						pstmt.setString(1, ip);
						
						try(ResultSet rs = pstmt.executeQuery()) {
							if (!rs.next()) {
								try (PreparedStatement pstmt2 = c.prepareStatement("INSERT INTO node (id, ip) values (?, ?);")) {
									pstmt2.setLong(1, this.nextNodeID);
									pstmt2.setString(2, ip);
								}
								
								id = this.nextNodeID;
							}
							else {
								id = rs.getLong(1);
								name =  rs.getString(2);
							}
							
							if (name == null) {
								name = ip;
							}
						}
					}
					
					if (registerSNMPNode(id, ip, profile)) {
						sendEvent(this.nextEventID, "search", id, 0, name, String.format("SNMP �끂�뱶 %s �깘吏� �꽦怨�.", name));
					}
					
					this.nextNodeID++;
				}
				
				this.nextEventID++;
			}
		} catch (SQLException sqle) {
			System.err.print(sqle);
		}
	}
	
	/**
	 * 
	 * @param id
	 * @param ip
	 * @param name profile name
	 */
	private boolean registerSNMPNode(long id, String ip, String name) {
		try (Connection c = DriverManager.getConnection(db)) {
			if (this.statusMap.containsKey(id)) {
				if (this.snmpMap.containsKey(id)) {
					if (this.snmpMap.get(id) == 0) {
						return false;
					}
				}
				
				nodeManager.removeNode(id);
				
				// update monitor
				try (PreparedStatement pstmt = c.prepareStatement("UPDATE monitor SET protocol=?, status=true, snmp=0 WHERE id=?;")) {
					pstmt.setString(1, name);
					pstmt.setLong(2, id);
					
					pstmt.executeUpdate();
				}
			}
			else {
				// insert monitor
				
				try (PreparedStatement pstmt = c.prepareStatement("INSERT INTO monitor (id, ip, protocol, status, snmp) VALUES (?, ?, ?, 1, 0);")) {
					pstmt.setLong(1, id);
					pstmt.setString(2, ip);
					pstmt.setString(3, name);
					
					pstmt.executeUpdate();
				}	
			}
					
			try (PreparedStatement pstmt = c.prepareStatement("SELECT port, version, security, COALESCE(level, 0) FROM profile WHERE name=?;")) {
				pstmt.setString(1, name);
				
				try (ResultSet rs = pstmt.executeQuery()) {
					if (rs.next()) {
						this.nodeManager.createNode(id, ip, rs.getInt(1), rs.getString(2), rs.getString(3), rs.getInt(4));
					}
				}			
			}
				
			this.statusMap.put(id, true);
			this.snmpMap.put(id, 0);
			
			return true;
		} catch (Exception sqle) {
			System.err.print(sqle);
		}
		
		return false;
	}
	
	private boolean registerICMPNode(long id, String ip) {
		try (Connection c = DriverManager.getConnection(db)) {
			if (this.statusMap.containsKey(id)) { // SNMPNode or ICMPNode
				if (this.snmpMap.containsKey(id)) { // SNMPNode
					nodeManager.removeNode(id);
					
					this.snmpMap.remove(id);
				}
				else { // ICMPNode
					return false;
				}
				
				// update monitor
				try (PreparedStatement pstmt = c.prepareStatement("UPDATE monitor SET protocol='icmp', status=true, snmp=0 WHERE id=?;")) {
					pstmt.setLong(1, id);
					
					pstmt.executeUpdate();
				}
			}
			else {
				// insert monitor
				try (PreparedStatement pstmt = c.prepareStatement("INSERT INTO monitor (id, ip, protocol) VALUES (?, ?, 'icmp');")) {
					pstmt.setLong(1, id);
					pstmt.setString(2, ip);
					
					pstmt.executeUpdate();
				}	
			}
			
			this.nodeManager.createNode(id, ip, "icmp");
			
			this.statusMap.put(id, true);
			
			return true;
		} catch (Exception sqle) {
			System.err.print(sqle);
		}
		
		return false;
	}
	
	private boolean registerTCPNode(long id, String ip) {
		if (this.statusMap.containsKey(id)) {
			return false;
		}
		
		try (Connection c = DriverManager.getConnection(db)) {
			try (PreparedStatement pstmt = c.prepareStatement("INSERT INTO monitor (id, ip, protocol) VALUES (?, ?, 'tcp');")) {
				pstmt.setLong(1, id);
				pstmt.setString(2, ip);
				
				pstmt.executeUpdate();
			}
			
			this.nodeManager.createNode(id, ip, "tcp");
			
			this.statusMap.put(id, true);
			
			return true;
		} catch (Exception e) {
			System.err.print(e);
		}
		
		return false;
	}
	
	@Override
	public boolean removeAccount(String username) {
		try (Connection c = DriverManager.getConnection(this.db, this.properties)) {
			c.setAutoCommit(false);
			
			try {
				try (PreparedStatement pstmt = c.prepareStatement("DELETE FROM account WHERE username=?;")) {
					pstmt.setString(1, username);
					
					pstmt.executeUpdate();
				}
				
				try (Statement stmt = c.createStatement()) {
					try (ResultSet rs = stmt.executeQuery("SELECT username FROM account WHERE level=0;")) {
						if (!rs.next()) {
							throw new SQLException();
						}
					}
				}
				
				c.commit();
				
				return true;
			} catch (SQLException sqle) {
				c.rollback();
				
				throw sqle;
			} finally {
				c.setAutoCommit(true);
			}
		} catch (SQLException sqle) {
			System.err.print(sqle);
		}
		
		return false;
	}

	@Override
	public void removeEventListener(Listener listener) {
		this.listenerList.remove(listener);
	}
	
	@Override
	public boolean removeIcon(String type) {
		try (Connection c = DriverManager.getConnection(this.db, this.properties)) {
			try (PreparedStatement pstmt = c.prepareStatement("DELETE FROM icon WHERE type=?;")) {
				pstmt.setString(1, type);
				
				pstmt.executeUpdate();
				
				return true;
			}
		} catch (SQLException sqle) {
			System.err.print(sqle);
		}
		
		return false;
	}
	
	@Override
	public boolean removeLink(long id) {
		try (Connection c = DriverManager.getConnection(this.db, this.properties)) {
			try (PreparedStatement pstmt = c.prepareStatement("DELETE FROM link WHERE id=?;")) {
				pstmt.setLong(1, id);
				
				pstmt.executeUpdate();
				
				return true;
			}
		} catch (SQLException sqle) {
			System.err.print(sqle);
		}
		
		return false;
	}
	
	@Override
	public boolean removeNode(long id) {
		try (Connection c = DriverManager.getConnection(this.db, this.properties)) {
			c.setAutoCommit(false);
			
			try {
				try (Statement stmt = c.createStatement()) {
					try (ResultSet rs = stmt.executeQuery("SELECT position FROM position where name='position';")) {
						if (rs.next()) {
							JSONObject position = new JSONObject(rs.getString(1));
							
							position.remove(Long.toString(id));
							
							try (PreparedStatement pstmt = c.prepareStatement("UPDATE position set position=? where name='position';")) {
								pstmt.setString(1, position.toString());
								
								pstmt.executeUpdate();
							}
						}
					}
				}
				
				try (PreparedStatement pstmt = c.prepareStatement("DELETE FROM link WHERE node_from=? OR node_to=?;")) {
					pstmt.setLong(1, id);
					pstmt.setLong(2, id);
					
					pstmt.executeUpdate();
				}
				
				try (PreparedStatement pstmt = c.prepareStatement("DELETE FROM path WHERE node_from=? OR node_to=?;")) {
					pstmt.setLong(1, id);
					pstmt.setLong(2, id);
					
					pstmt.executeUpdate();
				}
				
				try (PreparedStatement pstmt = c.prepareStatement("DELETE FROM node WHERE id=?;")) {
					pstmt.setLong(1, id);
					
					pstmt.executeUpdate();
				}
				
				try (PreparedStatement pstmt = c.prepareStatement("DELETE FROM monitor WHERE id=?;")) {
					pstmt.setLong(1, id);
					
					pstmt.executeUpdate();
				}
				
				c.commit();
				
				this.nodeManager.removeNode(id);
				
				this.statusMap.remove(id);
				this.snmpMap.remove(id);
				
				return true;
			} catch (SQLException sqle) {
				c.rollback();
				
				throw sqle;
			} finally {
				c.setAutoCommit(true);
			}
		} catch (SQLException sqle) {
			System.err.print(sqle);
		}
		
		return false;
	}
	
	@Override
	public boolean removePath(long nodeFrom, long nodeTo) {
		try (Connection c = DriverManager.getConnection(this.db, this.properties)) {
			c.setAutoCommit(false);
			
			try {
				try (PreparedStatement pstmt = c.prepareStatement("DELETE FROM link WHERE node_from=? AND node_to=?;")) {
					pstmt.setLong(1, nodeFrom);
					pstmt.setLong(2, nodeTo);
					
					pstmt.executeUpdate();
				}
				
				try (PreparedStatement pstmt = c.prepareStatement("DELETE FROM path WHERE node_from=? AND node_to=?;")) {
					pstmt.setLong(1, nodeFrom);
					pstmt.setLong(2, nodeTo);
					
					pstmt.executeUpdate();
				}
				
				c.commit();
				
				return true;
			} catch (SQLException sqle) {
				c.rollback();
				
				throw sqle;
			} finally {
				c.setAutoCommit(true);
			}
		} catch (SQLException sqle) {
			System.err.print(sqle);
		}
		
		return false;
	}
	
	@Override
	public boolean removeProfile(String name) {
		try (Connection c = DriverManager.getConnection(this.db, this.properties)) {
			c.setAutoCommit(false);
		
			try {
				try (PreparedStatement pstmt = c.prepareStatement("SELECT id FROM monitor WHERE protocol=? LIMIT 1;")) {
					pstmt.setString(1, name);
					
					try (ResultSet rs = pstmt.executeQuery()) {
						if(rs.next()) {
							return false;
						}
					}
				}
				
				try (PreparedStatement pstmt = c.prepareStatement("DELETE FROM profile WHERE name=?;")) {
					pstmt.setString(1, name);
					
					pstmt.executeUpdate();
				}
		
				c.commit();
				
				return true;
			} catch (SQLException sqle) {
				c.rollback();
				
				throw sqle;
			} finally {
				c.setAutoCommit(true);
			}
		} catch (SQLException sqle) {
				System.err.print(sqle);
		}
		
		return false;
	}
	
	@Override
	public boolean removeUser(String name) {
		try (Connection c = DriverManager.getConnection(this.db, this.properties)) {
			try (PreparedStatement pstmt = c.prepareStatement("DELETE FROM user WHERE name=?;")) {
				pstmt.setString(1, name);
				
				pstmt.executeUpdate();
				
				return true;
			}
		} catch (SQLException sqle) {
			System.err.print(sqle);
		}
		
		return false;
	}
	
	@Override
	public boolean search(String network, int mask) {
		try {
			JSONObject profileList = getProfile(), profile;
			Profile	args [] = new Profile[profileList.length()];
			int i = 0;
			SmartSearch search;
			
			for (Object o: profileList.keySet()) {
				profile = profileList.getJSONObject((String)o);
				
				args[i++] = new Profile(profile.getString("name"), profile.getString("version"), profile.getInt("port"), profile.getString("sucurity"), profile.getInt("level"));
			}
			
			search = new SmartSearch(this.nodeManager, new Network(network, mask), args);
			
			search.addEventListener(this);
			
			search.start();
			
			return true;
		} catch (IOException ioe) {
			System.err.print(ioe);
		}
		
		return false;
	}
	
	private void sendEvent (long eventID, String origin, long id, int level, String name, String message) throws SQLException {
		JSONObject event = new JSONObject()
			.put("eventID", eventID)
			.put("origin", origin)
			.put("id", id)
			.put("level", level)
			.put("name", name)
			.put("message", message);
		
		try (Connection c = DriverManager.getConnection(this.db, this.properties)) {
			try (PreparedStatement pstmt = c.prepareStatement("INSERT INTO event (id, timestamp, origin, level, message, name, event_id, date)"+
				" VALUES(?, ?, ?, ?, ?, ?, ?, ?);")) {
				Calendar calendar = Calendar.getInstance();
			
				pstmt.setLong(1, id);
				pstmt.setLong(2, calendar.getTimeInMillis());
				pstmt.setString(3, "snmp");
				pstmt.setInt(4, level);
				pstmt.setString(5, message);
				pstmt.setString(6, name);
				pstmt.setLong(7, this.nextEventID);
				
				calendar.set(Calendar.HOUR_OF_DAY, 0);
				calendar.set(Calendar.MINUTE, 0);
				calendar.set(Calendar.SECOND, 0);
				calendar.set(Calendar.MILLISECOND, 0);
				
				pstmt.setLong(8, calendar.getTimeInMillis());
				
				pstmt.executeUpdate();
			}
			
			fireEvent(event);
		}
	}
	
	@Override
	public boolean setAccount(String username, JSONObject account) {
		try (Connection c = DriverManager.getConnection(this.db, this.properties)) {
			c.setAutoCommit(false);
			
			try {
				try (PreparedStatement pstmt = c.prepareStatement("UPDATE account SET password=?, level=? WHERE username=?;")) {
					pstmt.setString(1, account.getString("password"));
					pstmt.setInt(2, account.getInt("level"));
					pstmt.setString(3, account.getString("username"));
					
					pstmt.executeUpdate();
				}
				
				try (Statement stmt = c.createStatement()) {
					try (ResultSet rs = stmt.executeQuery("SELECT username FROM account WHERE level=0;")) {
						if (!rs.next()) {
							throw new SQLException();
						}
					}
				}
				
				c.commit();
				
				return true;
			} catch (SQLException sqle) {
				c.rollback();
				
				throw sqle;
			} finally {
				c.setAutoCommit(true);
			}
		} catch (SQLException sqle) {
			System.err.print(sqle);
		}
		
		return false;
	}

	@Override
	public boolean setLink(long nodeFrom, long nodeTo, JSONObject link) {
		try (Connection c = DriverManager.getConnection(db)) {
			try (PreparedStatement pstmt = c.prepareStatement("UPDATE link SET"+
					" index_from=?"+
					", index_to=?"+
					", extra=?"+
					" WHERE id=?;")) {
		
				if (link.has("indexFrom")) {
					pstmt.setLong(1, link.getLong("indexFrom"));
				} else {
					pstmt.setNull(1, Types.NULL);
				}
				
				if (link.has("indexTo")) {
					pstmt.setLong(2, link.getLong("indexTo"));
				} else {
					pstmt.setNull(2, Types.NULL);
				}
				
				if (link.has("extra")) {
					link.getJSONObject("extra").toString();
				} else {
					pstmt.setNull(3, Types.NULL);
				}
				
				pstmt.setLong(4, link.getLong("id"));
				
				pstmt.executeUpdate();
				
				return true;
			}
		} catch (SQLException sqle) {
			System.err.print(sqle);
		}
		
		return false;
	}
	
	@Override
	public boolean setRetry(int retry) {		
		try (Connection c = DriverManager.getConnection(this.db, this.properties)) {
			try (PreparedStatement pstmt = c.prepareStatement("INSERT OR REPLACE INTO config (key, value) VALUES"+
				" ('retry', ?);")) {
				pstmt.setString(1, Integer.toString(retry));
				
				pstmt.executeUpdate();
								
				this.nodeManager.setRetry(retry);
				
				return true;
			}
		} catch (SQLException sqle) {
			System.err.print(sqle);
		}
		
		return false;
	}

	@Override
	public boolean setRequestInterval(long interval) {
		try (Connection c = DriverManager.getConnection(this.db, this.properties)) {
			try (PreparedStatement pstmt = c.prepareStatement("INSERT OR REPLACE INTO config (key, value) VALUES"+
					" ('snmpInterval', ?);")) {
				pstmt.setString(1, Long.toString(interval));
				
				pstmt.executeUpdate();
				
				this.nodeManager.setInterval(interval);
				
				return true;
			}
		} catch (SQLException sqle) {
			System.err.print(sqle);

		}
		
		return false;
	}

	
	@Override
	public boolean setTimeout(int timeout) {		
		try (Connection c = DriverManager.getConnection(this.db, this.properties)) {
			try (PreparedStatement pstmt = c.prepareStatement("INSERT OR REPLACE INTO config (key, value) VALUES"+
				" ('timeout', ?);")) {
				pstmt.setString(1, Integer.toString(timeout));
				
				pstmt.executeUpdate();
				
				this.nodeManager.setTimeout(timeout);
				
				return true;
			}
		} catch (SQLException sqle) {
			System.err.print(sqle);
		}
		
		return false;
	}

	@Override
	public boolean setSaveInterval(int interval) {
		try (Connection c = DriverManager.getConnection(this.db, this.properties)) {
			try (PreparedStatement pstmt = c.prepareStatement("INSERT OR REPLACE INTO config (key, value) VALUES"+
				" ('saveInterval', ?);")) {
				pstmt.setString(1, Integer.toString(interval));
				
				pstmt.executeUpdate();
				
				//TODO ���옣 �씤�꽣踰� �쟻�슜�븯湲� 
				
				return true;
			}
		} catch (SQLException sqle) {
			System.err.print(sqle);
		}
		
		return false;
	}

	@Override
	public SMTP setSMTPServer(JSONObject smtp) {
		if (smtp.has("disabled") && smtp.getBoolean("disabled")) {
			try (Connection c = DriverManager.getConnection(this.db, this.properties)) {
				try (Statement stmt = c.createStatement()){
					stmt.executeUpdate("UPDATE config SET value='true' where key='smtpDisabled';");
			
					//TODO SMTP �꽌踰� �룞�옉 以묒�
					
					return null;
				}
			} catch (SQLException sqle) {					
				System.err.print(sqle);
			}
		}
		else {
			SMTP smtpServer;
			String
				server = smtp.getString("server"),
				user = smtp.getString("user"),
				password = smtp.getString("password"),
				protocol = smtp.getString("protocol");
			
			switch(protocol.toUpperCase()) {
			case "SMTP":
				smtpServer = new SMTP(server, user);
				
				break;
			case "TLS":
				smtpServer = new SMTP(server, user, password, SMTP.Protocol.TLS);
				
				break;
			case "SSL":
				smtpServer = new SMTP(server, user, password, SMTP.Protocol.SSL);
				
				break;
			default:
				return null;
			}
			
			try (Connection c = DriverManager.getConnection(this.db, this.properties)) {
				try (PreparedStatement pstmt = c.prepareStatement("INSERT OR REPLACE INTO config (key, value) VALUES"+
					" ('smtpServer', ?)"+
					" ,('smtpProtocol', ?)"+
					" ,('smtpUser', ?)"+
					" ,('smtpPassword', ?)"+
					" ,('smtpdisabled', 'false');")) {
					
					pstmt.setString(1, server);
					pstmt.setString(2, protocol);
					pstmt.setString(3, user);
					pstmt.setString(4, password);
					
					pstmt.executeUpdate();
					
					return smtpServer;
				}
			} catch (SQLException sqle) {
				System.err.print(sqle);
			}
		}
		
		return null;
	}

	@Override
	public boolean setStoreDate(int period) {
		try (Connection c = DriverManager.getConnection(this.db, this.properties)) {
			try (PreparedStatement pstmt = c.prepareStatement("INSERT OR REPLACE INTO config (key, value) VALUES"+
				" ('storeDate', ?)")) {
				pstmt.setString(1, Integer.toString(period));
				
				pstmt.executeUpdate();
				//TODO �뙆�씪�젙由� �꽕�젙�븯湲�
				
				return true;
			} 
		} catch (SQLException sqle) {
			System.err.print(sqle);
		}
		
		return false;	
	}
	
	@Override
	public boolean setNode(long id, JSONObject node) {
		try (Connection c = DriverManager.getConnection(this.db, this.properties)) {
			try (PreparedStatement pstmt = c.prepareStatement("UPDATE node SET"+
				" name=?"+
				", type=?"+
				", label=?"+
				", extra=?"+
				" WHERE id=?;")) {
				if (node.has("name")) {
					pstmt.setString(1, node.getString("name"));
				}
				else {
					pstmt.setNull(1, Types.NULL);
				}
				
				if (node.has("type")) {
					pstmt.setString(2, node.getString("type"));
				}
				else {
					pstmt.setNull(2, Types.NULL);
				}
				
				if (node.has("label")) {
					pstmt.setString(3, node.getString("label"));
				}
				else {
					pstmt.setNull(3, Types.NULL);
				}
				
				if (node.has("extra")) {
					pstmt.setString(4, node.getString("extra"));
				}
				else {
					pstmt.setNull(4, Types.NULL);
				}
				
				pstmt.setLong(5, id);
				
				pstmt.executeUpdate();
				
				return true;
			}
		} catch (SQLException sqle) {
			System.err.print(sqle);
		}
		
		return false;
	}

	@Override
	public boolean setCritical(long id, JSONObject critical) {
		return true;		
	}

	@Override
	public boolean setIcon(String type, JSONObject icon) {
		try (Connection c = DriverManager.getConnection(this.db, this.properties)) {
			try (PreparedStatement pstmt = c.prepareStatement("UPDATE icon SET"+
				" _group=?,"+
				" src=?,"+
				" disabled=?"+
				" WHERE type=?;")) {
				pstmt.setString(1, icon.getString("group"));
				pstmt.setString(2, icon.getString("src"));
				pstmt.setString(3, icon.getString("disabled"));
				pstmt.setString(4, icon.getString("type"));
				
				pstmt.executeUpdate();
				
				return true;
			}
		} catch (SQLException sqle) {
			System.err.print(sqle);
		}
		
		return false;
	}
	
	@Override
	public boolean setPath(long nodeFrom, long nodeTo, JSONObject path) {
		try (Connection c = DriverManager.getConnection(this.db, this.properties)) {
			try (PreparedStatement pstmt = c.prepareStatement("UPDATE path SET"+
				" type=?,"+
				" color=?,"+
				" size=?"+
				" WHERE node_from=? AND node_to=?;")) {
				if (path.has("type")) {
					pstmt.setString(1, path.getString("type"));	
				}
				else {
					pstmt.setNull(1, Types.NULL);
				}
				
				if (path.has("color")) {
					pstmt.setString(2, path.getString("color"));
				}
				else {
					pstmt.setNull(2, Types.NULL);
				}
				
				if (path.has("size")) {
					pstmt.setLong(3, path.getInt("size"));
				}
				else {
					pstmt.setNull(3, Types.NULL);
				}
				
				pstmt.setLong(4, nodeFrom);
				pstmt.setLong(5, nodeTo);
				
				pstmt.executeUpdate();
				
				return true;
			}
		} catch (SQLException sqle) {
			System.err.print(sqle);
		}
		
		return false;
	}

	@Override
	public boolean setMonitor(long id, String ip, String protocol) {
		if (protocol == null) {
			try (Connection c = DriverManager.getConnection(this.db, this.properties)) {
				try (PreparedStatement pstmt = c.prepareStatement("DELETE FROM monitor WHERE id=?;")) {
					pstmt.setLong(1, id);
					
					pstmt.executeUpdate();
					
					this.nodeManager.removeNode(id);
					
					this.statusMap.remove(id);
					this.snmpMap.remove(id);
				}
			} catch (SQLException sqle) {
				System.err.print(sqle);
				
				return false;
			}
		}
		else if (protocol.toUpperCase().equals("SNMP")){
			JSONObject
				profiles = this.getProfile(),
				p;
			Arguments args [] = new Arguments [profiles.length()];
			int i = 0;
			
			for (Object key : profiles.keySet()) {
				p = profiles.getJSONObject((String)key);
				
				args[i] = new Arguments(p.getString("name"),
					p.getInt("port"),
					p.getString("version"),
					p.getString("security"),
					p.has("level")? p.getInt("level"): 0);
			}
			
			this.nodeManager.testNode(id, ip, protocol, args);
		}
		else {
			this.nodeManager.testNode(id, ip, protocol);
		}
		
		return true;
	}

	@Override
	public boolean setPosition(String name, JSONObject position) {
		try (Connection c = DriverManager.getConnection(db)) {
			try (PreparedStatement pstmt = c.prepareStatement("UPDATE position SET"+
				" position=?"+
				" where name=?;")) {
				pstmt.setString(1, position.toString());
				pstmt.setString(2, name);
				
				pstmt.executeUpdate();
				
				return true;
			}
		} catch (SQLException sqle) {
			System.err.print(sqle);
		}
		
		return false;
	}

	@Override
	public boolean setSetting(String key, String value) {
		try (Connection c = DriverManager.getConnection(db)) {
			try (PreparedStatement pstmt = c.prepareStatement("INSERT INTO setting (key, value) VALUES"+
					" (?, ?)"+
					" ON CONFLICT(key) DO UPDATE SET value=?;")) {
		
				pstmt.setString(1, key);
				
				if (value == null) {
					pstmt.setNull(2, Types.NULL);
					pstmt.setNull(3, Types.NULL);
				}
				else {
					pstmt.setString(2, value);
					pstmt.setString(3, value);
				}
				
				pstmt.executeUpdate();
				
				return true;
			}
		} catch (SQLException sqle) {
			System.err.print(sqle);
		}
		
		return false;
	}
	
	@Override
	public boolean setSpeed(long id, JSONObject critical) {
		return true;
	}
	
	@Override
	public boolean setUser(String name, JSONObject user) {
		try (Connection c = DriverManager.getConnection(this.db, this.properties)) {
			try (PreparedStatement pstmt = c.prepareStatement("UPDATE user SET"+
				" email=?,"+
				" sms=?,"+
				" WHERE name=?;")) {
				pstmt.setString(1, user.getString("email"));
				pstmt.setString(2, user.getString("sms"));
				pstmt.setString(3, user.getString("name"));
				
				pstmt.executeUpdate();
			} 
		} catch (SQLException sqle) {
			System.err.print(sqle);
			
			return false;
		}
		
		return true;
	}

	@Override
	public boolean setUpDown(long id, JSONObject critical) {
		return true;
	}

	@Override
	public void start() throws Exception {
		try (Connection c = DriverManager.getConnection(this.db, this.properties)) {
			try (Statement stmt = c.createStatement()) {
				try (ResultSet rs = stmt.executeQuery("SELECT security, level, auth_protocol, auth_key, priv_protocol, priv_key FROM profile WHERE version='v3';")) {
					while (rs.next()) {
						this.nodeManager.addUSMUser(rs.getString(1), rs.getInt(2), rs.getString(3), rs.getString(4), rs.getString(5), rs.getString(6));	
					}
				}
			}
			
			try (Statement stmt = c.createStatement()) {
				try (ResultSet rs = stmt.executeQuery("SELECT id, ip, m.protocol, port, version, security, level, status, snmp"+
					" FROM monitor AS m LEFT JOIN profile AS p ON m.protocol = p.name;")) {
					long id;
					
					while (rs.next()) {
						System.out.print("!");
					
						id = rs.getLong(1);
						
						switch(rs.getString(3).toUpperCase()) {
						case "ICMP":
						case "TCP":
							this.nodeManager.createNode(id, rs.getString(2), rs.getString(3));
							
							break;
						default:
							this.nodeManager.createNode(id, rs.getString(2), rs.getInt(4), rs.getString(5), rs.getString(6), rs.getInt(7));
							
							this.snmpMap.put(id, rs.getInt(9));
						}
						
						this.statusMap.put(id, rs.getBoolean(8));
					}
					
					System.out.println();
				}
			}
		}
	}
	
	public class Rule {
		public final String oid;
		public final String name;
		public final String syntax;
		public final boolean rolling;
		public final boolean onChange;
		
		private Rule(String oid, String name, String syntax, boolean rolling, boolean onChange) {
			this.oid = oid;
			this.name = name;
			this.syntax = syntax;
			this.rolling = rolling;
			this.onChange = onChange;
		}
	}

	@Override
	public JSONObject getResource(long id, int index, String oid, long date, boolean summary) {
		// TODO Auto-generated method stub
		return null;
	}
}
