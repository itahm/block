package com.itahm.block;

import java.io.Closeable;
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

import org.snmp4j.smi.OID;
import org.snmp4j.smi.Variable;

import com.itahm.block.NodeManager;
import com.itahm.block.SMTP;
import com.itahm.block.command.Commander;
import com.itahm.json.JSONException;
import com.itahm.json.JSONObject;
import com.itahm.util.Listener;
import com.itahm.util.Network;

public class Agent implements Commander, Closeable, Listener {
	
	private final String MD5_ROOT = "63a9f0ea7bb98050796b649e85481845";
	private final long DEF_SNMP_INTV = 10000;
	private final int DEF_STORE = 0;
	private final long DEF_SAVE_INTV = 60000;
	private final int DEF_TOP_CNT = 5;
	private final int DEF_TIMEOUT = 5000;
	private final int DEF_RETRY = 2;
	
	private Boolean isClosed = false;
	private Long lastNodeID = Long.valueOf(1);
	private Long lastLinkID = Long.valueOf(1);
	private final Memory memory = new Memory();
	private final String db;
	private final ArrayList<Listener> listenerList = new ArrayList<>();
	private final NodeManager nodeManager;
	
	{
		try {
			Class.forName("org.sqlite.JDBC");
		} catch (ClassNotFoundException cnfe) {
			System.err.print(cnfe);
		}	
	}
	
	public Agent(Path root) throws IOException, SQLException {
		System.out.println("Commander: Agent v1.0");
		
		nodeManager = new NodeManager(this);
		
		db = "jdbc:sqlite:"+ root.resolve("sql.db").toString();
		
		try (Connection c = DriverManager.getConnection(db)) {
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
				
				try (Statement stmt = c.createStatement()) {
					try (ResultSet rs = stmt.executeQuery("SELECT * FROM account")) {
						while (rs.next()) {
							memory.addAccount(rs.getString(1), new JSONObject()
								.put("username", rs.getString(1))
								.put("password", rs.getString(2))
								.put("level", rs.getInt(3)));
						}
					}
				}
				
				if (memory.getAccount().length() == 0) {
					try (Statement stmt = c.createStatement()) {
						stmt.executeUpdate("INSERT INTO ACCOUNT "+
							" (username, password)"+
							" values('root', '"+ MD5_ROOT +"');");
					}
					
					memory.addAccount("root", new JSONObject()
						.put("username", "root")
						.put("password", MD5_ROOT)
						.put("level", 0));
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
				
				try (PreparedStatement pstmt = c.prepareStatement("INSERT OR IGNORE INTO config (key, value) VALUES" + 
						" ('timeout', ?)"+
						", ('retry', ?)"+
						", ('snmpInterval', ?)"+
						", ('store', ?)"+
						", ('saveInterval', ?)"+
						", ('topCount', ?);")) {
					pstmt.setString(1, Long.toString(DEF_TIMEOUT));
					pstmt.setString(2, Long.toString(DEF_RETRY));
					pstmt.setString(3, Long.toString(DEF_SNMP_INTV));
					pstmt.setString(4, Integer.toString(DEF_STORE));
					pstmt.setString(5, Long.toString(DEF_SAVE_INTV));
					pstmt.setString(6, Integer.toString(DEF_TOP_CNT));
					
					pstmt.executeUpdate();
				}
				
				try (Statement stmt = c.createStatement()) {
					try (ResultSet rs = stmt.executeQuery("SELECT * FROM config")) {
						while (rs.next()) {
							memory.addConfig(rs.getString(1), rs.getString(2));
						}
					}
				}
				/**END**/
				
				/**
				 * EVENT
				 */
				try (Statement stmt = c.createStatement()) {
					stmt.executeUpdate("CREATE TABLE IF NOT EXISTS event"+
						" (id INTEGER NOT NULL"+
						", timestamp INTEGER NOT NULL"+
						", origin TEXT NOT NULL"+
						", status INTEGER NOT NULL"+
						", message TEXT NOT NULL"+
						", ip TEXT DEFAULT NULL"+
						", name TEXT NOT NULL"+
						", date INTEGER NOT NULL"+
						", PRIMARY KEY(id));");
				}
				
				try (Statement stmt = c.createStatement()) {
					stmt.executeUpdate("CREATE INDEX IF NOT EXISTS idx ON event (date);");
				}
				/**END**/
				
				/**
				 * ICON
				 */
				try (Statement stmt = c.createStatement()) {
					stmt.executeUpdate("CREATE TABLE IF NOT EXISTS icon"+
						" (type TEXT NOT NULL"+
						", _group TEXT NOT NULL"+
						", alt TEXT NOT NULL"+
						", src TEXT NOT NULL"+
						", disabled TEXT NOT NULL"+
						", unit INT NOT NULL DEFAULT 1"+
						", color TEXT(7) NOT NULL DEFAULT '#000000'"+
						", texture TEXT DEFAULT NULL"+
						", top TEXT DEFAULT NULL"+
						", PRIMARY KEY(type));");
				}
				
				try (Statement stmt = c.createStatement()) {
					try (ResultSet rs = stmt.executeQuery("SELECT type, _group, alt, src, disabled, unit, color, texture, top FROM icon")) {
						while (rs.next()) {
							memory.addIcon(rs.getString(1), new JSONObject()
								.put("type", rs.getString(1))
								.put("group", rs.getString(2))
								.put("alt", rs.getString(3))
								.put("src", rs.getString(4))
								.put("disabled", rs.getString(5))
								.put("unit", rs.getInt(6))
								.put("color", rs.getString(7))
								.put("texture", rs.getString(8))
								.put("top", rs.getString(9)));
						}
					}
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
					try (ResultSet rs = stmt.executeQuery("SELECT id, node_from, node_to, index_from, index_to FROM link ORDER BY id;")) {
						while (rs.next()) {
							memory.setLink(rs.getLong(2), rs.getLong(3), rs.getLong(1), new JSONObject()
								.put("id", rs.getLong(1))
								.put("nodeFrom", rs.getLong(2))
								.put("nodeTo", rs.getLong(3))
								.put("indexFrom", rs.getLong(4))
								.put("indexTo", rs.getLong(5)));
							
							lastLinkID = rs.getLong(1);
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
				
				try (Statement stmt = c.createStatement()) {
					try (ResultSet rs = stmt.executeQuery("SELECT id, ip, protocol, status, snmp FROM monitor")) {
						while (rs.next()) {
							memory.addMonitor(rs.getLong(1), new JSONObject()
								.put("id", rs.getLong(1))
								.put("ip", rs.getString(2))
								.put("protocol", rs.getString(3))
								.put("status", rs.getInt(4) == 0? false: true)
								.put("snmp", rs.getInt(5)));
						}
					}
				}
				/**END**/
				
				/**
				 * NODE
				 */
				try (Statement stmt = c.createStatement()) {
					stmt.executeUpdate("CREATE TABLE IF NOT EXISTS node"+
						" (id INTEGER NOT NULL"+
						", name TEXT DEFAULT NULL"+
						", type TEXT DEFAULT NULL"+
						", ip TEXT DEFAULT NULL"+
						", label TEXT DEFAULT NULL"+
						", PRIMARY KEY(id));");
				}
				
				try (Statement stmt = c.createStatement()) {
					stmt.executeUpdate("CREATE INDEX IF NOT EXISTS idx ON node (ip);");
				}
				
				try (Statement stmt = c.createStatement()) {
					try (ResultSet rs = stmt.executeQuery("SELECT id, name, type, ip, label FROM node ORDER BY id")) {
						while (rs.next()) {
							memory.addNode(rs.getLong(1), new JSONObject()
								.put("id", rs.getLong(1))
								.put("name", rs.getString(2) == null? JSONObject.NULL: rs.getString(2))
								.put("type", rs.getString(3) == null? JSONObject.NULL: rs.getString(3))
								.put("ip", rs.getString(4) == null? JSONObject.NULL: rs.getString(4))
								.put("label", rs.getString(5) == null? JSONObject.NULL: rs.getString(5)));
							
							lastNodeID = rs.getLong(1);
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
				
				try (Statement stmt = c.createStatement()) {
					try (ResultSet rs = stmt.executeQuery("SELECT node_from, node_to, type, color, size FROM path;")) {
						JSONObject path;
						
						while (rs.next()) {
							path = new JSONObject()
								.put("nodeFrom", rs.getLong(1))
								.put("nodeTo", rs.getLong(2));
							
							if (rs.getString(3) != null) {
								path.put("type", rs.getString(3));
							}
							
							if (rs.getString(4) != null) {
								path.put("color", rs.getString(4));
							}
							
							if (rs.getInt(5) > 0) {
								path.put("size", rs.getInt(5));
							}
							
							memory.setPath(rs.getLong(1), rs.getLong(2), path);
						}
					}
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
				
				try (Statement stmt = c.createStatement()) {
					try (ResultSet rs = stmt.executeQuery("SELECT * FROM position")) {
						while (rs.next()) {
							memory.addPosition(rs.getString(1), rs.getString(2));
						}
					}
				}
				
				
				if (memory.getPosition().length() == 0) {
					try (Statement stmt = c.createStatement()) {
						stmt.executeUpdate("INSERT INTO position DEFAULT VALUES;");
						
						memory.addPosition("position", "{}");
					}
				}
				/**END**/
				
				/**
				 * PROFILE
				 */
				try (Statement stmt = c.createStatement()) {
					stmt.executeUpdate("CREATE TABLE IF NOT EXISTS profile"+
						" (name TEXT NOT NULL"+
						", protocol TEXT NOT NULL"+
						", port INTEGER NOT NULL"+
						", version TEXT NOT NULL"+
						", security TEXT NOT NULL"+
						", active INTEGER not null default 0"+
						", authProtocol TEXT DEFAULT NULL"+
						", authKey TEXT DEFAULT NULL"+
						", privProtocol TEXT DEFAULT NULL"+
						", privKey TEXT DEFAULT NULL"+
						", PRIMARY KEY(name));");
				}
				
				//active는 false로 초기화 해 준다.
				try (Statement stmt = c.createStatement()) {
					try (ResultSet rs = stmt.executeQuery("SELECT * FROM profile")) {
						while (rs.next()) {
							memory.addProfile(rs.getString(1), new JSONObject()
								.put("name", rs.getString(1))
								.put("protocol", rs.getString(2))
								.put("port", rs.getInt(3))
								.put("version", rs.getString(4))
								.put("security", rs.getString(5))
								.put("active", false)
								.put("authProtocol", rs.getString(6) == null? JSONObject.NULL: rs.getString(6))
								.put("authKey", rs.getString(7) == null? JSONObject.NULL: rs.getString(7))
								.put("privProtocol", rs.getString(8) == null? JSONObject.NULL: rs.getString(8))
								.put("privKey", rs.getString(9) == null? JSONObject.NULL: rs.getString(9)));
						}
					}
				}	
				
				if (memory.getProfile().length() == 0) {
					try (Statement stmt = c.createStatement()) {
						stmt.executeUpdate("INSERT INTO profile"+
							" (name, protocol, port, version, security)"+
							" VALUES('public', 'udp', 161, 'v2c', 'public');");
					}
					
					memory.addProfile("public", new JSONObject()
						.put("name", "public")
						.put("protocol", "udp")
						.put("port", 161)
						.put("version", "v2c")
						.put("security", "public"));
				}
				/**END**/
				
				/**
				 * RESOURCE
				 */
				try (Statement stmt = c.createStatement()) {
					stmt.executeUpdate("CREATE TABLE IF NOT EXISTS resource"+
						" (id INTEGER NOT NULL"+
						", oid TEXT NOT NULL"+
						", _index TEXT  NOT NULL"+
						", value TEXT  NOT NULL"+
						", timestamp INTEGER DEFAULT NULL"+
						", date INTEGER NOT NULL);");
				}
				
				try (Statement stmt = c.createStatement()) {
					stmt.executeUpdate("CREATE INDEX IF NOT EXISTS idx ON resource (date);");
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
				
				try (Statement stmt = c.createStatement()) {
					try (ResultSet rs = stmt.executeQuery("SELECT key, value FROM setting where value IS NOT NULL;")) {
						while (rs.next()) {
							memory.setSetting(rs.getString(1), rs.getString(2));
						}
					}
				}
				
				initProfile(this.memory.getProfile());
				initMonitor(this.memory.getMonitor());
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
				
				try (Statement stmt = c.createStatement()) {
					try (ResultSet rs = stmt.executeQuery("SELECT name, email, sms FROM user")) {
						while (rs.next()) {
							memory.addUser(rs.getString(1), new JSONObject()
								.put("name", rs.getString(1))
								.put("email", rs.getString(2))
								.put("sms", rs.getString(3)));
						}
					}
				}
				
				initProfile(this.memory.getProfile());
				initMonitor(this.memory.getMonitor());
				/**END**/
				
				c.commit();
			} catch(Exception e) {
				c.rollback();
				
				System.err.print(e);
			}
		}
	}
	
	/**
	 * return 모니터가 존재하지 않을때만 더 이상 ping 시도하지 않도록 false, sql 실패는 무시해 준다.
	 */
	@Override
	public synchronized boolean action01(long id, long rtt) {
		JSONObject monitor = this.memory.getMonitorByID(id);
		
		// 그 사이 지워졌을 수도 있으니까.
		if (monitor == null) {
			return false;
		}
		
		boolean status = rtt > -1;
		
		if (monitor.getBoolean("status") != status) {
			try(Connection c = DriverManager.getConnection(this.db)) {
				try  {
					c.setAutoCommit(false);
					
					try (PreparedStatement pstmt = c.prepareStatement("UPDATE monitor SET status=? WHERE id=?;")) {
						pstmt.setInt(1, status? 1: 0);
						pstmt.setLong(2, id);
						
						pstmt.executeUpdate();
					}
					
					monitor.put("status", status);
					
					//TODO
					
					c.commit();
				} catch (SQLException sqle) {
					c.rollback();
					
					throw sqle;
				}
			} catch (SQLException sqle) {
				System.err.print(sqle);
			}
		}
		
		return true;
	}
	
	@Override
	public synchronized void action02(long id, int status) {
		JSONObject monitor = this.memory.getMonitorByID(id);
		
		if (monitor == null || monitor.getInt("snmp") == status) {
			return;
		}
		
		try(Connection c = DriverManager.getConnection(this.db)) {
			try  {
				c.setAutoCommit(false);
				
				try (PreparedStatement pstmt = c.prepareStatement("UPDATE monitor SET snmp=? WHERE id=?;")) {
					pstmt.setInt(1, status);
					pstmt.setLong(2, id);
					
					pstmt.executeUpdate();
				}
				
				monitor.put("status", status);
				
				// TODO
				c.commit();
			} catch (SQLException sqle) {
				c.rollback();
				
				throw sqle;
			}
		} catch (SQLException sqle) {
			System.err.print(sqle);
		}
	}
	
	@Override
	public synchronized void action03(long id, OID oid, OID index, Variable variable) {
		try(Connection c = DriverManager.getConnection(this.db)) {
			Calendar calendar = Calendar.getInstance();
			
			try  {
				c.setAutoCommit(false);
				
				try (PreparedStatement pstmt = c.prepareStatement("INSERT INTO resource (id, oid, _index, value, timestamp, date)"+
					" VALUES (?, ?, ?, ?, ?);")) {
					pstmt.setLong(1, id);
					pstmt.setString(2, oid.toDottedString());
					pstmt.setString(3, oid.toDottedString());
					pstmt.setString(4, variable.toString());
					pstmt.setLong(5, calendar.getTimeInMillis());
					pstmt.setString(6, variable.toString());
					
					pstmt.executeUpdate();
				}
				
				c.commit();
			} catch (SQLException sqle) {
				c.rollback();
				
				throw sqle;
			}
		} catch (SQLException sqle) {
			System.err.print(sqle);
		}
	}
	
	@Override
	public boolean addAccount(String username, JSONObject account) {
		try(Connection c = DriverManager.getConnection(this.db)) {
			try  {
				c.setAutoCommit(false);
				
				try (PreparedStatement pstmt = c.prepareStatement("INSERT INTO account (username, password, level)"+
					" VALUES (?, ?, ?);")) {
					pstmt.setString(1, account.getString("username"));
					pstmt.setString(2, account.getString("password"));
					pstmt.setInt(3, account.getInt("level"));
					
					pstmt.executeUpdate();
				}
				
				this.memory.addAccount(username, account);
				
				c.commit();
			} catch (SQLException sqle) {
				c.rollback();
				
				throw sqle;
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
	public boolean addIcon(String type, JSONObject icon) {
		try (Connection c = DriverManager.getConnection(this.db)) {
			c.setAutoCommit(false);
			
			try {
				try (PreparedStatement pstmt = c.prepareStatement("INSERT INTO icon"+
					" (type, _group, alt, src, diasabled, unit, color, texture, top)"+
					" VALUES (?, ?, ?, ?, ?, ?, ?, ?);")) {
					pstmt.setString(1, icon.getString("type"));
					pstmt.setString(2, icon.getString("group"));
					pstmt.setString(3, icon.getString("alt"));
					pstmt.setString(4, icon.getString("src"));
					pstmt.setString(5, icon.getString("disabled"));
					pstmt.setInt(6, icon.getInt("unit"));
					pstmt.setString(7, icon.getString("color"));
					pstmt.setString(8, icon.getString("texture"));
					pstmt.setString(9, icon.getString("top"));
					
					pstmt.executeUpdate();
				}
				
				this.memory.addIcon(type, icon);
					
				c.commit();
			} catch (SQLException sqle) {
				c.rollback();
				
				throw sqle;
			}
		} catch (SQLException sqle) {
			System.err.print(sqle);
			
			return false;
		}
		
		return true;
	}

	@Override
	public boolean addLink(long nodeFrom, long nodeTo) {
		if (nodeFrom >= nodeTo) {
			return false;
		}
		
		try (Connection c = DriverManager.getConnection(this.db)) {
			long id;
			
			synchronized(this.lastLinkID) {
				id = this.lastLinkID++;
			}
			
			try (PreparedStatement pstmt = c.prepareStatement("INSERT INTO link (id, node_from, node_to) values (?, ?, ?);")) {
				pstmt.setLong(1, id);
				pstmt.setLong(2, nodeFrom);
				pstmt.setLong(3, nodeTo);
				
				pstmt.executeUpdate();
			}
			
			this.memory.setLink(nodeFrom, nodeTo, id, new JSONObject().put("id", id));
		} catch (SQLException sqle) {
			System.err.print(sqle);
			
			return false;
		}
		
		return true;
	}
	
	@Override
	public JSONObject addNode(JSONObject node) {
		
		
		try (Connection c = DriverManager.getConnection(this.db)) {
			c.setAutoCommit(false);
			
			try {
				long id;
				
				synchronized(this.lastNodeID) {
					id = this.lastNodeID++;
				}
				
				try (PreparedStatement pstmt = c.prepareStatement("INSERT INTO node (id, name, type, ip, label) values (?, ?, ?, ?, ?);")) {
					pstmt.setLong(1, id);
					pstmt.setString(2, node.has("name")? node.getString("name"): null);
					pstmt.setString(3, node.has("type")? node.getString("type"): null);
					pstmt.setString(4, node.has("ip")? node.getString("ip"): null);
					pstmt.setString(5, node.has("label")? node.getString("label"): null);			
					
					pstmt.executeUpdate();
				}
				
				node.put("id", id);
				
				if (!this.memory.addNode(id, node)) {
					throw new SQLException();
				}
				
				c.commit();
			} catch (SQLException sqle) {
				c.rollback();
				
				throw sqle;
			}
			
		} catch (SQLException sqle) {
			System.err.print(sqle);
			
			return null;
		}
		
		return node;
	}


	@Override
	public boolean addPath(long nodeFrom, long nodeTo) {
		if (nodeFrom >= nodeTo) {
			return false;
		}
		
		try (Connection c = DriverManager.getConnection(this.db)) {
			try (PreparedStatement pstmt = c.prepareStatement("INSERT INTO path (node_from, node_to) values (?, ?);")) {
				pstmt.setLong(1, nodeFrom);
				pstmt.setLong(2, nodeTo);
				
				pstmt.executeUpdate();
			}
			
			this.memory.setPath(nodeFrom, nodeTo, new JSONObject());
		} catch (SQLException sqle) {
			System.err.print(sqle);
			
			return false;
		}
		
		return true;
	}
	
	@Override
	public boolean addProfile(String name, JSONObject profile) {
		try (Connection c = DriverManager.getConnection(this.db)) {
			c.setAutoCommit(false);
			
			try {
				try (PreparedStatement pstmt = c.prepareStatement("INSERT INTO profile"+
					" (name, protocol, port, version, security, authProtocol, authKey, privProtocol, privKey)"+
					" VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);")) {
					pstmt.setString(1, profile.getString("name"));
					pstmt.setString(1, profile.getString("protocol"));
					pstmt.setString(1, profile.getString("port"));
					pstmt.setString(1, profile.getString("version"));
					pstmt.setString(1, profile.getString("security"));
					pstmt.setString(1, profile.has("authProtocol")? profile.getString("authProtocol"): null);
					pstmt.setString(1, profile.has("authKey")? profile.getString("authKey"): null);
					pstmt.setString(1, profile.has("privProtocol")? profile.getString("privProtocol"): null);
					pstmt.setString(1, profile.has("privKey")? profile.getString("privKey"): null);
					
					pstmt.executeUpdate();
				}
				
				this.memory.addProfile(name, profile);
				
				c.commit();
			} catch (SQLException sqle) {
				c.rollback();
				
				throw sqle;
			}
		} catch (SQLException sqle) {
			System.err.print(sqle);
			
			return false;
		}
		
		return true;
	}
	
	@Override
	public boolean addUser(String name, JSONObject user) {
		try (Connection c = DriverManager.getConnection(this.db)) {
			c.setAutoCommit(false);
		
			try {
				try (PreparedStatement pstmt = c.prepareStatement("INSERT INTO user (name, email, sms) VALUES"+
					" (?, ?, ?);")) {
					pstmt.setString(1, name);
					pstmt.setString(2, user.has("email")? user.getString("email"): null);
					pstmt.setString(3, user.has("sms")? user.getString("sms"): null);
					
					pstmt.executeUpdate();
				}
		
				this.memory.addUser(name, user);
					
				c.commit();
			} catch (SQLException sqle) {
				c.rollback();
				
				throw sqle;
			}
		} catch (SQLException sqle) {
			System.err.print(sqle);
			
			return false;
		}
		
		return true;
	}

	@Override
	public void close() throws IOException {
		synchronized(this.isClosed) {
			if (this.isClosed) {
				return;
			}
		}
	}
	
	@Override
	public JSONObject getAccount() {
		return this.memory.getAccount();
	}

	@Override
	public JSONObject getAccountByUsername(String username) {
		try {
			return this.memory.getAccount().getJSONObject(username);
		}
		catch (JSONException jsone) {}
		
		return null;
	}

	@Override
	public JSONObject getConfig() {
		return this.memory.getConfig();
	}

	@Override
	public JSONObject getConfigByKey(String key) {
		try {
			return new JSONObject()
				.put(key, this.memory.getConfig().getString(key));
		}
		catch (JSONException jsone) {}
		
		return null;
	}
	
	@Override
	public JSONObject getIcon() {
		return this.memory.getIcon();
	}

	@Override
	public JSONObject getLink() {
		return this.memory.getLink();
	}

	@Override
	public JSONObject getLinkByNodeID(long nodeFrom, long nodeTo) {
		try {
			return this.memory.getLink().getJSONObject(Long.toString(nodeFrom)).getJSONObject(Long.toString(nodeTo));
		}
		catch (JSONException jsone) {}
		
		return null;
	}
	
	@Override
	public JSONObject getEventByID(long id) {
		try (Connection c = DriverManager.getConnection(this.db)) {
			try (PreparedStatement pstmt = c.prepareStatement("SELECT date, origin, status, message, ip, name FROM event WHERE id=?;")) {
				pstmt.setLong(1, id);
				
				try (ResultSet rs = pstmt.executeQuery()) {
					if (rs.next()) {
						return new JSONObject()
							.put("date", rs.getLong(1))
							.put("origin", rs.getString(2))
							.put("status", rs.getInt(3))
							.put("message", rs.getString(4))
							.put("ip", rs.getString(5) == null? JSONObject.NULL: rs.getString(5))
							.put("name", rs.getString(6));
					}
				}
			} 
		} catch (SQLException sqle) {
			System.err.print(sqle);
		}
		
		return null;
	}

	@Override
	public void getDataByID(long id) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public JSONObject getEventByDate(long date) {
		try (Connection c = DriverManager.getConnection(this.db)) {
			try (PreparedStatement pstmt = c.prepareStatement("SELECT id, timestamp, origin, status, message, ip, name FROM EVENT where date=?;")) {
				pstmt.setLong(1, date);
				
				try (ResultSet rs = pstmt.executeQuery()) {
					JSONObject result = new JSONObject();
					
					while(rs.next()) {
						result.put(Long.toString(rs.getLong(1)),
							new JSONObject()
								.put("id", rs.getLong(1))
								.put("timestamp", rs.getLong(2))
								.put("origin", rs.getString(3))
								.put("status", rs.getInt(4))
								.put("message", rs.getString(5))
								.put("ip", rs.getString(6) == null? JSONObject.NULL: rs.getString(6))
								.put("name", rs.getString(7)));
					}
				}
			} 
		} catch (SQLException sqle) {
			System.err.print(sqle);
		}
		
		return null;
	}

	@Override
	public JSONObject getIconByType(String type) {
		try (Connection c = DriverManager.getConnection(this.db)) {
			try (PreparedStatement pstmt = c.prepareStatement("SELECT type, _group, alt, src, disabled, unit, color, texture, top FROM icon WHERE type=?;")) {
				pstmt.setString(1, type);
				
				try (ResultSet rs = pstmt.executeQuery()) {
					if (rs.next()) {
						return new JSONObject()
							.put("type", rs.getString(1))
							.put("group", rs.getString(2))
							.put("alt", rs.getString(3))
							.put("src", rs.getString(4))
							.put("disabled", rs.getString(5))
							.put("unit", rs.getInt(6))
							.put("color", rs.getString(7))
							.put("texture", rs.getString(8))
							.put("top", rs.getString(9));
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
		return this.memory.getNode();
	}

	@Override
	public JSONObject getNodeByID(long id, boolean snmp) {
		return this.memory.getNodeByID(id);
	}

	@Override
	public JSONObject getPath() {
		return this.memory.getPath();
	}

	@Override
	public JSONObject getPathByNodeID(long nodeFrom, long nodeTo) {
		try {
			return this.memory.getPath().getJSONObject(Long.toString(nodeFrom)).getJSONObject(Long.toString(nodeTo));
		}
		catch (JSONException jsone) {}
		
		return null;
	}
	/*}
		try (Connection c = DriverManager.getConnection(this.db)) {
			try (PreparedStatement pstmt = c.prepareStatement("SELECT id, type, color, size FROM path WHERE node_from=? AND node_to=?;")) {
				pstmt.setLong(1, nodeFrom);
				pstmt.setLong(1, nodeTo);
				
				try (ResultSet rs = pstmt.executeQuery()) {
					if (rs.next()) {
						JSONObject path = new JSONObject()
							.put("id", rs.getLong(1))
							.put("nodeFrom", nodeFrom)
							.put("nodeTo", nodeTo);
						
						if (rs.getString(2) != null) {
							path.put("type", rs.getString(2));
						}
						
						if (rs.getString(3) != null) {
							path.put("color", rs.getString(3));
						}
						
						if (rs.getInt(4) > 0) {
							path.put("size", rs.getInt(4));
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
	*/
	@Override
	public JSONObject getPositionByName(String name) {
		try (Connection c = DriverManager.getConnection(this.db)) {
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
		return this.memory.getProfile();
	}
	
	@Override
	public JSONObject getProfileByName(String name) {
		return this.memory.getProfileByName(name);
	}
	
	@Override
	public JSONObject getSetting() {
		return this.memory.getSetting();
	}

	@Override
	public JSONObject getSettingByKey(String key) {
		try {
			return new JSONObject()
				.put(key, this.memory.getSetting().getString(key));
		}
		catch (JSONException jsone) {}
		
		return null;
	}

	@Override
	public JSONObject getTop(JSONObject key) {
		return new JSONObject();
	}

	@Override
	public JSONObject getTraffic(JSONObject traffic) {
		// TODO Auto-generated method stub
		return traffic;
	}

	@Override
	public JSONObject getTopByResource(String resource) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public JSONObject getUser() {
		return this.memory.getUser();
	}
	
	public void initMonitor(JSONObject monitorList) throws IOException {
		JSONObject monitor;
		
		for (Object o: monitorList.keySet()) {
			monitor = monitorList.getJSONObject((String)o);
			
			this.nodeManager.createNode(monitor);
		}
	}
	
	public void initProfile(JSONObject profileList) {
		JSONObject profile;
		
		for (Object o: profileList.keySet()) {
			profile = profileList.getJSONObject((String)o);
			
			if ("v3".equals(profile.getString("version"))) {
				this.nodeManager.addUSMUser(profile);
			}
		}
	}
	
	@Override
	public boolean removeAccount(String username) {
		JSONObject account = this.memory.removeAccount(username);
		
		if (account == null) {
			return false;
		}
				
		try (Connection c = DriverManager.getConnection(this.db)) {
			try (PreparedStatement pstmt = c.prepareStatement("DELETE FROM account WHERE username=?;")) {
				pstmt.setString(1, username);
				
				pstmt.executeUpdate();
			} 
		} catch (SQLException sqle) {
			this.memory.addAccount(username, account);
			
			System.err.print(sqle);
			
			return false;
		}
		
		return true;
	}

	@Override
	public void removeEventListener(Listener listener) {
		this.listenerList.remove(listener);
	}
	
	@Override
	public boolean removeIcon(String type) {
		try (Connection c = DriverManager.getConnection(this.db)) {
			c.setAutoCommit(false);
			
			try {
				try (PreparedStatement pstmt = c.prepareStatement("DELETE FROM icon WHERE type=?;")) {
					pstmt.setString(1, type);
					
					pstmt.executeUpdate();
				}
		
				if (this.memory.removeIcon(type) == null) {
					throw new SQLException();
				}
				
				c.commit();
			} catch (SQLException sqle) {
				c.rollback();
				
				throw sqle;
			}
		} catch (SQLException sqle) {
			System.err.print(sqle);
			
			return false;
		}
		
		return true;
	}
	
	@Override
	public JSONObject removeLink(long nodeFrom, long nodeTo, long id) {
		JSONObject link = null;
		
		try (Connection c = DriverManager.getConnection(this.db)) {
			c.setAutoCommit(false);
		
			try {
				try (PreparedStatement pstmt = c.prepareStatement("DELETE FROM link WHERE id=?;")) {
					pstmt.setLong(1, id);
					
					pstmt.executeUpdate();
				}
				
				link = this.memory.removeLink(nodeFrom, nodeTo, id);
				
				if (link == null) {
					throw new SQLException();
				}
				
				c.commit();
			} catch (SQLException sqle) {
				c.rollback();
				
				throw sqle;
			}
		} catch (SQLException sqle) {
			System.err.print(sqle);
			
			return null;
		}
		
		return link;
	}
	

	@Override
	public boolean removeMonitor(long id) {
		try (Connection c = DriverManager.getConnection(this.db)) {
			c.setAutoCommit(false);
			
			try {
				try (PreparedStatement pstmt = c.prepareStatement("DELETE FROM monitor WHERE id=?;")) {
					pstmt.setLong(1, id);
					
					pstmt.executeUpdate();
				}
				
				if (this.memory.removeMonitor(id) == null) {
					throw new SQLException();
				}
				
				c.commit();
			} catch (SQLException sqle) {
				c.rollback();
				
				throw sqle;
			}
		} catch (SQLException sqle) {
			System.err.print(sqle);
			
			return false;
		}
		
		return true;
	}
	
	/** TODO
	 * Table node, position, monitor, line 삭제
	 * node 중지
	 */
	@Override
	public boolean removeNode(long id) {
		JSONObject position = this.memory.copyPositionbyName("position");
		String s;
		
		try (Connection c = DriverManager.getConnection(this.db)) {
			c.setAutoCommit(false);
			
			try {
				try (PreparedStatement pstmt = c.prepareStatement("DELETE FROM node WHERE id=?;")) {
					pstmt.setLong(1, id);
					
					pstmt.executeUpdate();
				}
				
				if (position.remove(Long.toString(id)) == null) {
					throw new SQLException();
				}
		
				s = position.toString();
				
				try (PreparedStatement pstmt = c.prepareStatement("UPDATE position set position=? where name=?;")) {
					pstmt.setString(1, s);
					pstmt.setString(2, "position");
					
					pstmt.executeUpdate();
				}
				
				if (this.memory.removeNode(id) == null) {
					throw new SQLException();
				}
				
				c.commit();
			} catch (SQLException sqle) {
				c.rollback();
				
				throw sqle;
			}
		} catch (SQLException sqle) {
			System.err.print(sqle);
			
			return false;
		}
		
		this.memory.setPosition("position", s);
		
		this.nodeManager.removeNode(id);
		
		return true;
	}
	
	@Override
	public boolean removeProfile(String name) {
		try (Connection c = DriverManager.getConnection(this.db)) {
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
				
				try (PreparedStatement pstmt = c.prepareStatement("delete FROM profile WHERE protocol=?;")) {
					pstmt.setString(1, name);
					
					pstmt.executeUpdate();
				}
				
				if (this.memory.removeProfile(name) == null) {
					throw new SQLException();
				}
			} catch (SQLException sqle) {
				c.rollback();
				
				throw sqle;
			}
		} catch (SQLException sqle) {
			System.err.print(sqle);
			
			return false;
		}
		
		return true;
	}
	
	@Override
	public boolean removeUser(String name) {
		try (Connection c = DriverManager.getConnection(this.db)) {
			c.setAutoCommit(false);
			
			try {
				try (PreparedStatement pstmt = c.prepareStatement("DELETE FROM user WHERE name=?;")) {
					pstmt.setString(1, name);
					
					pstmt.executeUpdate();
				}
				
				if (this.memory.removeUser(name) == null) {
					throw new SQLException();
				}
				
				c.commit();
			} catch (SQLException sqle) {
				c.rollback();
				
				throw sqle;
			}
		} catch (SQLException sqle) {
			System.err.print(sqle);
			
			return false;
		}
		
		return true;
	}
	
	@Override
	public boolean setCleaner(int store) {
		try (Connection c = DriverManager.getConnection(this.db)) {
			try (PreparedStatement pstmt = c.prepareStatement("INSERT INTO config (key, value) VALUES"+
					" ('store', ?)"+
					" ON DUPLICATE KEY UPDATE"+
					" key=VALUES(key) value=VALUES(value);")) {
				pstmt.setString(1, Integer.toString(store));
				
				pstmt.executeUpdate();
			}
			
		} catch (SQLException sqle) {
			System.err.print(sqle);
			
			return false;
		}
		
		this.memory.setConfig("store", Integer.toString(store));
		
		//TODO 
		
		return true;
	}

	@Override
	public boolean setHealth(int health) {		
		try (Connection c = DriverManager.getConnection(this.db)) {
			try (PreparedStatement pstmt = c.prepareStatement("INSERT INTO config (key, value) VALUES"+
				" ('health', ?)"+
				" ON DUPLICATE KEY UPDATE"+
				" key=VALUES(key) value=VALUES(value);")) {
				pstmt.setString(1, Integer.toString(health));
				
				pstmt.executeUpdate();				
			}
		} catch (SQLException sqle) {
			System.err.print(sqle);
			
			return false;
		}
		
		//int timeout = Byte.toUnsignedInt((byte)(health & 0x0f)) *1000; // timeout
		//int retry = Byte.toUnsignedInt((byte)((health >> 4)& 0x0f)); // retry
		
		this.memory.setConfig("health", Integer.toString(health));
		// TODO node().setHealth(timeout, retry);
		
		return true;
	}

	@Override
	public boolean setLink(long nodeFrom, long nodeTo, long id, JSONObject link) {
		try (Connection c = DriverManager.getConnection(db)) {
			try (PreparedStatement pstmt = c.prepareStatement("UPDATE link SET"+
					" index_from=?"+
					", index_to=?"+
					", extra=?"+
					" WHERE id=?;")) {
		
				if (link.has("indexFrom")) {
					pstmt.setLong(1, link.getLong("indexFrom"));
				}
				else {
					pstmt.setNull(1, Types.INTEGER);
				}
				
				if (link.has("indexTo")) {
					pstmt.setLong(2, link.getLong("indexTo"));
				}
				else {
					pstmt.setNull(2, Types.INTEGER);
				}
				
				pstmt.setString(3, link.has("extra")? link.getJSONObject("extra").toString(): null);
				pstmt.setLong(4, id);
				
				pstmt.executeUpdate();
				
				this.memory.setLink(nodeFrom, nodeTo, id, link);
			}
		} catch (SQLException sqle) {
			System.err.print(sqle);
			
			return false;
		}
		
		return true;
	}
	
	@Override
	public boolean setSNMPInterval(long interval) {
		try (Connection c = DriverManager.getConnection(this.db)) {
			try (PreparedStatement pstmt = c.prepareStatement("INSERT INTO config (key, value) VALUES"+
					" ('snmpInterval', ?)"+
					" ON DUPLICATE KEY UPDATE"+
					" key=VALUES(key) value=VALUES(value);")) {
				pstmt.setString(1, Long.toString(interval));
				
				pstmt.executeUpdate();
			}
		} catch (SQLException sqle) {
			System.err.print(sqle);
			
			return false;
		}
		
		this.memory.setConfig("snmpInterval", Long.toString(interval));
		
		//TODO 
		
		return true;
	}

	@Override
	public boolean setSaveInterval(int interval) {
		try (Connection c = DriverManager.getConnection(this.db)) {
			try (PreparedStatement pstmt = c.prepareStatement("INSERT INTO config (key, value) VALUES"+
				" ('saveInterval', ?)"+
				" ON DUPLICATE KEY UPDATE"+
				" key=VALUES(key) value=VALUES(value);")) {
				pstmt.setString(1, Integer.toString(interval));
				
				pstmt.executeUpdate();
			}
		} catch (SQLException sqle) {
			System.err.print(sqle);
			
			return false;
		}
		
		this.memory.setConfig("saveInterval", Integer.toString(interval));
	 	
		//TODO 저장 인터벌 적용하기 
		
		return true;
	}

	@Override
	public boolean setTopCount(int count) {
		try (Connection c = DriverManager.getConnection(this.db)) {
			try (PreparedStatement pstmt = c.prepareStatement("INSERT INTO config (key, value) VALUES"+
				" ('topCount', ?)"+
				" ON DUPLICATE KEY UPDATE"+
				" key=VALUES(key) value=VALUES(value);")) {
				pstmt.setString(1, Integer.toString(count));
				
				pstmt.executeUpdate();
			} 
		} catch (SQLException sqle) {
			System.err.print(sqle);
			
			return false;
		}
		
		this.memory.setConfig("topCount", Integer.toString(count));
		
		//TODO Top 갯수 변경하기
		
		return true;
	}

	@Override
	public SMTP setSMTPServer(JSONObject smtp) {
		if (smtp.has("disabled") && smtp.getBoolean("disabled")) {
			try (Connection c = DriverManager.getConnection(this.db)) {
				try (Statement stmt = c.createStatement()){
					stmt.executeUpdate("UPDATE config SET value='true' where key='smtpDisabled';");
				}
				
				this.memory.setConfig("smtpDisabled", "true");
				
			} catch (SQLException sqle) {					
				System.err.print(sqle);
			}
			
			//TODO SMTP 서버 동작 중지
			
			return null;
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
			default: return null;
			}
			
			try (Connection c = DriverManager.getConnection(this.db)) {
				try (PreparedStatement pstmt = c.prepareStatement("INSERT INTO config (key, value) VALUES"+
					" ('smtpServer', ?)"+
					" ,('smtpProtocol', ?)"+
					" ,('smtpUser', ?)"+
					" ,('smtpPassword', ?)"+
					" ,('smtpdisabled', 'false')"+
					" ON DUPLICATE KEY UPDATE"+
					" key=VALUES(key)"+
					" value=VALUES(value)"+
					";")) {
					
					pstmt.setString(1, server);
					pstmt.setString(2, protocol);
					pstmt.setString(3, user);
					pstmt.setString(4, password);
					
					pstmt.executeUpdate();
				}
			} catch (SQLException sqle) {
				System.err.print(sqle);
				
				return null;
			}
			
			this.memory.setConfig("smtpServer", server);
			this.memory.setConfig("smtpProtocol", protocol);
			this.memory.setConfig("smtpUser", user);
			this.memory.setConfig("smtpPassword", password);
			this.memory.setConfig("smtpdisabled", "true");
			
			return smtpServer;
		}
	}

	@Override
	public boolean setStoreDate(int period) {
		try (Connection c = DriverManager.getConnection(this.db)) {
			try (PreparedStatement pstmt = c.prepareStatement("INSERT INTO config (key, value) VALUES"+
				" ('storeDate', ?)"+
				" ON DUPLICATE KEY UPDATE"+
				" key=VALUES(key) value=VALUES(value);")) {
				pstmt.setString(1, Integer.toString(period));
				
				pstmt.executeUpdate();
			} 
		} catch (SQLException sqle) {
			System.err.print(sqle);
			
			return false;
		}
		
		this.memory.setConfig("storeDate", Integer.toString(period));
		
		//TODO 파일정리 설정하기
		return true;	
	}
	
	@Override
	public boolean setNode(long id, JSONObject node) {
		try (Connection c = DriverManager.getConnection(this.db)) {
			try (PreparedStatement pstmt = c.prepareStatement("UPDATE node SET"+
				" name=?"+
				", type=?"+
				", label=?"+
				" WHERE id=?;")) {
				pstmt.setString(1, node.getString("name"));
				pstmt.setString(2, node.getString("type"));
				pstmt.setString(3, node.getString("label"));
				pstmt.setLong(4, id);
				
				pstmt.executeUpdate();
			}
			
			this.memory.setNode(id, node);
		} catch (SQLException sqle) {
			System.err.print(sqle);
			
			return false;
		}
		
		return true;
	}

	@Override
	public boolean setAccount(String username, JSONObject account) {
		try (Connection c = DriverManager.getConnection(this.db)) {
			c.setAutoCommit(false);
			
			try {
				try (PreparedStatement pstmt = c.prepareStatement("UPDATE account SET password=?, level=? WHERE username=?;")) {
					pstmt.setString(1, account.getString("password"));
					pstmt.setInt(2, account.getInt("level"));
					pstmt.setString(3, account.getString("username"));
					
					pstmt.executeUpdate();
				}
				
				if (!this.memory.setAccount(username, account)) {
					throw new SQLException();
				}
				
				c.commit();
			} catch (SQLException sqle) {
				c.rollback();
				
				throw sqle;
			}
		} catch (SQLException sqle) {
			System.err.print(sqle);
			
			return false;
		}
		
		return true;
	}

	@Override
	public boolean setCritical(String id, JSONObject critical) {
		return true;		
	}

	@Override
	public boolean setIcon(String type, JSONObject icon) {
		try (Connection c = DriverManager.getConnection(this.db)) {
			try (PreparedStatement pstmt = c.prepareStatement("UPDATE icon SET"+
				" _group=?,"+
				" alt=?,"+
				" src=?,"+
				" disabled=?,"+
				" unit=?,"+
				" color=?,"+
				" texture=?,"+
				" top=?"+
				" WHERE type=?;")) {
				pstmt.setString(1, icon.getString("group"));
				pstmt.setString(2, icon.getString("alt"));
				pstmt.setString(3, icon.getString("src"));
				pstmt.setString(4, icon.getString("disabled"));
				pstmt.setInt(5, icon.getInt("unit"));
				pstmt.setString(6, icon.getString("color"));
				pstmt.setString(7, icon.getString("texure"));
				pstmt.setString(8, icon.getString("top"));
				pstmt.setString(9, icon.getString("type"));
				
				pstmt.executeUpdate();
			}
			
			this.memory.setIcon(type, icon);
		} catch (SQLException sqle) {
			System.err.print(sqle);
			
			return false;
		}
		
		return true;
	}

	@Override
	public boolean setInterfaceUpDown(String id, JSONObject updown) {
		return true;
	}
	
	@Override
	public boolean setPath(long nodeFrom, long nodeTo, JSONObject path) {
		try (Connection c = DriverManager.getConnection(this.db)) {
			try (PreparedStatement pstmt = c.prepareStatement("UPDATE path SET"+
				" type=?,"+
				" color=?,"+
				" size=?,"+
				" WHERE node_from=? AND node_to=?;")) {
				pstmt.setString(1, path.has("type")? path.getString("type"): null);
				pstmt.setString(2, path.has("color")? path.getString("color"): null);
				pstmt.setInt(3, path.has("size")? path.getInt("size"): 0);
				pstmt.setLong(4, nodeFrom);
				pstmt.setLong(5, nodeTo);
				
				pstmt.executeUpdate();
				
				this.memory.setPath(nodeFrom, nodeTo, path);
			}
		} catch (SQLException sqle) {
			System.err.print(sqle);
			
			return false;
		}
		
		return true;
	}

	@Override
	public boolean setMonitor(long id, String protocol) {
		return true;
	}

	@Override
	public boolean setProfile(String id, JSONObject profile) {
		return true;
	}

	@Override
	public boolean setSpeed(String id, JSONObject critical) {
		return true;
	}
	
	@Override
	public boolean setUser(String name, JSONObject user) {
		try (Connection c = DriverManager.getConnection(this.db)) {
			try (PreparedStatement pstmt = c.prepareStatement("UPDATE user SET"+
				" email=?,"+
				" sms=?,"+
				" WHERE name=?;")) {
				pstmt.setString(1, user.getString("email"));
				pstmt.setString(2, user.getString("sms"));
				pstmt.setString(3, user.getString("name"));
				
				pstmt.executeUpdate();
				
				this.memory.setUser(name, user);
			} 
		} catch (SQLException sqle) {
			System.err.print(sqle);
			
			return false;
		}
		
		return true;
	}

	@Override
	public boolean setPosition(String name, JSONObject position) {
		String s = position.toString();
		
		try (Connection c = DriverManager.getConnection(db)) {
			try (PreparedStatement pstmt = c.prepareStatement("UPDATE position SET"+
				" position=?"+
				" where name=?;")) {
				pstmt.setString(1, s);
				pstmt.setString(2, name);
				
				pstmt.executeUpdate();
			}
			
			this.memory.setPosition(name, s);
		} catch (SQLException sqle) {
			System.err.print(sqle);
			
			return false;
		}
		
		return true;
	}

	@Override
	public boolean setSetting(String key, String value) {
		try (Connection c = DriverManager.getConnection(db)) {
			try (PreparedStatement pstmt = c.prepareStatement("INSERT INTO setting (key, value) VALUES"+
					" (?, ?)"+
					" ON CONFLICT(key) DO UPDATE SET value=?;")) {
		
				pstmt.setString(1, key);
				pstmt.setString(2, value);
				pstmt.setString(3, value);
				
				pstmt.executeUpdate();
			}
			
			this.memory.setSetting(key, value);
		} catch (SQLException sqle) {
			System.err.print(sqle);
			
			return false;
		}
		
		return true;
	}

	@Override
	public boolean search(String network, int mask) {
		try {
			JSONObject
				profileList = this.memory.getProfile(),
				args [] = new JSONObject[this.memory.getProfile().length()];
			int i = 0;
			Search search;
			
			for (Object o: profileList.keySet()) {
				args[i++] = profileList.getJSONObject((String)o);
			}
			
			search = new Search(this.nodeManager, new Network(network, mask), args);
			
			search.addEventListener(this);
			
			search.start();
		} catch (IOException ioe) {
			System.err.print(ioe);
			
			return false;
		}
		
		return true;
	}
	
	@Override
	public void onEvent(Object caller, Object ...event) {
		if (caller instanceof SMTP) {
			// event = exception
			// SMTP 오류. + ((Exception)event).getMessage()
		}
		else if (caller instanceof Search) {
			onSearchEvent((String)event[0], (String)event[1]);
		}
	}

	private void onSearchEvent(String ip, String profile) {
		JSONObject node = this.memory.getNodeByIP(ip);
		boolean fireEvent = false;
		
		if (node == null) {
			node = addNode(new JSONObject().put("ip", ip));
			
			if (node == null) {
				return;
			}
		}
		
		long id = node.getLong("id");
		JSONObject monitor = this.memory.getMonitorByID(id);
		
		if (monitor == null) {
			try (Connection c = DriverManager.getConnection(db)) {
				try (PreparedStatement pstmt = c.prepareStatement("INSERT INTO monitor (id, ip, protocol, status, snmp) VALUES (?, ?, 'snmp', 1, 0);")) {
					pstmt.setLong(1, id);
					pstmt.setString(2, ip);
					
					this.memory.addMonitor(id, monitor = new JSONObject()
						.put("id", id)
						.put("ip", ip)
						.put("protocol", "snmp")
						.put("status", true)
						.put("snmp", 0));
					
					fireEvent = true;
				}
			} catch (SQLException sqle) {
				System.err.print(sqle);
				
				//return;
			}	
		}
		else {
			switch(monitor.getString("protocol")) {
			case "snmp":
				if (!monitor.getBoolean("status")) {
					try (Connection c = DriverManager.getConnection(db)) {
						try (PreparedStatement pstmt = c.prepareStatement("UPDATE monitor SET status=1, snmp=0 WHERE id=?;")) {
							pstmt.setLong(1, id);
							
							monitor
								.put("status", true)
								.put("snmp", 0);
						 	
							fireEvent = true;
						}
					} catch (SQLException sqle) {
						System.err.print(sqle);
						
						//return;
					}
				}
				
				break;
			case "icmp":
				try (Connection c = DriverManager.getConnection(db)) {
					try (PreparedStatement pstmt = c.prepareStatement("UPDATE monitor SET protocol='snmp', status=1 WHERE id=?;")) {
						pstmt.setLong(1, id);
						
						monitor
							.put("protocol", "snmp")
							.put("status", true);
						
						nodeManager.removeNode(monitor.getLong("id"));
						
						fireEvent = true;
					}
				} catch (SQLException sqle) {
					System.err.print(sqle);
					
					//return;
				}
				
				break;
			default:
			}
		}
		
		if (fireEvent) {
			
		}
		//TODO 모니터 시작 프로세스 진행
	}
	
}
