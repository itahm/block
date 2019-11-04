package com.itahm.service;

import java.nio.file.Path;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

import org.h2.jdbcx.JdbcConnectionPool;

import com.itahm.http.Request;
import com.itahm.http.Response;
import com.itahm.http.Session;
import com.itahm.json.JSONObject;

public class SignIn implements Serviceable {

	private final static String MD5_ROOT = "63a9f0ea7bb98050796b649e85481845";
	private final static int SESS_TIMEOUT = 3600;
	
	private final JdbcConnectionPool connPool;
	
	private Boolean isClosed = true;
	
	public SignIn(Path root) throws Exception {
		connPool = JdbcConnectionPool.create(String.format("jdbc:h2:%s", root.resolve("account").toString()), "sa", "");
		
		try (Connection c = connPool.getConnection()) {
			c.setAutoCommit(false);
			
			try {
				/**
				 * ACCOUNT
				 */
				try (Statement stmt = c.createStatement()) {
					stmt.executeUpdate("CREATE TABLE IF NOT EXISTS account"+
						" (username VARCHAR NOT NULL"+
						", password VARCHAR NOT NULL"+
						", level INT NOT NULL DEFAULT 0"+
						", PRIMARY KEY(username));");
				}
				
				try (Statement stmt = c.createStatement()) {
					try (ResultSet rs = stmt.executeQuery("SELECT COUNT(username) FROM account;")) {
						if (!rs.next() || rs.getLong(1) == 0) {
							try (PreparedStatement pstmt = c.prepareStatement("INSERT INTO account"+
								" (username, password, level)"+
								" VALUES ('root', ?, 0);")) {
								pstmt.setString(1, MD5_ROOT);
								
								pstmt.executeUpdate();
							}
						}
					}
				}
				
				c.commit();
			} catch (SQLException sqle) {
				c.rollback();
				
				throw sqle;
			}
		}
	}
	
	@Override
	public void start() {
		synchronized(this.isClosed) {
			if (!this.isClosed) {
				return;
			}
			
			this.isClosed = false;
		}
	}
	
	@Override
	public void stop() {
		synchronized(this.isClosed) {
			if (this.isClosed) {
				return;
			}
			
			this.isClosed = true;
		}
	}

	@Override
	synchronized public boolean service(Request request, Response response, JSONObject data) {
		synchronized(this.isClosed) {
			if (this.isClosed) {
				return false;
			}
		}
		
		Session session = request.getSession(false);
	
		switch (data.getString("command").toUpperCase()) {
		case "SIGNIN":
			if (session == null) {
				try (Connection c = connPool.getConnection()) {
					try (PreparedStatement pstmt = c.prepareStatement("SELECT username, level FROM account"+
						" WHERE username=? AND password=?;")) {
						pstmt.setString(1, data.getString("username"));
						pstmt.setString(2, data.getString("password"));
						
						try (ResultSet rs = pstmt.executeQuery()) {							
							if (rs.next()) {
								JSONObject account = new JSONObject()
									.put("username", rs.getString(1))
									.put("level", rs.getInt(2));
								
								session = request.getSession();
								
								session.setAttribute("account", account);
								
								session.setMaxInactiveInterval(SESS_TIMEOUT);
								
								response.write(account.toString());
							} else {
								response.setStatus(Response.Status.UNAUTHORIZED);
							}
						}
					}
				} catch (SQLException sqle) {
					sqle.printStackTrace();
					
					response.setStatus(Response.Status.SERVERERROR);
				}
			}
			else {
				response.write(((JSONObject)session.getAttribute("account")).toString());
			}
			
			return true;
		case "SIGNOUT":
			if (session == null) {
				response.setStatus(Response.Status.UNAUTHORIZED);
			} else {
				session.invalidate();
			}
			
			return true;
		case "ADD":
			if(data.getString("target").equalsIgnoreCase("ACCOUNT")) {
				if (!addAccount(data.getString("username"), data.getJSONObject("account"))) {
					response.setStatus(Response.Status.CONFLICT);
				}
				
				return true;
			}
			
			break;
		case "GET":
			if (data.getString("target").equalsIgnoreCase("ACCOUNT")) {
				JSONObject account = data.has("username")?
					getAccount(data.getString("username")):
					getAccount();
					
				if (account == null) {
					response.setStatus(Response.Status.NOCONTENT);
				} else {
					response.write(account.toString());
				}
				
				return true;
			}
			
			break;
		case "REMOVE":
			if(data.getString("target").equalsIgnoreCase("ACCOUNT")) {
				if(!removeAccount(data.getString("username"))) {
					response.setStatus(Response.Status.CONFLICT);
				}
				
				return true;
			}
			
			break;
		case "SET":
			if(data.getString("target").equalsIgnoreCase("ACCOUNT")) {
				if (!setAccount(data.getString("username"), data.getJSONObject("account"))) {
					response.setStatus(Response.Status.CONFLICT);
				}
				
				return true;
			}

			break;
		}
	
		return false;
	}
	
	public boolean addAccount(String username, JSONObject account) {
		try(Connection c = this.connPool.getConnection()) {
			try (PreparedStatement pstmt = c.prepareStatement("INSERT INTO account (username, password, level)"+
				" VALUES (?, ?, ?);")) {
				pstmt.setString(1, account.getString("username"));
				pstmt.setString(2, account.getString("password"));
				pstmt.setInt(3, account.getInt("level"));
				
				pstmt.executeUpdate();
			}
			
			return true;
		} catch (SQLException sqle) {
			sqle.printStackTrace();
		}
		
		return false;
	}
	
	public JSONObject getAccount() {
		try (Connection c = this.connPool.getConnection()) {
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
			sqle.printStackTrace();
		}
		
		return null;
	}
	
	public JSONObject getAccount(String username) {
		try (Connection c = this.connPool.getConnection()) {
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
			sqle.printStackTrace();
		}
		
		return null;
	}
	
	@Override
	public boolean isRunning() {
		synchronized(this.isClosed) {
			return !this.isClosed;
		}
	}
	
	public boolean removeAccount(String username) {
		try (Connection c = this.connPool.getConnection()) {
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
			}
		} catch (SQLException sqle) {
			sqle.printStackTrace();
		}
		
		return false;
	}
	
	public boolean setAccount(String username, JSONObject account) {
		try (Connection c = this.connPool.getConnection()) {
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
			}
		} catch (SQLException sqle) {
			sqle.printStackTrace();
		}
		
		return false;
	}
}
