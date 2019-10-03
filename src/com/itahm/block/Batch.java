package com.itahm.block;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.FileTime;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Calendar;
import java.util.Map;
import java.util.Timer;
import java.util.TimerTask;
import java.util.concurrent.TimeUnit;

import org.h2.jdbcx.JdbcConnectionPool;

import com.itahm.block.Bean.Rule;
import com.itahm.block.Bean.Value;
import com.itahm.util.Util;

public class Batch extends Timer {

	private final String JDBC_URL = "jdbc:h2:%s";
	
	private final Path path;
	private final Map<Long, Map<String, Map<String, Value>>> resourceMap;
	private final Map<String, Rule> ruleMap;
	private Saver saver;
	private int storeDate = 0;
	private JdbcConnectionPool connPool;
	private JdbcConnectionPool nextPool;
	
	public Batch(Path path, Map<Long, Map<String, Map<String, Value>>> resourceMap, Map<String, Rule> ruleMap) throws SQLException {
		super("Batch Scheduler");

		this.path = path;
		this.resourceMap = resourceMap;
		this.ruleMap = ruleMap;
		
		Calendar calendar = Calendar.getInstance();
		
		connPool = JdbcConnectionPool.create(String.format(JDBC_URL,
			path.resolve(Util.toDateString(calendar.getTime())).toString()), "sa", "");
		
		calendar.add(Calendar.DATE, 1);
		
		nextPool = 	JdbcConnectionPool.create(String.format(JDBC_URL,
			path.resolve(Util.toDateString(calendar.getTime())).toString()), "sa", "");
		
		createRollingTable();
		
		super.scheduleAtFixedRate(new Roller(this), Util.trimDate(calendar).getTime(), TimeUnit.DAYS.toMillis(1));
		super.scheduleAtFixedRate(new Remover(this), Util.trimDate(calendar).getTime(), TimeUnit.DAYS.toMillis(1));
	}
	
	@Override
	public void cancel() {
		super.cancel();
		
		synchronized(this.connPool) {
			this.connPool.dispose();
		}
		
		this.nextPool.dispose();
	}
	
	private void createRollingTable() {
		long start = System.currentTimeMillis();
		
		while(true) {
			try (Connection c = connPool.getConnection()) {
				try (Statement stmt = c.createStatement()) {
					stmt.executeUpdate("CREATE TABLE IF NOT EXISTS rolling"+
						" (id BIGINT NOT NULL"+
						", oid VARCHAR NOT NULL"+
						", _index VARCHAR NOT NULL"+
						", value VARCHAR NOT NULL"+
						", timestamp BIGINT DEFAULT NULL);");
				}
				
				System.out.format("Rolling initialized in %dms.\n", System.currentTimeMillis() - start);
				
				break;
			} catch (SQLException sqle) {
				sqle.printStackTrace();
			}
			
			try {
				Thread.sleep(1000);
			} catch (InterruptedException e) {
				break;
			}
		}
	}
	
	private void reset() {
		JdbcConnectionPool pool;
		
		synchronized(this.connPool) {
			pool = this.connPool;
			
			this.connPool = this.nextPool;
		}
		
		pool.dispose();
		
		createRollingTable();
		
		Calendar calendar = Calendar.getInstance();
		
		calendar.add(Calendar.DATE, 1);
		
		this.nextPool = JdbcConnectionPool.create(String.format(JDBC_URL,
			this.path.resolve(Util.toDateString(calendar.getTime())).toString()), "sa", "");
	}
	
	public Connection getCurrentConnection() throws SQLException {
		return this.connPool.getConnection();
	}
	
	private void remove() {
		if (this.storeDate <= 0) {
			return;
		}
		
		try {
			Files.list(this.path).filter(Files::isRegularFile).filter(p -> {
				return p.endsWith(".mv.db");
			}).forEach(p -> {
				try {
					FileTime ft = Files.getLastModifiedTime(p);
					
					ft.toMillis();
				} catch (IOException ioe) {
					ioe.printStackTrace();
				}
			});
		} catch (IOException ioe) {
			ioe.printStackTrace();
		}
	}
	
	public void schedule(long period) {
		if (this.saver != null) {
			this.saver.cancel();
		}
		
		this.saver = new Saver(this);
		
		super.schedule(this.saver, period, period);
	}
	
	public void setStoreDate(int period) {
		this.storeDate = period;
	}
	
	private void save() {
		Map<String, Map<String, Value>> indexMap;
		Map<String, Value> oidMap;
		Value v;
		Rule rule;
		
		synchronized(this.connPool) {
			try(Connection c = this.connPool.getConnection()) {
				for (Long id: this.resourceMap.keySet()) {
					 indexMap = this.resourceMap.get(id);
					 
					 for (String index : indexMap.keySet()) {
						 oidMap = indexMap.get(index);
						 
						 for (String oid : oidMap.keySet()) {
							 v = oidMap.get(oid);
							 rule = ruleMap.get(oid);
							 
							 if (rule != null && rule.rolling) {
								 try (PreparedStatement pstmt = c.prepareStatement("INSERT INTO rolling"+
									" (id, oid, _index, value, timestamp)"+
									" VALUES (?, ?, ?, ?, ?);")) {
									pstmt.setLong(1, id);
									pstmt.setString(2, oid);
									pstmt.setString(3, index);
									pstmt.setString(4, v.value);
									pstmt.setLong(5, v.timestamp);
									
									pstmt.executeUpdate();
								}
							 }
						 }
					 }
				}
			} catch (SQLException sqle) {
				sqle.printStackTrace();
			}
		}
	}
	
	private static class Roller extends TimerTask {

		private final Batch batch;
		
		public Roller(Batch batch) {
			this.batch = batch;
		}
		
		@Override
		public void run() {
			this.batch.reset();
		}
	}
	
	private static class Saver extends TimerTask {

		private final Batch batch;
		
		public Saver(Batch batch) {
			this.batch = batch;
		}
		
		@Override
		public void run() {
			this.batch.save();
		}
		
	}
	
	private static class Remover extends TimerTask {
		private final Batch batch;
		
		public Remover(Batch batch) {
			this.batch = batch;
		}
		
		@Override
		public void run() {
			this.batch.remove();
		}
		
	}
}
