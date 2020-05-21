package com.itahm.nms.parser;

public class HRStorageMemory extends HRStorage {
	
	private final static String OID = "1.3.6.1.2.1.25.2.1.2";
	private final static String EVENT_TITLE = "물리 메모리";
	
	@Override
	public String getStorageTypeOID() {
		return OID;
	}

	@Override
	protected String getEventTitle() {
		return EVENT_TITLE;
	}

	@Override
	public String toString() {
		return "HRSTORAGEMEMORY";
	}
}
