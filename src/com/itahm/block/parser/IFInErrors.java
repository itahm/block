package com.itahm.block.parser;

public class IFInErrors extends IFErrors {
	
	private final static String ERRORS_OID = "1.3.6.1.2.1.2.2.1.14";
	private final static String CPS_OID = "1.3.6.1.4.1.49447.3.3";
	private final static String EVENT_TITLE = "수신 오류";

	@Override
	protected String getErrorsOID() {
		return ERRORS_OID;
	}

	@Override
	protected String getCPSOID() {
		return CPS_OID;
	}

	@Override
	protected String getEventTitle() {
		return EVENT_TITLE;
	}
	
}
