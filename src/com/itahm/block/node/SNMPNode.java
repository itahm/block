package com.itahm.block.node;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.Vector;

import org.snmp4j.PDU;
import org.snmp4j.Snmp;
import org.snmp4j.Target;
import org.snmp4j.event.ResponseEvent;
import org.snmp4j.mp.SnmpConstants;
import org.snmp4j.smi.Null;
import org.snmp4j.smi.OID;
import org.snmp4j.smi.UdpAddress;
import org.snmp4j.smi.Variable;
import org.snmp4j.smi.VariableBinding;

import com.itahm.block.node.PDUManager;
import com.itahm.util.Listenable;
import com.itahm.util.Listener;

abstract public class SNMPNode extends ICMPNode implements Listenable {

	private final static long TIMEOUT = 5000L;
	private final static int RETRY = 2;
	private final Snmp snmp;
	protected final Target<UdpAddress> target;
	private final ArrayList<Listener> listenerList = new ArrayList<>();
	private final Set<OID> reqList = new HashSet<>();
	private final Map<OID, OID> reqMap = new HashMap<>();
	
	public SNMPNode(Snmp snmp, long id, String ip, Target<UdpAddress> target) throws IOException {
		super(id, ip, String.format("SNMPNode %s", ip));

		this.snmp = snmp;
		this.target = target;
		
		target.setTimeout(TIMEOUT);
		target.setRetries(RETRY);
	}
	
	@Override
	public void addEventListener(Listener listener) {
		this.listenerList.add(listener);
	}
	
	@Override
	public void removeEventListener(Listener listener) {
		this.listenerList.remove(listener);
	}
	
	@Override
	public void fireEvent(Object ...event) {
		if (event[0] instanceof Event && (Event)event[0] == Event.PING) {
			if (event[1] instanceof Long) {
				long rtt = (long)event[1];
				
				if (rtt > -1) {
					PDU pdu = PDUManager.requestPDU(super.id, createPDU());
					OID oid;
					
					pdu.setType(PDU.GETNEXT);
					
					this.reqList.clear();
					this.reqMap.clear();

					List<? extends VariableBinding> vbs = pdu.getVariableBindings();
					VariableBinding vb;
					
					for (int i=0, length = vbs.size(); i<length; i++) {
						vb = (VariableBinding)vbs.get(i);
					
						oid = vb.getOid();
						
						this.reqList.add(oid);
						this.reqMap.put(oid, oid);
					}
					
					try {
						int code = repeat(this.snmp.send(pdu, this.target));
						
						for (Listener listener: this.listenerList) {
							listener.onEvent(this, Event.SNMP, code);
						}
					} catch (Exception e) {
						for (Listener listener: this.listenerList) {
							listener.onEvent(this, Event.SNMP, e);
						}
					};
				}
				
				for (Listener listener: this.listenerList) {
					listener.onEvent(this, event);
				}
			}
		}
	}
	
	private final PDU getNextPDU(PDU request, PDU response) throws IOException {
		PDU pdu = null;
		long requestID = response.getRequestID().toLong();
		List<? extends VariableBinding> requestVBs = request.getVariableBindings();
		List<? extends VariableBinding> responseVBs = response.getVariableBindings();
		List<VariableBinding> nextRequests = new Vector<VariableBinding>();
		VariableBinding requestVB;
		VariableBinding responseVB;
		Variable value;
		OID
			initialOID,
			requestOID,
			responseOID;
		
		for (int i=0, length = responseVBs.size(); i<length; i++) {
			requestVB = requestVBs.get(i);
			responseVB = responseVBs.get(i);
			
			requestOID = requestVB.getOid();
			responseOID = responseVB.getOid();
			
			value = responseVB.getVariable();
			
			if (!value.equals(Null.endOfMibView)) {
				initialOID = this.reqMap.get(requestOID);
				
				if (responseOID.startsWith(initialOID)) {
					nextRequests.add(new VariableBinding(responseOID));
					
					this.reqMap.put(responseOID, initialOID);
						
					for (Listener listener: this.listenerList) {
						listener.onEvent(this, Event.RESOURCE, initialOID, responseOID.getSuffix(initialOID), responseVB.getVariable(), requestID);
					}
				}
			}
			
			this.reqMap.remove(requestOID);
		}
		
		if (nextRequests.size() > 0) {
			pdu = createPDU();
			
			pdu.setVariableBindings(nextRequests);
		}
		
		return pdu;
	}
	
	// recursive method
	private int repeat(ResponseEvent<UdpAddress> event) throws IOException {
		if (event == null) {
			return SnmpConstants.SNMP_ERROR_TIMEOUT;
		}
		
		PDU response = event.getResponse();
		
		if (response == null || event.getSource() instanceof Snmp.ReportHandler) {			
			return SnmpConstants.SNMP_ERROR_TIMEOUT;
		}
		
		PDU request = event.getRequest();
		int status = response.getErrorStatus();
		
		if (status != SnmpConstants.SNMP_ERROR_SUCCESS) {
			return status;
		}
		
		PDU nextPDU = getNextPDU(request, response);
		
		if (nextPDU == null) {
			return SnmpConstants.SNMP_ERROR_SUCCESS;
		}
		
		return repeat(this.snmp.send(nextPDU, this.target));
	}
	
	abstract protected PDU createPDU();
}