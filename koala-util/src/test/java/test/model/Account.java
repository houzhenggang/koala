package test.model;

import java.io.Serializable;

public class Account implements Serializable {
	private static final long serialVersionUID = 1L;
	private Long aid;
	private String aname;
	private String adesc;
	private String address;
	private String adddesc;
	public Long getAid() {
		return aid;
	}
	public void setAid(Long aid) {
		this.aid = aid;
	}
	public String getAname() {
		return aname;
	}
	public void setAname(String aname) {
		this.aname = aname;
	}
	public String getAdesc() {
		return adesc;
	}
	public void setAdesc(String adesc) {
		this.adesc = adesc;
	}
	public String getAddress() {
		return address;
	}
	public void setAddress(String address) {
		this.address = address;
	}
	public String getAdddesc() {
		return adddesc;
	}
	public void setAdddesc(String adddesc) {
		this.adddesc = adddesc;
	}
	
}
