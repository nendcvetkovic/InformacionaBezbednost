package ib.project.model;

public class User {
	private Integer id;
	private String email;
	private String password;
	private String certificate;
	private Authority authority;
	private Boolean active;
	
	public User(Integer id, String email, String password, String certificate, Authority authority, Boolean active) {
		 this.id = id;
	     this.email = email;
	     this.password = password;
	     this.certificate = certificate;
	     this.authority = authority;
	     this.active = active;
	}

	public Integer getId() {
		return id;
	}

	public void setId(Integer id) {
		this.id = id;
	}

	public String getEmail() {
		return email;
	}

	public void setEmail(String email) {
		this.email = email;
	}

	public String getPassword() {
		return password;
	}

	public void setPassword(String password) {
		this.password = password;
	}

	public String getCertificate() {
		return certificate;
	}

	public void setCertificate(String certificate) {
		this.certificate = certificate;
	}

	public Authority getAuthority() {
		return authority;
	}

	public void setAuthority(Authority authority) {
		this.authority = authority;
	}

	public Boolean getActive() {
		return active;
	}

	public void setActive(Boolean active) {
		this.active = active;
	}
	
	

}
