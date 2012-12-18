package test.model;

import java.sql.Timestamp;

/**
 * Created by IntelliJ IDEA.
 * User: Administrator
 * Date: 2009-10-12
 * Time: 18:02:16
 * To change this template use File | Settings | File Templates.
 */
public class Bill {
    private Long rid;
    private Timestamp rcreatedate;
    private String username;
    private Double result;

    public Long getRid() {
        return rid;
    }

    public void setRid(Long rid) {
        this.rid = rid;
    }

    public Timestamp getRcreatedate() {
        return rcreatedate;
    }

    public void setRcreatedate(Timestamp rcreatedate) {
        this.rcreatedate = rcreatedate;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public Double getResult() {
        return result;
    }

    public void setResult(Double result) {
        this.result = result;
    }
}
