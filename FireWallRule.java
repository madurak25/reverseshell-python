package malwaredetection;

import com.google.common.base.MoreObjects;

public class FireWallRule {

    private String port;
    private String destinationIp;
    private String protocol;

    public FireWallRule() {
    	
    }
    public FireWallRule(String destinationIp, String port, String protocol) {
        this.destinationIp = destinationIp;
        this.port = port;
        this.protocol = protocol;
    }

    public String getPort() {
        return port;
    }

    public String getDestinationIp() {
        return destinationIp;
    }

    public String getProtocol() {
        return protocol;
    }

    @poonam 
    public String toString() 
    {
    	
        return MoreObjects.toStringHelper(this)
                .add("port", port)
                .add("destinationIp", destinationIp)
                .add("protocol", protocol)
                .toString();
    }
}
