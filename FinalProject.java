package net.floodlightcontroller.FinalProject;

import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.core.IOFMessageListener;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.packet.*;
import org.projectfloodlight.openflow.protocol.OFFlowMod;
import org.projectfloodlight.openflow.protocol.OFMessage;
import org.projectfloodlight.openflow.protocol.OFPacketIn;
import org.projectfloodlight.openflow.protocol.OFType;
import org.projectfloodlight.openflow.protocol.action.OFAction;
import org.projectfloodlight.openflow.protocol.match.Match;
import org.projectfloodlight.openflow.types.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.util.*;
import java.util.concurrent.ConcurrentSkipListSet;

public class FinalProject implements IOFMessageListener, IFloodlightModule {

    protected IFloodlightProviderService floodlightProvider;
    protected Set<Long> macAddresses;
    protected static Logger logger;

    // Open the IP Blacklist from file (floodlight 1.2/backlist.txt)
    protected ArrayList<FireWallRule> blacklist;
    public void OpenBlacklist() throws IOException {
        Scanner s = new Scanner(new File("/home/poonamnigade/FireWallRules.txt"));
        while (s.hasNext()){

            blacklist.add(convertToFireWallRule(s.nextLine()));
        }
        s.close();
    }

    private FireWallRule convertToFireWallRule(String rule) {
        String[] ruleDetails = rule.split(" ");
        System.out.println("Rule:"+rule);
        //if(ruleDetails.length==3)
        	return new FireWallRule(ruleDetails[0], ruleDetails[1],  ruleDetails[2]);
        //return new FireWallRule(ruleDetails[0], "", "");
    }

    @Override
    public String getName() {
        return FinalProject.class.getSimpleName();
    }

    @Override
    public boolean isCallbackOrderingPrereq(OFType type, String name) {
        // TODO Auto-generated method stub
        return false;
    }

    @Override
    public boolean isCallbackOrderingPostreq(OFType type, String name) {
        // TODO Auto-generated method stub
        return false;
    }

    @Override
    public Collection<Class<? extends IFloodlightService>> getModuleServices() {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public Map<Class<? extends IFloodlightService>, IFloodlightService> getServiceImpls() {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public Collection<Class<? extends IFloodlightService>> getModuleDependencies() {
        Collection<Class<? extends IFloodlightService>> l =
                new ArrayList<Class<? extends IFloodlightService>>();
        l.add(IFloodlightProviderService.class);
        return l;
    }

    @Override
    public void init(FloodlightModuleContext context)
            throws FloodlightModuleException {
        floodlightProvider = context.getServiceImpl(IFloodlightProviderService.class);
        macAddresses = new ConcurrentSkipListSet<Long>();
        logger = LoggerFactory.getLogger(FinalProject.class);

        // The IP Blacklist
        blacklist = new ArrayList<FireWallRule>();
        try {
            OpenBlacklist();
            //System.out.println("The IP Blacklist: " + Arrays.toString(blacklist.toArray()));
            // Arrays.toString(blacklist.toArray());

        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        //------------------------
    }

    @Override
    public void startUp(FloodlightModuleContext context)
            throws FloodlightModuleException {
        floodlightProvider.addOFMessageListener(OFType.PACKET_IN, this);

    }

    @Override
    public net.floodlightcontroller.core.IListener.Command receive(
            IOFSwitch sw, OFMessage msg, FloodlightContext cntx) {

        switch (msg.getType()) {
            case PACKET_IN:
                /* Retrieve the deserialized packet in message */
                Ethernet eth = IFloodlightProviderService.bcStore.get(cntx, IFloodlightProviderService.CONTEXT_PI_PAYLOAD);

                /* Various getters and setters are exposed in Ethernet */
                MacAddress srcMac = eth.getSourceMACAddress();
                VlanVid vlanId = VlanVid.ofVlan(eth.getVlanID());

                /*
                 * Check the ethertype of the Ethernet frame and retrieve the appropriate payload.
                 * Note the shallow equality check. EthType caches and reuses instances for valid types.
                 */
                if (eth.getEtherType() == EthType.IPv4) {
                    /* We got an IPv4 packet; get the payload from Ethernet */
                    IPv4 ipv4 = (IPv4) eth.getPayload();

                    /* Various getters and setters are exposed in IPv4 */
                    byte[] ipOptions = ipv4.getOptions();
                    IPv4Address dstIp = ipv4.getDestinationAddress();
                    /*
                     * Check the IP protocol version of the IPv4 packet's payload.
                     */
                    if (ipv4.getProtocol() == IpProtocol.TCP) 
                    {
                        /* We got a TCP packet; get the payload from IPv4 */
                        TCP tcp = (TCP) ipv4.getPayload();
                        // Block source IP address in the Blacklist
                        IPv4Address destinationIP = ipv4.getDestinationAddress();
                        
                        System.out.println("Port number for tcp packet is: " + destinationIP.toString( )+ "  "+ tcp.getDestinationPort());

                       
                        for (FireWallRule fireWallRule: blacklist) {
                        	System.out.println("text file ip address: " +fireWallRule.getDestinationIp());
                        	System.out.println("text file protocol: " +fireWallRule.getProtocol());
                            if(fireWallRule.getDestinationIp().equalsIgnoreCase(destinationIP.toString())
                                     && fireWallRule.getPort().equalsIgnoreCase(tcp.getDestinationPort().toString())
                                    &&fireWallRule.getProtocol().equalsIgnoreCase("TCP")) {
                                System.out.println("Rule matched for traffic " + fireWallRule.toString());
                                OFPacketIn pi = (OFPacketIn) msg;
                                Match m = pi.getMatch();
                                dropFlowMod(sw, m);
                                return Command.STOP;
                            }
                        }

                    }
                    else if (ipv4.getProtocol() == IpProtocol.ICMP) 
                    {
                        /* We got a TCP packet; get the payload from IPv4 */
                        ICMP icmp = (ICMP) ipv4.getPayload();
                        
                        IPv4Address destinationIP = ipv4.getDestinationAddress();
                        System.out.println("ICMP is the protocol with destination IP from packet:" +destinationIP);
                        
                        for (FireWallRule fireWallRule: blacklist) 
                        {
                        	System.out.println("text file ip address: " +fireWallRule.getDestinationIp());
                        	System.out.println("text file protocol: " +fireWallRule.getProtocol());
                            if(fireWallRule.getDestinationIp().equalsIgnoreCase(destinationIP.toString())
                                    &&fireWallRule.getProtocol().equalsIgnoreCase("ICMP")) 
                            {
                                System.out.println("Rule matched for traffic " + fireWallRule.toString());
                                OFPacketIn pi = (OFPacketIn) msg;
                                Match m = pi.getMatch();
                                dropFlowMod(sw, m);
                                return Command.STOP;
                            }
                        }

                    }
                    else if (ipv4.getProtocol() == IpProtocol.UDP) {
                        /* We got a UDP packet; get the payload from IPv4 */
                        UDP udp = (UDP) ipv4.getPayload();

                        IPv4Address destinationIP = ipv4.getDestinationAddress();
                        System.out.println("Port number for udp packet is: " + udp.getDestinationPort());
                        System.out.println("UDP is the protocol with destination IP from packet:" +destinationIP.toString() +"  "+udp.getDestinationPort().toString());
                        
                        for (FireWallRule fireWallRule: blacklist) {

                        	System.out.println("text file ip address: " +fireWallRule.getDestinationIp());
                        	System.out.println("text file protocol: " +fireWallRule.getProtocol());
                            if(fireWallRule.getDestinationIp().equalsIgnoreCase(destinationIP.toString())
                                    && fireWallRule.getPort().equalsIgnoreCase(udp.getDestinationPort().toString())
                                    &&fireWallRule.getProtocol().equalsIgnoreCase("UDP")) {
                                System.out.println("Rule matched for traffic " + fireWallRule.toString());
                                OFPacketIn pi = (OFPacketIn) msg;
                                Match m = pi.getMatch();
                                dropFlowMod(sw, m);
                                return Command.STOP;
                            }
                        }
                        // -----------------------------------------

                    }

                }
                break;
            default:
                break;
        }

        //---------
        return Command.CONTINUE;
    }

    // Flow-Mod defaults
    protected static final short FLOWMOD_IDLE_TIMEOUT = 5; // in seconds
    protected static final short FLOWMOD_HARD_TIMEOUT = 0; // infinite
    protected static final short FLOWMOD_PRIORITY = 100;

    public static final int NO_ARP_SPOOF_APP_ID = 1;
    public static final int APP_ID_BITS = 12;
    public static final int APP_ID_SHIFT = (64 - APP_ID_BITS);
    public static final long NO_ARP_SPOOF_COOKIE = (long) (NO_ARP_SPOOF_APP_ID & ((1 << APP_ID_BITS) - 1)) << APP_ID_SHIFT;

    // Drop the Flow of malware device
    private void dropFlowMod(IOFSwitch sw, Match match) {

        OFFlowMod.Builder fmb;
        List<OFAction> actions = new ArrayList<OFAction>(); // set no action to drop

        fmb = sw.getOFFactory().buildFlowAdd();
        fmb.setMatch(match);
        fmb.setIdleTimeout(FLOWMOD_IDLE_TIMEOUT);
        fmb.setHardTimeout(FLOWMOD_HARD_TIMEOUT);
        fmb.setPriority(FLOWMOD_PRIORITY);
        fmb.setCookie((U64.of(NO_ARP_SPOOF_COOKIE)));
        fmb.setBufferId(OFBufferId.NO_BUFFER);
        fmb.setActions(actions);

        // and write it out
        sw.write(fmb.build());
    }
}