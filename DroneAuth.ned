package droneauth;

import inet.networklayer.configurator.ipv4.Ipv4NetworkConfigurator;
import inet.node.inet.StandardHost;
import inet.physicallayer.wireless.ieee80211.packetlevel.Ieee80211ScalarRadioMedium;

network DroneAuthNetwork
{
    parameters:
        int numDrones = default(3);
        @display("bgb=1400,900");
    
    submodules:
        configurator: Ipv4NetworkConfigurator {
            @display("p=100,50");
        }
        
        radioMedium: Ieee80211ScalarRadioMedium {
            @display("p=100,150");
        }
        
        groundStation: StandardHost {
            @display("p=700,700;i=device/antennatower,gold,80");
        }
        
        drone[numDrones]: StandardHost {
            @display("i=misc/drone,blue,60");
        }
}
