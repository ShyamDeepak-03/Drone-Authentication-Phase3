package droneauth.src;

import inet.applications.contract.IApp;

simple DroneAuthApp like IApp
{
    parameters:
        int localPort = default(6000);
        int destPort = default(5000);
        string destAddress = default("");
        string droneId = default("DRONE_001");
        string password = default("password");
        double startTime @unit(s) = default(1s);
        double authTimeout @unit(s) = default(5s);
        double retryInterval @unit(s) = default(10s);

        @display("i=block/app");
        @signal[authRequest](type=long);
        @signal[authSuccess](type=long);
        @signal[authFailure](type=long);
        @statistic[authRequest](title="Auth Requests"; record=count,vector);
        @statistic[authSuccess](title="Auth Success"; record=count,vector);
        @statistic[authFailure](title="Auth Failures"; record=count,vector);

    gates:
        input socketIn @labels(UdpControlInfo/up);
        output socketOut @labels(UdpControlInfo/down);
}
