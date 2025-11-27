package droneauth.src;

import inet.applications.contract.IApp;

simple GroundStation like IApp
{
    parameters:
        int localPort = default(5000);

        @display("i=block/control");
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
