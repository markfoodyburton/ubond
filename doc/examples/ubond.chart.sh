# no need for shebang - this file is loaded from charts.d.plugin

# if this chart is called X.chart.sh, then all functions and global variables
# must start with X_

# _update_every is a special variable - it holds the number of seconds
# between the calls of the _update() function
ubond_update_every=1

# the priority is used to sort the charts on the dashboard
# 1 = the first chart
ubond_priority=150000


# _check is called once, to find out if this chart should be enabled or not
ubond_check() {
	# this should return:
	#  - 0 to enable the chart
	#  - 1 to disable the chart
    if [ "`wget -q -O - 127.0.0.1:1040/status | grep "name" -c -m 1`" == '1' ]
    then
        return 0;
    else
        return 1;
    fi
}

# _create is called once, to create the charts
ubond_create() {
    # create the chart with 3 dimensions

    cat <<EOF
CHART ubond.outbound '' "UBOND Outbound Traffic" "kbits/s" '' '' stacked 1 ''
EOF
    wget -q -O - 127.0.0.1:1040/status | perl -e 'use Data::Dumper; use JSON;local $/ = undef;$data = decode_json(<>); $ts=$data->{'tunnels'};foreach $i (reverse(@$ts)) { print  "DIMENSION ".$i->{"name"}." ".$i->{"name"}." incremental 1 125\n"; }'

    cat <<EOF
CHART ubond.bandwidth_out '' "UBOND Outbound Bandwidth" "kbits/s" '' '' line 1 ''
EOF
    wget -q -O - 127.0.0.1:1040/status | perl -e 'use Data::Dumper; use JSON;local $/ = undef;$data = decode_json(<>); $ts=$data->{'tunnels'};foreach $i (reverse(@$ts)) { print  "DIMENSION ".$i->{"name"}." ".$i->{"name"}." absolute\n"; }'
    echo DIMENSION bandwidth bandwidth absolute
    
    cat <<EOF
CHART ubond.outbound_p '' "UBOND Outbound Traffic breakdown" "%" '' '' stacked 3 ''
EOF
    wget -q -O - 127.0.0.1:1040/status | perl -e 'use Data::Dumper; use JSON;local $/ = undef;$data = decode_json(<>); $ts=$data->{'tunnels'};foreach $i (reverse(@$ts)) { print  "DIMENSION ".$i->{"name"}." ".$i->{"name"}." percentage-of-incremental-row\n"; }'

    cat <<EOF
CHART ubond.outbound_w '' "UBOND Outbound Traffic weight" "%" '' '' stacked 3 ''
EOF
    wget -q -O - 127.0.0.1:1040/status | perl -e 'use Data::Dumper; use JSON;local $/ = undef;$data = decode_json(<>); $ts=$data->{'tunnels'};foreach $i (reverse(@$ts)) { print  "DIMENSION ".$i->{"name"}." ".$i->{"name"}." absolute 1 100\n"; }'

    cat <<EOF
CHART ubond.inbound '' "UBOND Inbound Traffic" "kbits/s" '' '' stacked 2 ''
EOF
    wget -q -O - 127.0.0.1:1040/status | perl -e 'use Data::Dumper; use JSON;local $/ = undef;$data = decode_json(<>); $ts=$data->{'tunnels'};foreach $i (reverse(@$ts)) { print  "DIMENSION ".$i->{"name"}." ".$i->{"name"}." incremental 1 125\n"; }'

    cat <<EOF
CHART ubond.inbound_p '' "UBOND Inbound Traffic Breakdown" "%" '' '' stacked 3 ''
EOF
    wget -q -O - 127.0.0.1:1040/status | perl -e 'use Data::Dumper; use JSON;local $/ = undef;$data = decode_json(<>); $ts=$data->{'tunnels'};foreach $i (reverse(@$ts)) { print  "DIMENSION ".$i->{"name"}." ".$i->{"name"}." percentage-of-incremental-row\n"; }'
    
    cat <<EOF
CHART ubond.loss '' "UBOND loss" "%" '' '' line 7 ''
EOF
    wget -q -O - 127.0.0.1:1040/status | perl -e 'use Data::Dumper; use JSON;local $/ = undef;$data = decode_json(<>); $ts=$data->{'tunnels'};foreach $i (reverse(@$ts)) { print  "DIMENSION ".$i->{"name"}."in ".$i->{"name"}."in absolute 1 100\n"; print  "DIMENSION ".$i->{"name"}."out ".$i->{"name"}."out absolute 1 100\n"; }'
    echo DIMENSION totalloss totalloss absolute

    cat <<EOF
CHART ubond.reorder_length '' "UBOND reorder length" "packets" '' '' line 7 ''
EOF
    wget -q -O - 127.0.0.1:1040/status | perl -e 'use Data::Dumper; use JSON;local $/ = undef;$data = decode_json(<>); $ts=$data->{'tunnels'};foreach $i (reverse(@$ts)) { print  "DIMENSION ".$i->{"name"}." ".$i->{"name"}." absolute 1 1\n"; }'
    echo DIMENSION totalreorder totalreorder absolute

    cat <<EOF
CHART ubond.permitted '' "UBOND permitted" "Mbytes" '' '' line 6 ''
EOF
    wget -q -O - 127.0.0.1:1040/status | perl -e 'use Data::Dumper; use JSON;local $/ = undef;$data = decode_json(<>); $ts=$data->{'tunnels'};foreach $i (reverse(@$ts)) { print  "DIMENSION ".$i->{"name"}." ".$i->{"name"}." absolute 1 1\n"; }'

    cat <<EOF
CHART ubond.srtt '' "UBOND SRTT" "s" '' '' line 4 ''
EOF
    wget -q -O - 127.0.0.1:1040/status | perl -e 'use Data::Dumper; use JSON;local $/ = undef;$data = decode_json(<>); $ts=$data->{'tunnels'};foreach $i (reverse(@$ts)) { print  "DIMENSION ".$i->{"name"}." ".$i->{"name"}." absolute 1 100\n"; }'

#    cat <<EOF
#CHART ubond.traffic '' "UBOND Traffic" "Traffic" '' '' stacked '' ''
#DIMENSION recieved '' absolute 1 1
#EOF

	return 0
}


# _update is called continiously, to collect the values
ubond_update() {
	# the first argument to this function is the microseconds since last update
	# pass this parameter to the BEGIN statement (see bellow).

#    wget -q -O - 127.0.0.1:1040/status | perl -e 'use Data::Dumper; use JSON;local $/ = undef;$data = decode_json(<>); $ts=$data->{'tunnels'};foreach $i (reverse(@$ts)) { print  "SET ".$i->{"name"}." = ". $i->{"recvbytes"}."\n"; }'

    wget -q -O - 127.0.0.1:1040/status | perl -e 'use Data::Dumper; use JSON;$arg="'$1'";local $/ = undef;$data = decode_json(<>); $ts=$data->{'tunnels'};
print "BEGIN ubond.bandwidth_out $arg\n";
foreach $i (reverse(@$ts)) { print  "SET ".$i->{"name"}." = ". $i->{"bandwidth"}."\n"; }
print "SET bandwidth = ".$data->{'bandwidth_out'}."\n";
print "END\n";
print "BEGIN ubond.inbound $arg\n";
foreach $i (reverse(@$ts)) { print  "SET ".$i->{"name"}." = ". $i->{"recvbytes"}."\n"; }
print "END\n";
print "BEGIN ubond.inbound_p $arg\n";
foreach $i (reverse(@$ts)) { print  "SET ".$i->{"name"}." = ". $i->{"recvbytes"}."\n"; }
print "END\n";
print "BEGIN ubond.outbound $arg\n";
foreach $i (reverse(@$ts)) { print  "SET ".$i->{"name"}." = ". $i->{"sentbytes"}."\n"; }
print "END\n";
print "BEGIN ubond.outbound_p $arg\n";
foreach $i (reverse(@$ts)) { print  "SET ".$i->{"name"}." = ". $i->{"sentbytes"}."\n"; }
print "END\n";
print "BEGIN ubond.outbound_w $arg\n";
foreach $i (reverse(@$ts)) { print  "SET ".$i->{"name"}." = ". (($i->{"weight"})*100.0)."\n"; }
print "END\n";
print "BEGIN ubond.loss $arg\n";
foreach $i (reverse(@$ts)) { print  "SET ".$i->{"name"}."in = ". $i->{"lossin"}*100.0."\n"; }
foreach $i (reverse(@$ts)) { print  "SET ".$i->{"name"}."out = ". $i->{"lossout"}*100.0."\n"; }
print "SET totalloss = ".$data->{'total_loss'}."\n";
print "END\n";
print "BEGIN ubond.reorder_length $arg\n";
foreach $i (reverse(@$ts)) { print  "SET ".$i->{"name"}." = ". $i->{"reorder_length"}."\n"; }
print "SET totalreorder = ".$data->{'reorder_length'}."\n";
print "END\n";
print "BEGIN ubond.permitted $arg\n";
foreach $i (reverse(@$ts)) { print  "SET ".$i->{"name"}." = ". $i->{"permitted"}."\n"; }
print "END\n";
print "BEGIN ubond.srtt $arg\n";
foreach $i (reverse(@$ts)) { print  "SET ".$i->{"name"}." = ". $i->{"srtt"}*100.0."\n"; }
print "END\n";
'
	return 0
}

#ubond_create
#ubond_update 42
