#!/usr/bin/perl

use strict;
use warnings;
use Socket;
use MIME::Lite;
use XML::LibXML;
use POSIX qw(strftime);


my $log = "alert_log";
my $ALERT_CONF = "conf/alert.conf";
my $RULES_CONF = "conf/rules.conf";
my %ALERT_CONF_DATA;
my %RULES_DATA;
my @keys; # Stores the distinct IPAddresses as a key
my $meta_data = ''; ## Stores the XML data as scalar 
my %result; # Stores final results


if( ! -d "logs" ){
	mkdir("logs") or die "Unable to Create log folder";	
	&logger("log folder does not exist . Creating the log folder .");
}


&loadAlertConfigurations();
&loadRulesConfigurations();
&doGmetadDataCollection();
&sendEmail();
#&sendSMS();



sub doGmetadDataCollection{

	
	my $gmetad_host = $ALERT_CONF_DATA{"GMETAD_HOST"};
	my $gmetad_port = $ALERT_CONF_DATA{"GMETAD_PORT"};

	$gmetad_host = "localhost" if !$gmetad_host;
	$gmetad_port = 8651 if !$gmetad_port;

      	my $iaddr = inet_aton($gmetad_host) || die("Can't connect to: $gmetad_host\n");
        my $paddr  = sockaddr_in($gmetad_port, $iaddr);
        socket(SOCK, PF_INET, SOCK_STREAM, getprotobyname('tcp'));
        connect(SOCK, $paddr) || die("Can't connect: $!");

         while (defined(my $line = <SOCK>)) {
                $meta_data.=$line;
        }

	logger("ERROR : No Data Collected from gmetad") if ! $meta_data;
	logger("INFO  : gMetad Data Collection is Successful") if $meta_data;


	foreach(keys %RULES_DATA){
	
		my $ip = (split ":",$_)[0];
		my $metric = (split ":",$_)[1];
		my $condition = (split ":",$RULES_DATA{$_})[0];
		my $thr_val = (split ":",$RULES_DATA{$_})[1];

		#print "$ip :::: $metric :::: $condition :::: $thr_val";
		&monitorThreshold($ip,$metric,$condition,$thr_val);	
	}
}


sub monitorThreshold{

	my ($ip,$met,$con,$thr) = @_;

	#print "$ip:$met:$con:$thr";

	my $parser = XML::LibXML->new();
	my $xmldoc = $parser->parse_string($meta_data);

	my $root = $xmldoc->getDocumentElement;
	my @hosts = $root->getElementsByTagName('HOST');;

	for my $host (@hosts){

		my $ip_val = $host->getAttribute('IP');
		my $name_val = $host->getAttribute('NAME');
		#print "$ip_val:$name_val\n";
		
		next if(!($ip_val eq $ip or $name_val eq $ip)); # IP or NAME matches the given ip . Then continue

			my @metrics = $host->getElementsByTagName('METRIC');
			for my $metric(@metrics){
				
				my $metric_name = $metric->getAttribute('NAME');
				my $metric_val = $metric->getAttribute('VAL');

				#print " - - - $ip_val - - $name_val - - - $metric_name : $metric_val\n";

				next if(!("$metric_name" eq "$met"));
				#print $metric;
				#print "$metric_name : $metric_val\n";
			
				my $str_condition = "$metric_val $con $thr";
				chomp($thr);
	
					if(eval($str_condition) ){

						my $k = $ip.":".$met;
						my $cond = &getConditionstring($con);
						my $v = "$cond:$thr:$metric_val";
						$result{$k} = $v;
						logger("Threshold Crossed : $k => $cond => $v");
						# KEY = IP:METRICNAME
						# VAL = CONDITION:CONFIGURED_THRESHOLD_VALUE:CURRENT_VALUE
						#
					}

				last; # If required METRIC reached , then break the loop.
			}
	}
}


sub getConditionstring{

	my $str;
	
	$str = "GREATER_THAN" if($_[0] eq ">");
	$str = "LESSER_THAN" if($_[0] eq "<");
	$str = "GREATER_THAN_OR_EQUAL" if($_[0] eq ">=");
	$str = "LESSER_THAN_OR_EQUAL" if($_[0] eq "<=");
	$str = "EQUAL" if($_[0] eq "==");
	$str = "NOT_EQUAL" if($_[0] eq "!=");

	$str;
}

sub loadRulesConfigurations{

	my @temp_key;


        if(! -e "$RULES_CONF"){
                logger("$RULES_CONF does not exist.quitting..");
                die "No Rules conf exist . Exiting.";
        }

        open FH,"<","$RULES_CONF" or die "Unable to read $RULES_CONF";
	my @rules_data = <FH>;
	close FH;

	foreach(@rules_data){

                next if($_ =~ /^#/ || $_ =~ /^$/);
                my $key = (split ":",$_)[0].":".(split ":",$_)[1];
		my $val = (split ":",$_)[2].":".(split ":",$_)[3];
		$RULES_DATA{$key} = $val;
		push(@temp_key,(split ":",$_)[0]);
        }
		@keys = uniq(@temp_key);

}

sub uniq {
    my %seen;
    grep !$seen{$_}++, @_;
}


sub loadAlertConfigurations{


	if(! -e "$ALERT_CONF"){
		logger("$ALERT_CONF does not exist.quitting..");
		die "No alert conf exist . Exiting.";
	}

	open FH,"$ALERT_CONF" or die "Unable to read $ALERT_CONF";
	
	while(my $line = <FH>){

		next if($line =~ /^#/ || $line =~ /^$/);
		my $key = (split "=",$line)[0];
		my $val = (split "=",$line)[1];
		chomp($key);
		chomp($val);
		$ALERT_CONF_DATA{$key} = "$val";
	}
	close FH;

}


sub logger{

	my @msg = @_;
	my $today = strftime "%F", localtime;
	my $time_now = strftime "%F %H:%M:%S", localtime;
	open FH,"+>>logs/$log.$today" or warn "Unable to open log file . $! ";
	print FH "$time_now	: @msg\n";
	close FH;

}

sub sendEmail{

	my $isEnabled = $ALERT_CONF_DATA{'ALERT_ENABLE_EMAIL'};
	return if($isEnabled eq 'false');



	my ($metric_name,$chk_rule,$curr_val,$threshold_val,$mail_data);
	my $smtp_host	= $ALERT_CONF_DATA{'ALERT_SMTP_HOST'};	
	my $smtp_port	= $ALERT_CONF_DATA{'ALERT_SMTP_PORT'};
	my $subject	= $ALERT_CONF_DATA{'ALERT_EMAIL_SUBJECT'};	
	my $from	= $ALERT_CONF_DATA{'ALERT_EMAIL_FROM'};
	my $to		= $ALERT_CONF_DATA{'ALERT_EMAIL_TO'};
	my $cc		= $ALERT_CONF_DATA{'ALERT_EMAIL_CC'};
        my $mail_user   = $ALERT_CONF_DATA{'ALERT_SMTP_AUTH_USER'};
        my $mail_pass   = $ALERT_CONF_DATA{'ALERT_SMTP_AUTH_PASSWORD'};	

	my $can_send = 'false'; # flag is used to control the email Trigger . i.e Email will be sent only if threshold crossed
	my $len = scalar keys %result;
	my $msg = MIME::Lite->new(
                 From     => $from,
                 To       => $to,
                 Cc       => $cc,
                 );


 
	for my $k(@keys){
			
			$subject = $subject." : ".$k;
			
			$mail_data = "<pre>Team,<br/></br>Configured Threshold is Crossed !";
			$mail_data .= "Take necessary action immediately.<br/></br></pre>";
			$mail_data .= "<table cellspacing=0 cellpadding=0 border='0' width='75%' style='border:1px solid #3369E8;'>";
			$mail_data .= "<tr><th style='font-size:13px;background-color:#b8d1f3;border:1px solid #3369E8;'>MetricName</th>";
			$mail_data .= "<th style='font-size:13px;background-color:#b8d1f3;border:1px solid #3369E8;'>Threshold</th>";
			$mail_data .= "<th style='font-size:13px;background-color:#b8d1f3;border:1px solid #3369E8;'>Current Value</th></tr>";	
	
		for my $res_key (keys %result){
			
			next if($res_key !~ m/$k/);
			$can_send = 'true';

			$metric_name	= (split ":",$res_key)[1];
			$chk_rule	= (split ":",$result{$res_key})[0];
			$threshold_val	= (split ":",$result{$res_key})[1];
			$curr_val	= (split ":",$result{$res_key})[2];

			$mail_data .= "<tr><td style='font-size:13px;border:1px solid #3369E8;'>$metric_name</td>";
			$mail_data .= "<td style='font-size:13px;border:1px solid #3369E8;'>$chk_rule : $threshold_val </td>";
			$mail_data .= "<td style='font-size:13px;border:1px solid #3369E8;'>$curr_val</td></tr>";	

			#print "$subject -> $metric_name -> $chk_rule -> $threshold_val -> $curr_val\n";
			#print "$res_key	=========== $result{$res_key}\n";
		}
			$mail_data .= "</table>";
			$mail_data .= "<pre><br/><br/>Regards,.<br/>Alert Mailer Daemon</br></pre>";
			
			$msg->add(Subject => $subject);
			$msg->{'Data'} = $mail_data;
			$msg->attr("content-type" => "text/html");

			#$msg->send('smtp', $smtp_host, Timeout=>60, AuthUser=>$mail_user, AuthPass=>$mail_pass, Debug=>1);
			if($len > 0 && $can_send eq 'true'){

				logger("INFO :  Sending Email with Subject : $subject");
				$msg->send('smtp', $smtp_host, Timeout=>60, Debug=>0);
				$can_send = 'false';

			}else{
				 logger("INFO :  No Metrics Crossed the threshold for $k. So I am silent");
			}

			$msg->delete("Subject"); # Delete old subject if exist
			$mail_data = ""; # Reset mail data for next e-mail
			$subject = $ALERT_CONF_DATA{'ALERT_EMAIL_SUBJECT'}; # Reset subject

	}#Loop ends here



}

sub sendSMS{
	
	# Implement the SMS facility . (Iterate %result hash)
	print "SMS \n";
}

