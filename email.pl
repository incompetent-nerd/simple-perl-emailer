#!/usr/bin/perl -w
use Getopt::Long;
use POSIX qw(strftime);
use Net::SMTP;
use MIME::Base64;
use File::Basename;
use warnings;
use strict;

 #     # #######    #    ######  ####### ######
 #     # #         # #   #     # #       #     #
 #     # #        #   #  #     # #       #     #
 ####### #####   #     # #     # #####   ######
 #     # #       ####### #     # #       #   #
 #     # #       #     # #     # #       #    #
 #     # ####### #     # ######  ####### #     #

#Simple Perl Emailer.
#Version 1.0 - Initial Release 2020/05/02 (May 2nd, 2020)
#
#This script was created out of necessity.
#A production server needed to be able to send SMTP emails and I was unable to find any email
#scripts that would work with the limited subset of Perl modules the server had.
#
#If you have the ability to install additional Perl modules, I recommend you find a better script.
#
#Please send bug reports, corrections and stinging insults to author: incompetent.nerd(at)gmail.com
#
# Variables:
#       <--to|-t TO[,TO]>
#       [--from|-f FROM]
#       [--cc|-c CC[,CC]]
#       [--subject|-s "SUBJECT"]
#       [--body|-b "BODY"]
#       [--attachment|-a /PATH/TO/ATTACHMENT]
#       [--host|-h SMTP-HOST]
#       [--port|-p SMTP-PORT]
#       [--username|-u SMTP-USERNAME]
#       [--password|-x SMTP-PASSWORD]
#       [--EHLOdomain|-e SMTP-EHLO-DOMAIN]
#       [--debug|-d]
#       [--logging|-l]
#       [--exitonerror]
#       [--help]

 ######  ####### #######    #    #     # #       #######  #####
 #     # #       #         # #   #     # #          #    #     #
 #     # #       #        #   #  #     # #          #    #
 #     # #####   #####   #     # #     # #          #     #####
 #     # #       #       ####### #     # #          #          #
 #     # #       #       #     # #     # #          #    #     #
 ######  ####### #       #     #  #####  #######    #     #####

#Set default values for user controllable variables. Used only if respective variable is not passed to script.
my @TO;                                 #Recipient list.
my $FROM ='';                           #From email address (Who the email will come from).
my @CC;                                 #CC (List of CC recipients).
my $SUBJECT = 'Test Email';             #Subject (Defaults To "Test Email").
my $MESSAGEBODY = 'Test Email';         #Body of Email (Defaults to "Test Email").
my $ATTACHMENT;                         #Attachment ***be cognizant of what user the script is run as, i.e. user root has access to all files***.
my $SMTPHOST = '';                      #SMTP hostname or IP Address.
my $SMTPPORT = 25;                      #SMTP port (Defaults to port 25).
my $SMTPUSERNAME;                       #SMTP AUTH username.
my $SMTPPASSWORD;                       #SMTP AUTH password.
my $SMTPEHLODOMAIN;                     #SMTP EHLO domain.
my $DEBUG = '0';                        #Debug ***Warning SMTP AUTH password will appear in plain text***.
my $LOGGING = '0';                      #SYSLOG logging (defaults to no logging).
my $HELP;                               #Show usage help.
my $EXITONERROR = '0';                  #When set to 0, if the error is not fatal, the script will attempt to continue.
                                        #When set to 1, exit immediately if the script encounters any errors..

#Set default values for non user controllable variables.
my $MESSAGEBODY_SIZE_LIMIT =            '1024000';      #Maximum length of email body in characters.
my $ATTACHMENT_SIZE_LIMIT =             '1024000';      #Maximum size of attachment in bytes.
my $ATTACHMENT_PATH_LIMIT =             '255';          #Maximum number of characters the full path of the attachment may contain.
my $SUBJECT_LENGTH_LIMIT =              '998';          #Maximum number of characters the subject line may contain.
my $EMAIL_LENGTH_LIMIT =                '253';          #Maximum number of characters the email address may contain.
my $SMTP_TIMEOUT =                      '60';           #SMTP Timeout in seconds.
my $SMTP_HOSTNAME_LENGTH_LIMIT =        '253';          #Maximum number of characters the SMTP FQDN may contain.
my $SMTP_AUTH_USERNAME_LENGTH_LIMIT =   '253';          #Maximum number of characters the SMTP AUTH username may contain.
my $SMTP_AUTH_PASSWORD_LENGTH_LIMIT =   '253';          #Maximum number of characters the SMTP AUTH password may contain.
my $SMTP_EHLO_DOMAIN_LENGTH_LIMIT =     '253';          #Maximum number of characters the SMTP EHLO domain may contain.
my $UNTRUSTED_INPUT =                   '0';            #Setting this to 1 will make the script validate all email addresses immediately.
                                                        #This will make it harder for people to cause the script to exit due to buffer overflows or the sending of control characters.
                                                        #If set to 0, the script will validate the email addresses later on in the script and will give a description of which emails are being discarded and why.

#This is how the script determines if the input data is valid or not.
#Modify REGEX validation strings here. You can adjust these to fit your environment.
#Note the qr/ operator. This prevents a lot of headaches when using REGEX strings.
#REGEX to validate email addresses.
my $EMAIL_ADDRESS_REGEX = qr/^(?=.{6,253}$)[a-zA-Z0-9.!#$%&'*+\=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;  
#REGEX to validate a host name, FQDN or IP address.
my $HOSTNAME_REGEX = qr/^(?=.{2,253}$)([a-zA-Z0-9]([a-zA-Z0-9\-]{0,62}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,6}$|^[a-zA-Z0-9][a-zA-Z0-9\-]{0,62}/; 
#REGEX to validate a port number between 1 and 65535.
my $PORTNUMBER_REGEX = qr/^()([1-9]|[1-5]?[0-9]{2,4}|6[1-4][0-9]{3}|65[1-4][0-9]{2}|655[1-2][0-9]|6553[1-5])$/;
#REGEX to validate a SMTP EHLO domain name.
my $SMTP_EHLO_DOMAIN_REGEX = qr/^(?=.{2,253}$)([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,6}$/; 
#REGEX to validate only ASCII characters in a SMTP AUTH Username.
my $SMTP_AUTH_USERNAME_REGEX = qr/(?=.{1,253}$)[[:ascii:]]/; 
#REGEX to validate only ASCII characters in a SMTP AUTH Password.
my $SMTP_AUTH_PASSWORD_REGEX = qr/(?=.{1,253}$)[[:ascii:]]/; 
#REGEX to determine any non-ASCII characters in subject line of the email (note the carat at the beginning).
my $SUBJECT_REGEX = qr/[^[:ascii:]]/; 
#REGEX to determine any non-ASCII characters in body of the email (note the carat at the beginning).
my $MESSAGEBODY_REGEX = qr/[^[:ascii:]]/; 
#REGEX to validate a valid *nix path and filename (e.g. /tmp/data.txt).
my $ATTACHMENT_PATH_REGEX = qr/^(?=.{1,253}$)((\.\.\/|[a-zA-Z0-9_\/\-\\])*\.[a-zA-Z0-9]+)$/; 

 ####### #     # #     #  #####  ####### ### ####### #     #  #####
 #       #     # ##    # #     #    #     #  #     # ##    # #     #
 #       #     # # #   # #          #     #  #     # # #   # #
 #####   #     # #  #  # #          #     #  #     # #  #  #  #####
 #       #     # #   # # #          #     #  #     # #   # #       #
 #       #     # #    ## #     #    #     #  #     # #    ## #     #
 #        #####  #     #  #####     #    ### ####### #     #  #####

#Functions go here
sub show_usage
{
print "Example: $0 -t NOC\@local.lan --cc admin\@local.lan -f server2\@local.lan -h smtp.local.lan -p 25 --s \"Status\" --b \"Done\"
*NOTE* Most of the below variables can be configured as defaults within the script.

Usage: $0 --to|-t TO[,TO]
  [--from|-f FROM]
  [--cc|-c CC[,CC]]
  [--subject|-s \"SUBJECT\"]
  [--body|-b \"BODY\"]
  [--attachment|-a \"/PATH/TO/ATTACHMENT\"]
  [--host|-h SMTP-HOST] (e.g. smtp.domain.lan, 192.168.1.2, MAIL)
  [--port|-p SMTP-PORT] (e.g. 25, 587)
  [--username|-u SMTP-USERNAME]
  [--password|-x SMTP-PASSWORD]
  [--ehlodomain|-e SMTP-EHLO-DOMAIN] (e.g. domain.lan)
  [--debug|-d] (Debug)
  [--logging|-l] (Log To Syslog)
  [--exitonerror] (Exit immediately if the script encounters an error. If the error is not fatal, the script will try to continue)
  [--help] (See this help screen)

Simple Perl Emailer (https://github.com/incompetent-nerd/simple-perl-emailer)
Version 1.0 - 2020/05/02\n";
exit;
}

 #     #    #    ######  ###    #    ######  #       #######       #     #####   #####  ###  #####  #     # #     # ####### #     # #######
 #     #   # #   #     #  #    # #   #     # #       #            # #   #     # #     #  #  #     # ##    # ##   ## #       ##    #    #
 #     #  #   #  #     #  #   #   #  #     # #       #           #   #  #       #        #  #       # #   # # # # # #       # #   #    #
 #     # #     # ######   #  #     # ######  #       #####      #     #  #####   #####   #  #  #### #  #  # #  #  # #####   #  #  #    #
  #   #  ####### #   #    #  ####### #     # #       #          #######       #       #  #  #     # #   # # #     # #       #   # #    #
   # #   #     # #    #   #  #     # #     # #       #          #     # #     # #     #  #  #     # #    ## #     # #       #    ##    #
    #    #     # #     # ### #     # ######  ####### #######    #     #  #####   #####  ###  #####  #     # #     # ####### #     #    #

#Assigns variables passed from shell
GetOptions (
  'to|t=s'              => \@TO,
  'from|f=s'            => \$FROM,
  'cc|c=s'              => \@CC,
  'subject|s=s'         => \$SUBJECT,
  'body|b=s'            => \$MESSAGEBODY,
  'attachment|a=s'      => \$ATTACHMENT,
  'host|h=s'            => \$SMTPHOST,
  'port|p=i'            => \$SMTPPORT,
  'username|u=s'        => \$SMTPUSERNAME,
  'password|x=s'        => \$SMTPPASSWORD,
  'ehlodomain|e=s'      => \$SMTPEHLODOMAIN,
  'debug|d'             => \$DEBUG,
  'logging|l'           => \$LOGGING,
  'exitonerror'         => \$EXITONERROR,
  'help'                => \$HELP,
  ) or show_usage();

#Show usage help if script is called with --help.
if ( $HELP ) {
  show_usage ();
}

#Populate TO and CC with all of the email addresses passed from the command line.
#If UNTRUSTED_INPUT is set to 1, the script will immediately filter all the data.
#If UNTRUSTED_INPUT is set to 0, the script will filter the data later on in the script and show you in more detail which emails (if any) are being discarded and why.
if ($UNTRUSTED_INPUT == '1') {
  @TO = grep { /$EMAIL_ADDRESS_REGEX/ } split(/,/,join(',',@TO));
  @CC = grep { /$EMAIL_ADDRESS_REGEX/ } split(/,/,join(',',@CC));
} else {
  @TO = split(/,/,join(',',@TO));
  @CC = split(/,/,join(',',@CC));
}

 ### #     # ######  #     # #######    #     #    #    #       ### ######     #    ####### ### ####### #     #
  #  ##    # #     # #     #    #       #     #   # #   #        #  #     #   # #      #     #  #     # ##    #
  #  # #   # #     # #     #    #       #     #  #   #  #        #  #     #  #   #     #     #  #     # # #   #
  #  #  #  # ######  #     #    #       #     # #     # #        #  #     # #     #    #     #  #     # #  #  #
  #  #   # # #       #     #    #        #   #  ####### #        #  #     # #######    #     #  #     # #   # #
  #  #    ## #       #     #    #         # #   #     # #        #  #     # #     #    #     #  #     # #    ##
 ### #     # #        #####     #          #    #     # ####### ### ######  #     #    #    ### ####### #     #

#Verify all the TO email addresses are valid.
#If invalid, and if EXITONERROR is enabled, the script will exit.
#If invalid, and if EXITONERROR is disabled, the script will remove the offending email and attempt to continue.
if (@TO) {
  if ($UNTRUSTED_INPUT == '0') {
    foreach my $TO (@TO) {
      #EMAIL_ADDRESS_REGEX above will limit email length to 253.
      #This is here for additional flexibility in case we want to restrict to less than 253.
      if (length($TO) <= $EMAIL_LENGTH_LIMIT) {
        if ($TO !~ /$EMAIL_ADDRESS_REGEX/ ) {
          if ($EXITONERROR == '1') {
            die "The Email " . "\"$TO\" " . "is not in a proper email address form e.g. user\@domain.lan, first.last\@domain.lan.\n" .
            "The script will now exit, no email has been sent.\n\n";
            } elsif ($DEBUG == '1') {
            print "The Email " . "\"$TO\" " . "is not in a proper email address form e.g. user\@domain.lan, first.last\@domain.lan.\n" .
            "The particular email will be removed and the script will attempt to continue.\n\n";
            }
           }
        } else {
         print "The Email address " . substr($TO, 0, 16) . "... exceeds $EMAIL_LENGTH_LIMIT characters and is not RFC 3696 compliant.\n" .
         "The particular email will be removed and the script will attempt to continue.\n\n";
      }
    }
  #This is where the emails that do not conform to a valid email address are filtered out.
  @TO = grep { /$EMAIL_ADDRESS_REGEX/ } @TO;
    if (!@TO) {
    die "All valid recipients have been removed due to formatting errors. No more recipients to send to. Need at least one recipient.\n" .
    "The script will now exit, no email has been sent.\n\n";
    }
  }
} else {
  #We need to have at least one recipient, so if there is no recipient print out an error and exit.
  print "\nNeed at least one recipient {--to TO}.\n\n";
  show_usage();
}

#Verify all the CC email addresses are valid.
#If invalid, and if EXITONERROR is enabled, the script will exit.
#If invalid, and if EXITONERROR is disabled, the script will remove the offending email and attempt to continue.
if (@CC) {
  if ($UNTRUSTED_INPUT == '0') {
    foreach my $CC (@CC) {
      #EMAIL_ADDRESS_REGEX above will limit email length to 253.
      #This is here for additional flexibility in case we want to restrict to less than 253.
      if (length($CC) <= $EMAIL_LENGTH_LIMIT) {
        if ($CC !~ /$EMAIL_ADDRESS_REGEX/ ) {
          if ($EXITONERROR == '1') {
            die "The Email " . "\"$CC\" " . "is not in a proper email address form e.g. user\@domain.lan, first.last\@domain.lan.\n" .
            "The script will now exit, no email has been sent.\n\n";
            } elsif ($DEBUG == '1') {
            print "The Email " . "\"$CC\" " . "is not in a proper email address form e.g. user\@domain.lan, first.last\@domain.lan.\n" .
            "The particular email will be removed and the script will attempt to continue.\n\n";
            }
          }
        } elsif ($DEBUG == '1') {
        print "The Email address " . substr($CC, 0, 16) . "... exceeds $EMAIL_LENGTH_LIMIT characters and is not RFC 3696 compliant.\n" .
        "The particular email will be removed and the script will attempt to continue.\n\n";
      }
    }
  #This is where the emails that do not conform to a valid email address are filtered out.
  @CC = grep { /$EMAIL_ADDRESS_REGEX/ } @CC;
  }
}

#Verify the from address is valid. If invalid, this is a fatal error as the SMTP server should refuse to the send the email.
#EMAIL_ADDRESS_REGEX above will limit email length to the RFC standard of 253.
#This is here for additional flexibility in case we want to restrict to less than 253.
if ($FROM ne '') {
  if (length($FROM) <= $EMAIL_LENGTH_LIMIT) {
    if ($FROM !~ /$EMAIL_ADDRESS_REGEX/ ) {
      die "The from email address " . "\"$FROM\" " . "is not in a proper email address form e.g. user\@domain.lan, first.last\@domain.lan.\n" .
      "The script will now exit, no email has been sent.\n\n";
    }
  } else {
    die "The \"from\" email address " . substr($FROM, 0, 16) . "... exceeds $EMAIL_LENGTH_LIMIT characters and is not RFC 3696 compliant.\n" .
    "The script will now exit, no email has been sent.\n\n";
  } 
} else {
  print "No FROM email address provided. Need to know who this email is from.\n\n";
  show_usage();
}

#Verify the SMTP host is valid. If invalid, this is a fatal error.
#$HOSTNAME_REGEX above will limit email length to the RFC standard of 253
#This is here for additional flexibility in case we want to restrict to less than 253.
if ($SMTPHOST ne '') {
  if (length($SMTPHOST) <= $SMTP_HOSTNAME_LENGTH_LIMIT) {
    if ( $SMTPHOST !~ /$HOSTNAME_REGEX/ ) {
      die "The SMTP host " . "\"$SMTPHOST\" " . "is not a valid host name, FQDN or IP address e.g. mail.domain.lan, mail, 192.168.0.10.\n" .
      "The script will now exit, no email has been sent.\n\n";
    }
  } else {
    die "The SMTP host name " . substr($SMTPHOST, 0, 16) . "... exceeds $SMTP_HOSTNAME_LENGTH_LIMIT characters and is not RFC 1123 compliant.\n" .
    "The script will now exit, no email has been sent.\n\n";
  }
} else {
  print "No SMTP host provided. Need to know what SMTP server to use.\n";
  show_usage();
}

#Verify the SMTP port is valid. If invalid, this is a fatal error.
if (defined $SMTPPORT) {
  if ($SMTPPORT >= 1 && $SMTPPORT <= 65535) {
    if ( $SMTPPORT !~ /$PORTNUMBER_REGEX/ ) {
      die "The SMTP port number " . "\"$SMTPPORT\" " . "is outside a valid range e.g. 1-65535.\n" .
      "The script will now exit, no email has been sent.\n\n";
    }
  } else {
    die "The SMTP port " . substr($SMTPPORT, 0, 5) . " is outside a valid range e.g. 1-65535.\n" .
    "The script will now exit, no email has been sent.\n\n";
    }
} else {
  print "No SMTP port provided. Need to know what SMTP port to use.\n";
  show_usage();
}

#Verify the SMTP EHLO domain is valid. If invalid, this is a fatal error.
#If no EHLO domain is supplied, Net::SMTP will use the name of the local server.
#$HOSTNAME_REGEX above will limit the domain name length to the RFC standard of 253
#This is here for additional flexibility in case we want to restrict to less than 253.
if (defined $SMTPEHLODOMAIN) {
  if (length($SMTPEHLODOMAIN) <= $SMTP_EHLO_DOMAIN_LENGTH_LIMIT) {
    if ( $SMTPEHLODOMAIN !~ /$SMTP_EHLO_DOMAIN_REGEX/ ) {
      die "The SMTP EHLO domain " . "\"$SMTPEHLODOMAIN\" " . "is not a valid host name or IP address e.g. mail.domain.lan, mail, 192.168.0.10.\n" .
      "The script will now exit, no email has been sent.\n\n";
    }
  } else {
    die "The SMTP EHLO domain " . substr($SMTPEHLODOMAIN, 0, 16) . "... exceeds $SMTP_EHLO_DOMAIN_LENGTH_LIMIT characters and is not RFC 5321 compliant.\n" .
    "The script will now exit, no email has been sent.\n\n";
  }
} elsif ($DEBUG == '1') {
  print "No EHLO domain has been supplied.\n" .
  "By default Net::SMTP will use localhost.localdomain as the EHLO domain. *NOTE* Not all servers may accept localhost.localdomain as valid.\n" .
  "Script is continuing.\n";
}

#Verify the SMTP username is valid. If invalid, this is a fatal error.
if (defined $SMTPUSERNAME) {
  #SMTP_AUTH_USERNAME_REGEX above will limit email length to the RFC standard of 253.
  #This is here for additional flexibility in case we want to restrict to less than 253.
  if (length($SMTPUSERNAME) <= $SMTP_AUTH_USERNAME_LENGTH_LIMIT) {
    if ($SMTPUSERNAME !~ /$SMTP_AUTH_USERNAME_REGEX/ ) {
    die "The SMTP username " . "\"$SMTPUSERNAME\" " . "appears to contain non-ASCII characters.\n" .
    "The script will now exit, no email has been sent.\n\n";
    }
  } else {
    die "The SMTP username " . substr($SMTPUSERNAME, 0, 16) . "... exceeds $SMTP_AUTH_USERNAME_LENGTH_LIMIT characters.\n" .
    "The script will now exit, no email has been sent.\n\n";
  }
}

#Verify the SMTP password is valid. If invalid, this is a fatal error.
if (defined $SMTPPASSWORD) {
  #SMTP_AUTH_PASSWORD_REGEX above will limit email length to the RFC standard of 253.
  #This is here for additional flexibility in case we want to restrict to less than 253.
  if (length($SMTPPASSWORD) <= $SMTP_AUTH_PASSWORD_LENGTH_LIMIT) {
    if ($SMTPPASSWORD !~ /$SMTP_AUTH_PASSWORD_REGEX/ ) {
    die "The SMTP password " . "\"$SMTPPASSWORD\" " . "appears to contain non-ASCII characters.\n" .
    "The script will now exit, no email has been sent.\n\n";
    }
  } else {
    die "The SMTP password " . substr($SMTPPASSWORD, 0, 16) . "... exceeds $SMTP_AUTH_PASSWORD_LENGTH_LIMIT characters.\n" .
    "The script will now exit, no email has been sent.\n\n";
  }
}

#Verify the body is valid.
#If invalid, and if EXITONERROR is enabled, the script will exit.
#If invalid, and if EXITONERROR is disabled, the script will strip invalid characters and attempt to continue.
if (defined $MESSAGEBODY) {
  if (length ($MESSAGEBODY) <= $MESSAGEBODY_SIZE_LIMIT) {
    if ($MESSAGEBODY =~ /$MESSAGEBODY_REGEX/ ) {
      if ($EXITONERROR == '1') {
      die "The email body has invalid characters. The script will now exit, no email has been sent.\n\n" ;
      } elsif ($DEBUG == '1') {
      print "The email body has invalid characters.\n" .
      "The invalid characters will be stripped and the script will attempt to continue.\n\n";
      ($MESSAGEBODY) =~ s/$MESSAGEBODY_REGEX//g;
      }
    }
  } else {
    die "The email body exceeds $MESSAGEBODY_SIZE_LIMIT characters.\n" .
    "The script will now exit, no email has been sent.\n\n";
  }
}

#Verify the subject is valid.
#If invalid, and if EXITONERROR is enabled, the script will exit.
#If invalid, and if EXITONERROR is disabled, the script will strip invalid characters and attempt to continue.
if (defined $SUBJECT) {
  if (length ($SUBJECT) <= $SUBJECT_LENGTH_LIMIT) {
    if ($SUBJECT =~ /$SUBJECT_REGEX/ ) {
      if ($EXITONERROR == '1') {
      die "The Subject " . "\"$SUBJECT\" " . "has invalid characters. The script will now exit, no email has been sent.\n\n" ;
      } elsif ($DEBUG == '1') {
      print "The Subject " . "\"$SUBJECT\" " . "has invalid characters.\n" .
      "The invalid characters will be stripped and the script will attempt to continue.\n\n";
      ($SUBJECT) =~ s/$SUBJECT_REGEX//g;
      }
    }
  } else {
    die "The subject " . substr($SUBJECT, 0, 16) . "... exceeds $SUBJECT_LENGTH_LIMIT characters and does not follow RFC 2822.\n" .
    "The script will now exit, no email has been sent.\n\n";
  }
}

#Verify the attachment is valid.
#If invalid, and if EXITONERROR is enabled, the script will exit.
#If invalid, and if EXITONERROR is disabled, the script will strip invalid characters and attempt to continue.
if (defined $ATTACHMENT) {
  if (length($ATTACHMENT) <= $ATTACHMENT_PATH_LIMIT) {
    if (-s $ATTACHMENT <= $ATTACHMENT_SIZE_LIMIT) {
      if ($ATTACHMENT !~ /$ATTACHMENT_PATH_REGEX/ ) {
        if ($EXITONERROR == '1') {
          die "The attachment " . "\"$ATTACHMENT\" " . "is not in a valid format (e.g. /path/path/file.txt).
          The script will now exit, no email has been sent.\n\n";
          } elsif ($DEBUG == '1') {
          print "The attachment " . "\"$ATTACHMENT\" " . "is not in a valid format (e.g. /path/path/file.txt)\n" .
          "The attachment has been removed and the script will attempt to continue.\n\n";
          undef $ATTACHMENT;
        }
      }
    } else {
      if ($EXITONERROR == '1') {
        die "The size of the attachment " . substr($ATTACHMENT, 0, 16) . "... exceeds $ATTACHMENT_SIZE_LIMIT bytes.\n" .
        "The script will now exit, no email has been sent.\n\n";
        } elsif ($DEBUG == '1') {
        print "The size of the attachment " . substr($ATTACHMENT, 0, 16) . "... exceeds $ATTACHMENT_SIZE_LIMIT bytes.\n" .
        "The attachment has been removed and the script will attempt to continue.\n\n";
        undef $ATTACHMENT;
      }
    }
  } else {
    if ($EXITONERROR == '1') {
      die "The path for the attachment " . substr($ATTACHMENT, 0, 16) . "... exceeds $ATTACHMENT_PATH_LIMIT characters.\n" .
      "The script will now exit, no email has been sent.\n\n";
      } elsif ($DEBUG == '1') {
      print "The path for the attachment " . substr($ATTACHMENT, 0, 16) . "... exceeds $ATTACHMENT_PATH_LIMIT characters.\n" .
      "The attachment has been removed and the script will attempt to continue.\n\n";
      undef $ATTACHMENT;
    }
  }
}

 ### #######    ######  ####### ######  #     #  #####
  #  #          #     # #       #     # #     # #     #
  #  #          #     # #       #     # #     # #
  #  #####      #     # #####   ######  #     # #  ####
  #  #          #     # #       #     # #     # #     #
  #  #          #     # #       #     # #     # #     #
 ### #          ######  ####### ######   #####   #####

#If debug is enabled, print what the script will do and using what variables.
if ($DEBUG == '1') {
  print "Sending an email from $FROM to ";
  foreach my $TO (@TO) {
    print ("$TO, ");
  }
  print ",\b\b\b"; #Remove pesky trailing comma on last email.
  if (@CC) {
    print " and CC'd to ";
    foreach my $CC (@CC) {
    print ("$CC, ");
    }
    print ",\b\b\b"; #Remove pesky trailing comma on last email.
  }
  print " with the subject \"$SUBJECT\", a body of \"$MESSAGEBODY\"";
  if (defined $ATTACHMENT) {
    print " and attachment ${\basename($ATTACHMENT)}";
  }
  print " using port $SMTPPORT on SMTP server $SMTPHOST";
  if ($LOGGING == '1') {
    print " and an entry will be logged into the system log.";
  }
  print "\n";
}

 #     #    #    ### #     #
 ##   ##   # #    #  ##    #
 # # # #  #   #   #  # #   #
 #  #  # #     #  #  #  #  #
 #     # #######  #  #   # #
 #     # #     #  #  #    ##
 #     # #     # ### #     #


#Generate a randomized MIME boundary.
sub rndStr{ join'', @_[ map{ rand @_ } 1 .. shift ] }
my $boundary = '------------' . rndStr 32, 'A'..'Z', 0..9, 'a'..'z', '-', '_';

#Connect to SMTP server.
my $smtp = Net::SMTP->new($SMTPHOST, Port => $SMTPPORT, Hello => $SMTPEHLODOMAIN, Timeout => $SMTP_TIMEOUT, Debug => $DEBUG) || die "Can't talk to server $SMTPHOST\n";

#If both SMTP username and password exist, then use SMTP AUTH to log into SMTP server before sending email.
if (defined $SMTPUSERNAME && defined $SMTPPASSWORD) {
  $smtp->starttls();
  $smtp->auth($SMTPUSERNAME, $SMTPPASSWORD);
}

#Transmit SMTP FROM data.
$smtp->mail("$FROM") || die "SMTP server rejected the FROM email recipient $FROM. The script will now exit, no email has been sent.\n";

#Transmit SMTP TO data.
foreach my $TO (@TO) {
  if ($EXITONERROR == '0') {
    if ($DEBUG == '1') {
      $smtp->to("$TO") || print "SMTP server rejected the TO email recipient $TO. The script will attempt to continue.\n";
    } else {
      $smtp->to("$TO");
    }
  } else {
    $smtp->to("$TO") || die "SMTP server rejected the TO email recipient $TO. The script has exited, no email has been sent.\n";
  }
}

#If CC is populated, send to each CC recipient.
if (@CC) {
  foreach my $CC (@CC) {
    if ($EXITONERROR == '0') {
      if ($DEBUG == '1') {
        $smtp->to("$CC") || print "SMTP server rejected the CC email recipient $CC. The script will attempt to continue.\n";
      } else {
        $smtp->to("$CC");
      }
    } else {
      $smtp->to("$CC") || die "SMTP server rejected the CC email recipient $CC. The script has exited, no email has been sent.\n";
    }
  }
}

#Transmit appropriate headers.
$smtp->data();
$smtp->datasend("Date: ".strftime("%a, %e %b %Y %X %z", localtime())."\n");
$smtp->datasend("From: $FROM\n");

#Send each TO header.
foreach my $TO (@TO) {
  $smtp->datasend("To: $TO\n");
}

#If CC is populated, send CC header.
if (@CC) {
  foreach my $CC (@CC) {
  $smtp->datasend("Cc: $CC\n");
  }
}

#Send the subject of the message.
$smtp->datasend("Subject: $SUBJECT\n");

#Send the MIME version and boundary.
$smtp->datasend("MIME-Version: 1.0\n");
$smtp->datasend("Content-type: multipart/mixed;\n\tboundary=\"$boundary\"\n\n");

#Send the body of the message.
$smtp->datasend("--$boundary\n");
$smtp->datasend("Content-Type: text/plain;\n\n");
$smtp->datasend("$MESSAGEBODY\n\n");

#If an attachment has been passed as a variable, send the attachment in the email.
if (defined $ATTACHMENT) {
  $smtp->datasend("--$boundary\n");
  #The basename ensures that only the filename appears as the attachment and not the entire path.
  $smtp->datasend("Content-Type: application/octet-stream; name=\"${\basename($ATTACHMENT)}.\"\n");
  $smtp->datasend("Content-Transfer-Encoding: base64\n");
  $smtp->datasend("Content-Disposition: attachment; filename=\"${\basename($ATTACHMENT)}.\"\n\n");
  open(DAT, "$ATTACHMENT") || die("Could not open binary file!");
  my $buf;
  binmode(DAT);
  local $/=undef;
  while (read(DAT, my $picture, 72*57)) {
    $buf = &encode_base64( $picture );
    $smtp->datasend($buf);
  }
  close(DAT);
  $smtp->datasend("\n");
}

#Send the terminating MIME bounday and close the SMTP connection.
$smtp->datasend("--$boundary--\n");
$smtp->dataend();
$smtp->quit;

 ######  ######  ### #     # #######     #####  #######    #    ####### #     #  #####
 #     # #     #  #  ##    #    #       #     #    #      # #      #    #     # #     #
 #     # #     #  #  # #   #    #       #          #     #   #     #    #     # #
 ######  ######   #  #  #  #    #        #####     #    #     #    #    #     #  #####
 #       #   #    #  #   # #    #             #    #    #######    #    #     #       #
 #       #    #   #  #    ##    #       #     #    #    #     #    #    #     # #     #
 #       #     # ### #     #    #        #####     #    #     #    #     #####   #####

#Log to Syslog if logging is enabled.
if ($LOGGING == '0' && $DEBUG == '1') {
  print "Script has completed sending the email.\n"
} elsif ($LOGGING == '1' && $DEBUG == '1') {
  `logger $0 Script Sent An Mail From $FROM to @TO With Subject $SUBJECT`;
  print "Script has completed sending the email and a message has been logged to the SYSLOG.\n"
}




