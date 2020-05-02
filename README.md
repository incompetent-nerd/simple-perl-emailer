Simple Perl Emailer.

This script was created out of necessity.
I needed to send SMTP email from a server but could not add Perl modules to the system, I was forced to use only the existing Perl
modules on the system. I was unable to find any email scripts that would work with the limited subset of modules I had.
If you have the ability to install additional Perl modules, I recommend you find a better script.

Please send bug reports, corrections and stinging insults to author: incompetent.nerd@gmail.com

Usage: ./email.pl --to|-t TO[,TO]
  [--from|-f FROM]
  [--cc|-c CC[,CC]]
  [--subject|-s "SUBJECT"]
  [--body|-b "BODY"]
  [--attachment|-a "/PATH/TO/ATTACHMENT.TXT"]
  [--host|-h SMTP-HOST] (e.g. smtp.domain.local, 192.168.1.2, MAIL)
  [--port|-p SMTP-PORT] (e.g. 25, 587)
  [--username|-u SMTP-USERNAME]
  [--password|-x SMTP-PASSWORD]
  [--ehlodomain|-e SMTP-EHLO-DOMAIN] (e.g. domain.local)
  [--debug|-d] (Debug)
  [--logging|-l] (Log To Syslog)
  [--exitonerror] (Exit immediately if the script encounters an error. If the error is not fatal, the script will try to continue)
  [--help] (help)
  Example: email.pl -t NOC@local.lan --cc admin@local.lan -f server2@local.lan -h smtp.local.lan -p 25 --s "Status" --b "Done"
  
  *NOTE* Any of the above variables can be configured as defaults within the script.
