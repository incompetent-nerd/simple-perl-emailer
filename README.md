Simple Perl Emailer.</br>
</br>
This script was created out of necessity.</br>
I needed to send SMTP email from a server but could not add Perl modules to the system, I was forced to use only the existing Perl</br>
modules on the system. I was unable to find any email scripts that would work with the limited subset of modules I had.</br>
If you have the ability to install additional Perl modules, I recommend you find a better script.</br>
</br>
Please send bug reports, corrections and stinging insults to author: incompetent.nerd@gmail.com</br>
</br>
Usage: ./email.pl --to|-t TO[,TO]<br>
  [--from|-f FROM]<br>
  [--cc|-c CC[,CC]]</br>
  [--subject|-s "SUBJECT"]</br>
  [--body|-b "BODY"]</br>
  [--attachment|-a "/PATH/TO/ATTACHMENT.TXT"]</br>
  [--host|-h SMTP-HOST] (e.g. smtp.domain.local, 192.168.1.2, MAIL)</br>
  [--port|-p SMTP-PORT] (e.g. 25, 587)</br>
  [--username|-u SMTP-USERNAME]</br>
  [--password|-x SMTP-PASSWORD]</br>
  [--ehlodomain|-e SMTP-EHLO-DOMAIN] (e.g. domain.local)</br>
  [--debug|-d] (Debug)</br>
  [--logging|-l] (Log To Syslog)</br>
  [--exitonerror] (Exit immediately if the script encounters an error. If the error is not fatal, the script will try to continue)</br>
  [--help] (help)</br>
  Example: email.pl -t NOC@local.lan --cc admin@local.lan -f server2@local.lan -h smtp.local.lan -p 25 --s "Status" --b "Done"</br>
  </br>
  *NOTE* Any of the above variables can be configured as defaults within the script.</br>
