Simple Perl Emailer.</br>
</br>
This script was created out of necessity.</br>
A production server needed to be able to send SMTP emails and I was unable to find any email scripts that would work with the limited subset of Perl modules the server had.</br>
If you have the ability to install additional Perl modules, I recommend you find a better script.</br>
</br>
Please send bug reports, corrections and stinging insults to author: incompetent.nerd(at)gmail.com</br>
</br>
Usage: ./email.pl --to|-t TO[,TO]<br>
  [--from|-f FROM]<br>
  [--cc|-c CC[,CC]]</br>
  [--subject|-s "SUBJECT"]</br>
  [--body|-b "BODY"]</br>
  [--attachment|-a "/PATH/TO/ATTACHMENT.TXT"]</br>
  [--host|-h SMTP-HOST] (e.g. smtp.domain.lan, 192.168.1.2, MAIL)</br>
  [--port|-p SMTP-PORT] (e.g. 25, 587)</br>
  [--username|-u SMTP-USERNAME]</br>
  [--password|-x SMTP-PASSWORD]</br>
  [--ehlodomain|-e SMTP-EHLO-DOMAIN] (e.g. domain.lan)</br>
  [--debug|-d] (Debug)</br>
  [--logging|-l] (Log To Syslog)</br>
  [--exitonerror] (Exit immediately if the script encounters an error. If the error is not fatal, the script will try to continue)</br>
  [--help] (help)</br>
  Example: email.pl -t NOC@local.lan --cc admin@local.lan -f server2@local.lan -h smtp.local.lan -p 25 --s "Status" --b "Done"</br>
  </br>
  *NOTE* Most of the above variables can be configured as defaults within the script.</br>
  
  
Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
