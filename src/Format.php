<?php 
namespace Cooker\Mail;

use Cooker\Mail\Imap\MailBox;

class Format
{

    public static function formatMailBoxes($mailBoxes, $imapServer)
    {
        $res = array();
        if($mailBoxes && $imapServer){
            foreach($mailBoxes as $mbox){
                $mbox = strpos($mbox, '&') === false ? $mbox : Charset::convert($mbox, 'UTF7-IMAP'); 
                $res[] = new MailBox($imapServer, $mbox); 
            }    
        }  
        return $res;
    }

}
