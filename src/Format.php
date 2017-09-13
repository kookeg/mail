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



    public static function getSmartCol($mbox, $delimiter)
    {
        $sent      = GlobalVar::get('sent_box');
        $draft     = GlobalVar::get('drafts_box');
        $sentBox   = $sent . $delimiter;
        $currBox   = $mbox . $delimiter;
        $draftBox  = $draft . $delimiter;
        if((strpos($currBox, $sentBox) === 0 || strpos($currBox, $sentBox) === 0 ) && $mbox != 'INBOX'){
            return 'to';
        }
        return 'from';
    }

    protected static function formatAddress($input, $max, $charset = '')
    {
        $a_parts = Mime::decode_address_list($input, null, true, $charset); 
        if(!count($a_parts)){
            return $input; 
        }
        $out = array();
        foreach($a_parts as $part){
            $out[] = Helper::idn_to_utf8(!is_array($part) ? $part : $part['string']);  
        }
        return implode(';', $out);
    } 

    public static function formatMessageList($messages, $folder = '', $delimiter)
    {
        $list = array();

        $list_cols = GlobalVar::get('list_cols');
        $show_cols = !empty($list_cols) && is_array($list_cols) ? $list_cols : array('subject');   
        if(array_search('fromto', $show_cols)){
            $smart_col = self::getSmartCol($folder, $delimiter); 
        }
        $msg_cols = $msg_flags = array();
        foreach($messages as $header){
            if(empty($header)){
                continue;
            } 
            foreach($show_cols as $col){
                $col_name = $col == 'fromto' ? $smart_col : $col; 
                switch($col_name){
                case 'from': 
                case 'to': 
                case 'cc': 
                case 'replyto': 
                    $res = self::formatAddress($header->$col_name, 3, $header->charset); 
                    $res = $res ? $res : '&nbsp;';
                    break;
                case 'subject':
                    $res = trim(Mime::decode_header($header->$col, $header->charset));
                    break;
                case 'size':
                    $res = Helper::show_bytes($header->$col);
                    break;
                case 'date':
                    $res = date('Y-m-d H:i:s', Helper::strtotime($header->$col));
                    break;
                default:
                    $res = Helper::rep_specialchars_output($header->$col, 'html', 'strict', true);
                }
                $msg_cols[$col_name] = $res;
            }

            $msg_flags = array_change_key_case(array_map('intval', (array) $header->flags));
            if ($header->depth)
                $msg_flags['depth'] = $header->depth;
            else if ($header->has_children)
                $roots[] = $header->uid;
            if ($header->parent_uid)
                $msg_flags['parent_uid'] = $header->parent_uid;
            if ($header->has_children)
                $msg_flags['has_children'] = $header->has_children;
            if ($header->unread_children)
                $msg_flags['unread_children'] = $header->unread_children;
            if ($header->flagged_children)
                $msg_flags['flagged_children'] = $header->flagged_children;
            if ($header->others['list-post'])
                $msg_flags['ml'] = 1;
            if ($header->priority)
                $msg_flags['prio'] = (int) $header->priority;

            $msg_flags['ctype'] = Helper::rep_specialchars_output($header->ctype, 'html', 'strict', true);
            $msg_flags['mbox']  = $header->mailBoxName;

            // merge with plugin result (Deprecated, use $header->flags)
            if (!empty($header->list_flags) && is_array($header->list_flags))
                $msg_flags = array_merge($msg_flags, $header->list_flags);
            if (!empty($header->list_cols) && is_array($header->list_cols))
                $msg_cols = array_merge($msg_cols, $header->list_cols);
            $list[$header->uid]['msg'] = $msg_cols;
            $list[$header->uid]['flag'] = $msg_flags;
        }
        return $list;

    }
}
