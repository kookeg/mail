<?php 
namespace Cooker\Mail\Imap;

use Cooker\Mail\Imap as ImapServer;
use Cooker\Mail\Exception\InviladException;
use Cooker\Mail\Error;
use Cooker\Mail\GlobalVar;
use Cooker\Mail\Helper;
use Cooker\Mail\Format;

class MailBox
{

    protected $imap   = null;

    protected $name   = '*';

    protected $parent = '';

    protected $filter = null;

    protected $rights = null;

    protected $sort   = array();
    protected $info   = array();

    protected $icache = array();

    protected $detectParent = false;


    public function __construct(ImapServer $imap, $name = null)
    {
        $this->imap = $imap;    
        $this->name = $name;
    }

    public function all($format = true)
    {
        $allBoxes = $this->getMailBoxFromImapDirect(); 
        $allBoxes = is_array($allBoxes) ? $allBoxes : array();
        if(
            Helper::in_array_nocase($this->parent . $this->name, array('*', '%', 'INBOX', 'INBOX*'))
            && (!$this->filter || $this->filter == 'mail')
            && !in_array('INBOX', $allBoxes) 
        ){
            array_unshift($allBoxes, 'INBOX');
        }
        if($this->rights && $this->imap->getCapability('ACL')){
            $allBoxes = $this->imap->filterRights($allBoxes, $rights);
        }
        $allBoxes = $this->imap->sortMailBoxList($allBoxes);
        return $format ? Format::formatMailBoxes($allBoxes, $this->imap) : $allBoxes;
    }

    public function allSubscribed($format = true)
    {
        $allBoxes = $this->getSubscribedMailBoxFromImapDirect();  
        if(
            Helper::in_array_nocase($this->parent . $this->name, array('*', '%', 'INBOX', 'INBOX*'))
            && (!$this->filter || $this->filter == 'mail')
            && !in_array('INBOX', $allBoxes) 
        ){
            array_unshift($allBoxes, 'INBOX');
        }
        if($this->rights && $this->imap->getCapability('ACL')){
            $allBoxes = $this->imap->filterRights($allBoxes, $rights);
        }
        $allBoxes = $this->imap->sortMailBoxList($allBoxes);
        return $format ? Format::formatMailBoxes($allBoxes, $this->imap) : $allBoxes;
    }

    /**
     * 创建mailbox 
     *
     * @access public 
     * @param  string $types (junk trash drafts sent archive)
     * @return bool 
     */

    public function create($type = null)
    {
        $name = $this->detectParent && $this->parent 
            ? $this->parent . $this->imap->delimiter . $this->name
            : $this->name;  
        $type = $type ? array("\\" . ucfirst($type)) : null;
        $name = array(Helper::escape($name));
        if($type && $this->imap->getCapability('CREATE-SPECIAL-USE')){
            $name[] = '(USE (' . implode(' ', $type) . '))'; 
        }
        $code = $this->imap->getConnection()->execute('CREATE', $name, Command::COMMAND_NORESPONSE);
        return $code == Error::ERROR_OK;
    }


    public function delete()
    {
        if($this->name && $this->name == '*'){
            return false; 
        } 
        $path = strspn($this->name, '%*') > 0 ? ($name . $this->imap->delimiter) : '';  
        $obj  = clone($this); 
        $subBox = $obj->setName($path)->all();
        if ($subBox) {
            foreach (array_reverse($subBox) as $mbox) {
                if (strpos($mbox->getName(), $this->name . $this->imap->delimiter) === 0) {
                    if ($this->deleteMailBox($mbox->getName())) {
                        $this->unsubscribeMailBox($mbox->getName());
                    }
                }
            }
        }
        if ($result = $this->deleteMailBox($this->name)) {
            $this->unsubscribeMailBox($this->name);
        } 
        return $result;
    }

    public function rename($newName = '')
    {
        if(!$newName || !$this->name || $this->name == '*'){
            return false;
        } 

        if ((strpos($this->name, '%') === false) && (strpos($this->name, '*') === false)) {
            $obj = clone $this;
            $obj->setName($this->name . $this->imap->delimiter . '*');
            $subscribedMailBoxes = $obj->allSubscribed();
            $subscribed   = $this->exist(true);
        }else {
            $subscribedMailBoxes = $this->allSubscribed();
            $subscribed          = in_array($this->name, $subscribedMailBoxes);
        }

        $result = $this->renameMailBox($this->name, $newName);

        if ($result) {
            // unsubscribe the old folder, subscribe the new one
            if ($subscribed) {
                $this->unsubscribeMailBox($this->name);
                $this->subscribeMailBox($newName);
            }
            // check if folder children are subscribed
            foreach ($subscribedMailBoxes as $subscribed) {
                if (strpos($subscribed, $this->name . $this->imap->delimiter) === 0) {
                    $this->unsubscribeMailBox($subscribed);
                    $this->subscribeMailBox(preg_replace('/^'.preg_quote($this->name, '/').'/',
                        $newName, $subscribed));
                }
            }
        }
        return $result;
    }


    public function subscribe()
    {
        if($this->validName()){
            return $this->subscribeMailBox($this->name);
        }
        return false;
    }

    public function unsubscribe()
    {
        if($this->validName()){
            return $this->unsubscribeMailBox($this->name);
        }
        return false;
    }

    public function exist($subscription = false)
    {
        if ($this->name == 'INBOX') {
            return true;
        }
        $key = $subscription ? 'subscribed' : 'existing';
        if(is_array(GlobalVar::get($key)) && in_array($this->name, GlobalVar::get($key))){
            return true;
        }
        if (!$this->imap->checkConnection()) {
            return false;
        }

        if ($subscription) {
            // It's possible we already called LIST command, check LIST data
            if (
                !($tmp = GlobalVar::get('LIST.' . $this->name, false))
                && Helper::in_array_nocase('\\Subscribed', $tmp)
            ) {
                $allBoxes = array($this->name);
            }else {
                $allBoxes = $this->listMailboxes(true);
            }
        }else {
            // It's possible we already called LIST command, check LIST data
            if (
                !($tmp = GlobalVar::get('LIST.' . $this->name, false))
                && Helper::in_array_nocase('\\Subscribed', $tmp)
            ) {
                $allBoxes = array($this->name);
            }else {
                $allBoxes = $this->listMailboxes();
            }
        }

        if (is_array($allBoxes) && in_array($this->name, $allBoxes)) {
            GlobalVar::set($key, array($this->name));
            return true;
        }
        return false;
    }

    public function setImap(ImapServer $imap)
    {
        $this->imap = $imap; 
        return $this;
    }

    public function setDetectParent($bool = false)
    {
        $this->detectParent = $bool; 
        return $this;
    }

    public function setName($name = null)
    {
        $this->name = $name; 
        return $this;
    }

    public function getName()
    {
        return $this->name;
    }

    public function setParent($parent)
    {
        $this->parent = trim($parent);
        return $this;
    }

    public function setFilter($filter)
    {
        $this->filter = $filter; 
        return $this;
    }

    public function setRights($rights)
    {
        $this->rights = $rights; 
        return $this;
    }

    public function setSort($sort = array())
    {
        $this->sort = (array)$sort; 
        return $this;
    }

    public function getImap()
    {
        if($this->imap instanceof ImapServer){
            return $this->imap;
        } 
        throw new InviladImapException('Invilad ImapServer From MailBox');
    }


    public function getMailBoxFromImapDirect()
    {
        if(!$this->imap->checkConnection()){
            return false; 
        }
        $mailbox = $this->listMailboxes();
        if(!$mailbox || !is_array($mailbox)){
            return array();
        }
        if(!$this->parent && $this->name == '*' && GlobalVar::get('imap_force_ns'))
        {
            $this->fixMailBoxByFromOtherNamespaces($mailbox);
        }
        if(GlobalVar::get('imap_skip_hidden_folders')){
            $mailbox = array_filter($mailbox, function($v) { return $v[0] != '.'; });
        }
        return $mailbox;
    }

    public function getSubscribedMailBoxFromImapDirect()
    {
        if(!$this->imap->checkConnection()){
            return false; 
        }
        $extended = !GlobalVar::get('imap_force_lsub') && $this->imap->getCapability('LIST-EXTENDED'); 
        if($extended){
            $result = $this->listMailboxes(false, null, array('SUBSCRIBED')); 
        }else{
            $result = $this->listMailboxes(true);
        }
        if(!is_array($result) && !$result){
            return array();
        }
        if(!$this->parent && $this->name == '*' && GlobalVar::get('imap_force_ns'))
        {
            $this->fixMailBoxByFromOtherNamespaces($result, ($extended ? 'ext-' : '') . 'subscribed');
        }
        if(GlobalVar::get('imap_skip_hidden_folders')){
            $result = array_filter($result, function($v) { return $v[0] != '.'; });
        }
        if ($extended) {
            // unsubscribe non-existent folders, remove from the list
            if ($this->name == '*' && GlobalVar::get('LIST')) {
                foreach ($result as $idx => $mbox) {
                    if (
                        ($opts = GlobalVar::get('LIST.' . $mbox))
                        && Helper::in_array_nocase('\\NonExistent', $opts)
                    ) {
                        $this->unsubscribeMailBox($mbox);
                        unset($result[$idx]);
                    }
                }
            }
        } else {
            // unsubscribe non-existent folders, remove them from the list
            if ($result && $this->name == '*') {
                $existing    = $this->all($format = false);
                $nonexisting = array_diff($result, $existing);
                $result      = array_diff($result, $nonexisting);

                foreach ($nonexisting as $mbox) {
                    $this->unsubscribeMailBox($mbox);
                }
            }
        } 
        return $result;
    }

    /**
     * IMAP LIST/LSUB command
     *
     * @param bool   $subscribed  Enables returning subscribed mailboxes only
     * @param array  $return_opts List of RETURN options (RFC5819: LIST-STATUS, RFC5258: LIST-EXTENDED)
     *                            Possible: MESSAGES, RECENT, UIDNEXT, UIDVALIDITY, UNSEEN,
     *                                      MYRIGHTS, SUBSCRIBED, CHILDREN
     * @param array  $select_opts List of selection options (RFC5258: LIST-EXTENDED)
     *                            Possible: SUBSCRIBED, RECURSIVEMATCH, REMOTE,
     *                                      SPECIAL-USE (RFC6154)
     *
     * @return array|bool List of mailboxes or hash of options if STATUS/MYROGHTS response
     *                    is requested, False on error.
     */
    public function listMailboxes($subscribed = false, $return_opts = array(), $select_opts = array())
    {
        $name = $this->name ? $this->name : '*';
        $args = array();
        $rets = array();
        $res  = array();

        $lstatus = false;
        if ($select_opts && $this->imap->getCapability('LIST-EXTENDED')) {
            $select_opts = (array)$select_opts;
            $args[] = '(' . implode(' ', $select_opts) . ')';
        }
        $args[] = Helper::escape($this->parent);
        $args[] = Helper::escape($name);

        if ($return_opts && $this->imap->getCapability('LIST-EXTENDED')) {
            $ext_opts    = array('SUBSCRIBED', 'CHILDREN');
            $rets        = array_intersect($return_opts, $ext_opts);
            $return_opts = array_diff($return_opts, $rets);
        }

        if ($return_opts && $this->imap->getCapability('LIST-STATUS')) {
            $lstatus     = true;
            $status_opts = array('MESSAGES', 'RECENT', 'UIDNEXT', 'UIDVALIDITY', 'UNSEEN');
            $opts        = array_diff($return_opts, $status_opts);
            $status_opts = array_diff($return_opts, $opts);
            if ($status_opts){
                $rets[] = 'STATUS (' . implode(' ', $status_opts) . ')';
            }
            if ($opts){
                $rets = array_merge($rets, $opts);
            }
        }

        if ($rets){
            $args[] = 'RETURN (' . implode(' ', $rets) . ')';
        }

        list($code, $response) = $this->imap->getConnection()->execute(
            $subscribed ? 'LSUB' : 'LIST'
            , $args
        );

        if ($code == Error::ERROR_OK) {
            $folders  = array();
            $last     = 0;
            $pos      = 0;
            $response .= "\r\n";

            while ($pos = strpos($response, "\r\n", $pos+1)) {
                // literal string, not real end-of-command-line
                if ($response[$pos-1] == '}') {
                    continue;
                }
                $line = substr($response, $last, $pos - $last);
                $last = $pos + 2;
                if (!preg_match('/^\* (LIST|LSUB|STATUS|MYRIGHTS) /i', $line, $m)) {
                    continue;
                }
                $cmd  = strtoupper($m[1]);
                $line = substr($line, strlen($m[0]));
                // * LIST (<options>) <delimiter> <mailbox>
                if ($cmd == 'LIST' || $cmd == 'LSUB') {
                    list($opts, $delim, $mailbox) = Helper::tokenizeResponse($line, 3);
                    $mailbox = $delim ? rtrim($mailbox, $delim) : $mailbox;
                    if(!$lstatus){
                        $res[] = $mailbox;
                    }else {
                        $res[$mailbox] = array();
                    }

                    // store folder options
                    if ($cmd == 'LIST') {
                        if(!GlobalVar::get('LIST.' . $mailbox)){
                            GlobalVar::set('LIST', array($mailbox => $opts));
                        }elseif(!$opts) {
                            GlobalVar::set('LIST', array(
                                $mailbox => array_unique(array_merge(
                                    GlobalVar::get('LIST.' . $mailbox, array()), $opts
                                ))  
                            ));
                        }
                    }
                }else if ($lstatus) {
                    // * STATUS <mailbox> (<result>)
                    if ($cmd == 'STATUS') {
                        list($mailbox, $status) = Helper::tokenizeResponse($line, 2);
                        for ($i = 0, $len = count($status); $i < $len; $i += 2) {
                            list($name, $value) = Helper::tokenizeResponse($status, 2);
                            $res[$mailbox][$name] = $value;
                        }
                    }else if ($cmd == 'MYRIGHTS') {
                        // * MYRIGHTS <mailbox> <acl>
                        list($mailbox, $acl)  = Helper::tokenizeResponse($line, 2);
                        $res[$mailbox]['MYRIGHTS'] = $acl;
                    }
                }
            }
        }
        return $res;
    }


    /**
     * Fix folders list by adding folders from other namespaces.
     * Needed on some servers eg. Courier IMAP
     *
     * @acces protected
     * @param array  $mailbox Reference to folders list
     * @param string $type   Listing type (ext-subscribed, subscribed or all)
     * @return void
     */

    protected function fixMailBoxByFromOtherNamespaces(&$mailbox, $type = null)
    {
        $namespace = $this->imap->getConnection()->getNamespace();
        $search    = array();

        // build list of namespace prefixes
        foreach ((array)$namespace as $ns) {
            if (is_array($ns)) {
                foreach ($ns as $ns_data) {
                    if (strlen($ns_data[0])) {
                        $search[] = $ns_data[0];
                    }
                }
            }
        }

        if (!empty($search)) {
            // go through all folders detecting namespace usage
            foreach ($mailbox as $folder) {
                foreach ($search as $idx => $prefix) {
                    if (strpos($folder, $prefix) === 0) {
                        unset($search[$idx]);
                    }
                }
                if (empty($search)) {
                    break;
                }
            }

            $oldName = $this->name;
            // get folders in hidden namespaces and add to the result
            foreach ($search as $prefix) {
                $this->setName($prefix . '*');
                switch($type){
                case 'ext-subscribed':
                    $list = $this->listMailboxes(false, null, array('SUBSCRIBED'));
                    break;

                case 'subscribed':
                    $list = $this->listMailboxes(true);
                    break;
                default:
                    $list  = $this->listMailboxes(); 
                }
                if (!empty($list)) {
                    $mailbox = array_merge($mailbox, $list);
                }
            }
            $this->setName($oldName);
        }
    }


    /**
     * Returns the namespace where the folder is in
     *
     * @param string $folder Folder name
     *
     * @return string One of 'personal', 'other' or 'shared'
     */
    public function mailBoxNamespace($mailbox = '')
    {
        $name = $mailbox ?: $this->name;
        if($name == 'INBOX'){
            return 'personal';
        }

        $namespaces = $this->imap->getConnection()->getNamespace();
        foreach ($namespaces as $type => $namespace) {
            if (is_array($namespace)) {
                foreach ($namespace as $ns) {
                    if ($len = strlen($ns[0])) {
                        if (($len > 1 && $name == substr($ns[0], 0, -1))
                            || strpos($name, $ns[0]) === 0
                        ) {
                            return $type;
                        }
                    }
                }
            }
        }

        return 'personal';
    }


    protected function deleteMailBox($mailBox)
    {
        $result = $this->imap->getConnection()->execute(
            'DELETE'
            , array(Helper::escape($mailBox))
            , Command::COMMAND_NORESPONSE);

        return $result == Error::ERROR_OK;
    }

    protected function unsubscribeMailBox($mailBox)
    {
        $result = $this->imap->getConnection()->execute(
            'UNSUBSCRIBE'
            , array(Helper::escape($mailBox))
            , Command::COMMAND_NORESPONSE);

        return $result == Error::ERROR_OK;
    }

    protected function subscribeMailBox($mailBox)
    {
        $result = $this->imap->getConnection()->execute(
            'SUBSCRIBE'
            , array(Helper::escape($mailBox))
            , Command::COMMAND_NORESPONSE);

        return $result == Error::ERROR_OK;
    }

    /**
     * Folder renaming (RENAME)
     *
     * @param string $mailbox Mailbox name
     *
     * @return bool True on success, False on error
     */
    public function renameMailBox($from, $to)
    {
        $result = $this->imap->getConnection()->execute(
            'RENAME'
            , array(Helper::escape($from), Helper::escape($to))
            , Command::COMMAND_NORESPONSE
        );

        return $result == Error::ERROR_OK;
    }

    protected function validName()
    {
        return $this->name && $this->name != '*';
    }
}
