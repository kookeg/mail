<?php 
namespace Cooker\Mail;

use Cooker\Mail\Imap\Connection;
use Cooker\Mail\Exception\ImapException;
use Cooker\Mail\Imap\MailBox;

class Imap 
{

    protected $host = null;

    protected $port = 25;

    protected $user = null;

    protected $pass = null;

    protected $ssl  = false;

    protected $conn = null;

    protected $options   = array();

    public    $delimiter = null;

    public    $namespace = array();

    protected $sort_folder_collator = null;

    public function __construct($host, $port, $ssl = false)
    {
        $this->host = $host;
        $this->port = $port;
        $this->ssl  = (bool)$ssl;
    }


    public function connect($user, $password, $options = array())
    {
        $this->checkConnectParams($user, $password);
        if($this->ssl){
            $this->checkEnvironment();
        }
        $this->connInit();
        $options = array_merge($options, array(
            'ssl' => $this->ssl,
        )); 

        $attempt = 3;
        do{
            $this->conn->connect($this->host, $this->port, $user, $password, $options);     
            $attempt--;
        }while(!$this->conn->connected() && $attempt);

        if($this->conn->connected()){
            GlobalVar::set('conn', $this->conn);
            $this->setDelimiterAndNamespace();
        }else{
            return false;  
        }
        return true;
    }

    protected function checkConnectParams($user, $password)
    {
        if($user && $password && $this->host && $this->port)
        {
            $this->user = $user; 
            $this->pass = $password;
            return true;
        }
        throw new ImapException('Imap connect params are not enough');
    }

    protected function connInit()
    {
        return $this->conn = new Connection(); 
    }

    protected function checkEnvironment()
    {
        if(!extension_loaded('openssl')){
            throw new ImapException('Imap ssl mode openssl must be available'); 
        } 
        return true;
    }

    protected function setDelimiterAndNamespace()
    {

        if(empty($this->namespace)  && !$this->delimiter){
            $personal = GlobalVar::get('imap_ns_personal', null); 
            $shared   = GlobalVar::get('imap_ns_shared'  , null);
            $other    = GlobalVar::get('imap_ns_other'   , null);
            if(!$this->checkConnection()){
                return;
            }
            $namespace = $this->conn->getNameSpace(); 
            if(is_array($namespace) && $namespace){
                $this->namespace = $namespace;
            }else{
                $this->namespace = array(
                    'personal' => null, 
                    'other'    => null,
                    'shared'   => null,
                );    
            }
            $this->delimiter = GlobalVar::get('imap_delimiter');
            if (!$this->delimiter && isset($this->namespace['personal'][0][1])) {
                $this->delimiter = $this->namespace['personal'][0][1];
            }
            if(!$this->delimiter){
                $this->delimiter = $this->conn->getHierarchyDelimiter();        
            }
            if(!$this->delimiter){
                $this->delimiter = '/'; 
            }
            if(!is_null($personal)){
                $this->namespace['personal'] = null; 
                foreach((array)$personal as $ns){
                    array_push($this->namespace['personal'], array($ns, $this->delimiter)); 
                }
            }
            if(!is_null($shared)){
                $this->namespace['shared'] = null; 
                foreach((array)$shared as $ns){
                    array_push($this->namespace['shared'], array($ns, $this->delimiter)); 
                }
            }
            if(!is_null($other)){
                $this->namespace['other'] = null; 
                foreach((array)$other as $ns){
                    array_push($this->namespace['other'], array($ns, $this->delimiter)); 
                }
            }
        } 
        GlobalVar::set('imap_namespace', $this->namespace);
        GlobalVar::set('imap_delimiter', $this->delimiter);
    }

    public function checkConnection()
    {
        return $this->conn->connected();
    }

    public function modifyNameAccordingPersonalNSPrefix($folder, $mode = 'out')
    {
        $prefix = $this->namespace['prefix_' . $mode]; 
        if(!$prefix){
            return $folder;
        }
        if($mode == 'out'){
            if(substr($folder, 0, strlen($prefix)) === $prefix){
                return substr($folder, strlen($prefix)); 
            } 
            return $folder;
        }
        return $prefix.$folder;
    }


    public function getConnection()
    {
        return $this->conn;
    }

    public function getCapability($capability)
    {
        $key = 'CAP_' . strtoupper($capability);
        if(!GlobalVar::get($key)){
            if(!$this->checkConnection()){
                return false;
            }      
            if($capability == 'X-DUAL-USE-FOLDERS'){
                $capability = $this->detectDualUseMailBox();
            }else{
                $capability = $this->conn->getCapability($capability); 
            }
            GlobalVar::set($key, $capability);
        }
        return $capability;
    }

    protected function detectDualUseMailBox()
    {
        if(!is_null($val = GlobalVar::get('imap_dual_use_folder'))){
            return (bool)$val; 
        }  
        if(!$this->checkConnection()){
            return false;
        }
        $created    = false;
        $name       = str_replace('.', '', 'mailboxtest'.microtime(true));
        $name       = $this->modifyNameAccordingPersonalNSPrefix($name, 'in');
        $subName    = $name. $this->delimiter . 'foldertest';
        $mailbox = new MailBox($this);
        if($mailbox->setName($name)->setDetectParent(false)->create()){
            $subMailBox = clone $mailbox;
            $created    = $subMailBox->setName($subName)->setDetectParent(false)->create();
        } 
        return $created;
    }

    /**
     * Filter the given list of folders according to access rights
     *
     * For performance reasons we assume user has full rights
     * on all personal folders.
     */

    public function filterRights($mailboxes, $rights)
    {
        $regex = '/('.$rights.')/';
        $object = new MailBox($this);
        foreach ($mailboxes as $idx => $name) {
            if ($object->mailBoxNamespace($name) == 'personal') {
                continue;
            }
            $myrights = join('', (array)$this->myRights($name));
            if ($myrights !== null && !preg_match($regex, $myrights)) {
                unset($mailboxes[$idx]);
            }
        }
        return $mailboxes;
    }


    /**
     * Returns the set of rights that the current user has to
     * folder (MYRIGHTS)
     *
     * @param string $name MailBox name
     * @return array MYRIGHTS response on success, NULL on error
     */

    public function myRights($name)
    {
        if (!$this->getCapability('ACL')) {
            return null;
        }

        if (!$this->checkConnection()) {
            return null;
        }
        return $this->conn->myRights($name);
    }

    /**
     * Sort Mailbox first by default folders and then in alphabethical order
     *
     * @param array $a_folders    Mailbox list
     * @param bool  $skip_default Skip default mailboxs handling
     *
     * @return array Sorted list
     */

    public function sortMailBoxlist($mailboxes, $skip_default = false)
    {
        $specials  = array_merge(array('INBOX'), array_values($this->getSpecialMailBox()));
        $res       = array();

        // convert names to UTF-8
        foreach ($mailboxes as $mailbox) {
            $res[$mailbox] = strpos($mailbox, '&') === false ? $mailbox : Charset::convert($mailbox, 'UTF7-IMAP');
        }

        uasort($res, array($this, 'sortMailboxComparator'));

        $res = array_keys($res);
        if ($skip_default) {
            return $res;
        }

        // force the type of folder name variable (#1485527)
        $res = array_map('strval', $res);
        $out = array();

        // finally we must put special folders on top and rebuild the list
        // to move their subfolders where they belong...
        $specials = array_unique(array_intersect($specials, $res));
        $res      = array_merge($specials, array_diff($res, $specials));

        $this->sortMailboxSpecials(null, $res, $specials, $out);

        return $out;
    }

    /**
     * Recursive function to put subfolders of special folders in place
     */
    protected function sortMailboxSpecials($mailbox, &$list, &$specials, &$out)
    {
        foreach ($list as $key => $name) {
            if ($mailbox === null || strpos($name, $mailbox.$this->delimiter) === 0) {
                $out[] = $name;
                unset($list[$key]);

                if (!empty($specials) && ($found = array_search($name, $specials)) !== false) {
                    unset($specials[$found]);
                    $this->sortMailboxSpecials($name, $list, $specials, $out);
                }
            }
        }

        reset($list);
    }


    /**
     * Detect special folder associations stored in storage backend
     */
    public function getSpecialMailBox($forced = false)
    {

        $result = array();
        $types  = array('drafts', 'sent', 'junk', 'trash');
        if(!($result = GlobalVar::get('special-mailbox', array()))){
            foreach($types as $type){
                if($name = GlobalVar::get($type . '_mbox')){
                    $result[$type] = $name; 
                } 
            } 
            GlobalVar::set('special-mailbox', $result);
        }

        if(GlobalVar::get('imap_lock_special_folders')){
            return $result; 
        }

        if ($used = GlobalVar::get('special-use')){
            return array_merge($result, $used);
        }

        if (!$forced || !$this->getCapability('SPECIAL-USE')) {
            return $result;
        }

        if (!$this->checkConnection()) {
            return $result;
        }

        $types = array_map(
            function($value) {
                return "\\" . ucfirst($value); 
            }
        , $types 
        );
        $special = array();

        // request \Subscribed flag in LIST response as performance improvement for folder_exists()
        $mailbox   = new MailBox($this);
        $mailboxes = $mailbox->setName('*')->listMailboxes(
            false
            , array('SUBSCRIBED')
            , array('SPECIAL-USE')
        );

        if (!empty($mailboxes)) {
            foreach ($mailboxes as $name) {
                if ($flags = GlobalVar::get('LIST.' . $name)) {
                    foreach ($types as $type) {
                        if (in_array($type, $flags)) {
                            $type           = strtolower(substr($type, 1));
                            $special[$type] = $name;
                        }
                    }
                }
            }
        }
        GlobalVar::set('special-use', $special);
        GlobalVar::remove('special-mailbox');
        return array_merge($result, $special);
    }

    /**
     * Callback for uasort() that implements correct
     * locale-aware case-sensitive sorting
     */
    protected function sortMailboxComparator($str1, $str2)
    {
        if (is_null($this->sort_folder_collator)) {
            $this->sort_folder_collator = false;
            if (stripos(PHP_OS, 'win') === 0 && function_exists('collator_compare')) {
                $locale = GlobalVar::get('language', 'zh_CN');
                $this->sort_folder_collator = collator_create($locale) ?: false;
            }
        }
        $path1 = explode($this->delimiter, $str1);
        $path2 = explode($this->delimiter, $str2);
        foreach ($path1 as $idx => $mbox1) {
            $mbox2 = $path2[$idx];
            if ($mbox1 === $mbox2) {
                continue;
            }
            if ($this->sort_folder_collator) {
                return collator_compare($this->sort_folder_collator, $mbox1, $mbox2);
            }
            return strcoll($mbox1, $mbox2);
        }
    }
}
