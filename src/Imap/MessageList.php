<?php 
namespace Cooker\Mail\Imap;
use Cooker\Mail\Exception\MailBoxNotFoundException;
use Cooker\Mail\Exception\MailBoxNameNotFoundException;
use Cooker\Mail\GlobalVar;
use Cooker\Mail\Format;

class MessageList
{
    protected $mailBox  = null; 

    protected $pageSize = 20;

    protected $page     = 1;

    protected $sortField = null;
    protected $sortOrder = null;

    protected $search    = '';


    public function __construct(MailBox $mailBox = null)
    {
        $this->setMailBox($mailBox); 
    }


    public function all()
    {
        $this->getMailBox(); 
        $index = $this->_getMessageUid();
        if ($index->is_empty()) {
            return array();
        }
        $from = ($this->page - 1) * $this->pageSize;
        $to   = $from + $this->pageSize;

        $index->slice($from, $to - $from);
        // fetch reqested messages headers
        $allIndex = $index->get();
        $headers  = $this->fetchHeaders($allIndex);

        return Format::formatMessageList(array_values($headers), $this->mailBox->getName(), $this->mailBox->getImap()->delimiter);
    }

    /**
     * Fetches messages headers (by UID)
     *
     * @param  array   $msgs     Message UIDs
     * @param  bool    $force    Disables cache use
     *
     * @return array Messages headers indexed by UID
     */
    public function fetchHeaders($msgs, $sort = true, $force = false)
    {
        if (empty($msgs)) {
            return array();
        }
        $mailBoxName = $this->mailBox->getName();
        // fetch reqested headers from server
        $headers = $this
            ->mailBox
            ->getImap()
            ->getConnection()
            ->fetchHeaders(
                $mailBoxName, $msgs, true, false, $this->getFetchHeaders());

        if (empty($headers)) {
            return array();
        }
        $allHeaders = array();
        foreach ($headers as $h) {
            $h->mailBoxName = $mailBoxName;
            $allHeaders[$h->uid] = $h;
        }

        if ($sort) {
            $sorter = new HeaderSort();
            $sorter->set_index($msgs);
            $sorter->sort_headers($allHeaders);
        }
        return $allHeaders;
    }

    public function getFetchHeaders()
    {
        $headers = ($globalHeaders = GlobalVar::get('fetch_headers', false)) 
            ? explode(' ', $globalHeaders) 
            : array();

        return array_merge($headers, array(
            'IN-REPLY-TO',
            'BCC',
            'SENDER',
            'MESSAGE-ID',
            'CONTENT-TRANSFER-ENCODING',
            'REFERENCES',
            'X-DRAFT-INFO',
            'MAIL-FOLLOWUP-TO',
            'MAIL-REPLY-TO',
            'RETURN-PATH',
        ));
    }

    protected function _getMessageUid()
    {
        $query = GlobalVar::get('skip_deleted') ? 'UNDELETED' : ''; 
        if($this->search){
            $query = trim($query . ' UID ' . $this->search);  
        }
        if(!$this->sortField && !$this->sortOrder){
            $index = $this
                ->mailBox
                ->getImap()
                ->getConnection()
                ->search($this->mailBox->getName(), $query, true);
        }else{
            if ($this->mailBox->getImap()->getCapability('SORT')) {
                $index = $this
                    ->mailBox
                    ->getImap()
                    ->getConnection()
                    ->sort($this->mailBox->getName(), $this->sortField, $query, true);
            }

            if (empty($index) || $index->is_error()) {
                $index = $this
                    ->mailBox
                    ->getImap()
                    ->getConnection()
                    ->index(
                        $this->mailBox->getName()
                        , $this->search ?: "1:*"
                        , $this->sortField
                        , GlobalVar::get('skip_deleted') 
                        , $this->search ? true : false
                        , true
                    );
            }  
        }  
        if($this->sortOrder != $index->get_parameters('ORDER')) {
            $index->revert();
        }
        return $index;
    } 

    public function setPageSize($pageSize = 20)
    {
        $this->pageSize = (int)$pageSize; 
        return $this;
    }

    public function setPage($page = 1)
    {
        $this->page = (int)$page; 
        return $this;
    }

    public function setSortField($field)
    {
        $this->sortField = trim($field); 
        return $this;
    }


    public function setSortOrder($order = 'DESC')
    {
        $this->sortOrder = trim($order); 
        return $this;
    }

    public function setMailBox(MailBox $mailBox)
    {
        $this->mailBox = $mailBox; 
        return $this;
    }

    public function getMailBox()
    {
        if(!($this->mailBox instanceof MailBox)){
            throw new MailBoxNotFoundException('Message MailBox is not found');
        } 
        if(!$this->mailBox->validName()){
            throw new MailBoxNameNotFoundException('Message MailBox Name is not found');
        }
        return $this->mailBox;
    }


    public function setSearch($searchStr = '')
    {
        $this->search = $searchStr; 
    }





}
