<?php

namespace App\Admin\Controllers;

use App\Models\HostNames;
use App\Http\Controllers\Controller;
use Encore\Admin\Controllers\HasResourceActions;
use Encore\Admin\Form;
use Encore\Admin\Grid;
use Encore\Admin\Layout\Content;
use Encore\Admin\Show;

use function GuzzleHttp\Psr7\str;
use Illuminate\Support\MessageBag;
use Etcd\Client;
use Encore\Admin\Facades\Admin;
use Illuminate\Support\Facades\DB;


class HostNamesController extends Controller
{
    use HasResourceActions;

    /**
     * Index interface.
     *
     * @param Content $content
     * @return Content
     */
    public function index(Content $content)
    {
        return $content
            ->header('主机')
            ->description('列表')
            ->body($this->grid());
    }

    /**
     * Show interface.
     *
     * @param mixed $id
     * @param Content $content
     * @return Content
     */
    public function show($id, Content $content)
    {
        return $content
            ->header('主机')
            ->description('详细')
            ->body($this->detail($id));
    }

    /**
     * Edit interface.
     *
     * @param mixed $id
     * @param Content $content
     * @return Content
     */
    public function edit($id, Content $content)
    {
        return $content
            ->header('主机')
            ->description('编辑')
            ->body($this->form()->edit($id));
    }

    /**
     * Create interface.
     *
     * @param Content $content
     * @return Content
     */
    public function create(Content $content)
    {
        return $content
            ->header('主机')
            ->description('创建')
            ->body($this->form());
    }

    /**
     * Make a grid builder.
     *
     * @return Grid
     */
    protected function grid()
    {
        $grid = new Grid(new HostNames);
        $grid->tools(function ($tools) {
            $tools->batch(function ($batch) {
                $batch->disableDelete();
            });
        });

        //$grid->id('Id');
        //$grid->fromUserId('FromUserId');
        $grid->fromUserId('所属用户')->display(function ($id){
            $name = DB::table('admin_users')->where('id', $id)->value('name');
            return $name;
        });
        $grid->hostName('域名');
        $grid->ip('ip地址');
        $grid->port('端口');
        $grid->ip_send_proxy('ip透传')->display(function ($text) {
            if($text === 0){
                return "关闭";
            }else if($text === 1){
                return "开启";
            }
        });
        $grid->type('类型');
        $grid->cname('分配的cname');
        $grid->ssl_certificate('ssl证书')->display(function ($text){
            if(strlen($text) > 0){
                return "已上传";
            }else{
                return "";
            }
        });
        $grid->ssl_certificate_key('ssl证书密钥')->display(function ($text){
            if(strlen($text) > 0){
                return "已上传";
            }else{
                return "";
            }
        });

        //$grid->disableExport();

        // 仅查询当前用户条目
        if (!Admin::user()->isAdministrator()){
            $grid->model()->where('fromUserId', '=', Admin::user()->id);
        }

        return $grid;
    }

    /**
     * Make a show builder.
     *
     * @param mixed $id
     * @return Show
     */
    protected function detail($id)
    {
        // 非超级管理员和当前fromUserId，不可查看当前条目信息
        if (!Admin::user()->isAdministrator()){
            if (!((int)Admin::user()->id === (int)DB::table('hostNames')->where('id', $id)->value('fromUserId'))){
                die("非法访问");
            }
        }

        $show = new Show(HostNames::findOrFail($id));

        //$show->id('Id');
        $show->fromUserId('所属用户')->as(function ($id){
            $name = DB::table('admin_users')->where('id', $id)->value('name');
            return $name;
        });
        $show->hostName('域名');
        $show->ip('ip地址');
        $show->port('端口');
        $show->ip_send_proxy('ip透传')->as(function ($text) {
            if($text === 0){
                return "关闭";
            }else if($text === 1){
                return "开启";
            }
        });
        $show->type('类型');
        $show->cname('分配的cname');
        $show->ssl_certificate('ssl证书')->as(function ($text) {
            if(strlen($text) > 0){
                return "已上传";
            }else{
                return "无";
            }
        });
        $show->ssl_certificate_key('ssl证书密钥')->as(function ($text) {
            if(strlen($text) > 0){
                return "已上传";
            }else{
                return "无";
            }
        });


        return $show;
    }

    /**
     * Make a form builder.
     *
     * @return Form
     */
    protected function form()
    {
        // ------------------------  表单显示部分 -------------------------------

        // 非超级管理员和当前fromUserId，不可查看当前条目信息
        $page_id = isset(request()->route()->parameters()['hostName']) ? request()->route()->parameters()['hostName'] : null;
        if (!Admin::user()->isAdministrator()){
            if (!((int)Admin::user()->id === (int)DB::table('hostNames')->where('id', $page_id)->value('fromUserId')) && $page_id!=null ){
                die("非法访问");
            }
        }

        $form = new Form(new HostNames);

        if ($page_id == null){
            // create
            $form->text('hostName', '域名')->help("TCP/UDP无需输入域名");
            $form->select('type', '类型')->options(['TCP' => 'TCP', 'UDP' => 'UDP', 'HTTP' => 'HTTP'])->rules('required');
        }else {
            // update
            $form->text('hostName', '域名')->help("TCP/UDP无需输入域名")->readonly();
            $form->select('type', '类型')->options(['TCP' => 'TCP',
                #'UDP' => 'UDP',
                'HTTP' => 'HTTP'])->rules('required')->readonly();
        }
        $form->ip('ip', 'ip地址')->rules("required");
        //$form->text('cname', 'Cname');
        $form->text('port', '端口')->help("HTTP类型：请输入80，HTTPS请输入443并上传证书。（仅支持80,443端口）<br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;TCP/UDP类型：多个端口用英文逗号分割，可使用英文横线输入连续端口。")->rules('required');
        $states = [
            'on'  => ['value' => 1, 'text' => '打开', 'color' => 'success'],
            'off' => ['value' => 0, 'text' => '关闭', 'color' => 'danger'],
        ];
        $form->switch('ip_send_proxy', 'ip透传')->states($states)->help("TCP转发时可选择开启");
        $form->file('ssl_certificate', 'ssl证书')->help("非HTTPS无需上传")->move('ssl/')->uniqueName();
        $form->file('ssl_certificate_key', 'ssl证书密钥')->help("非HTTPS无需上传<br><br>点击提交后请耐心等待，不要关闭窗口")->move('ssl/')->uniqueName();
        // 通过表单不能修改cname，fromUserId和该条数据id
        $form->ignore(['cname', 'fromUserId', 'id']);

        // ------------------------  表单显示部分 end ----------------------------


        // ------------------------   保存前回调   ------------------------
        $form->saving(function (Form $form) {
            // 获取当前page id，用来做create update判断。
            $page_id = isset(request()->route()->parameters()['hostName']) ? request()->route()->parameters()['hostName'] : null;
            // 获取 primaryDomain
            $primaryDomain = DB::table('sysParameter')->where('parameterName', 'primaryDomain')->value('parameterValue');
            if ($page_id == null){
                // 如果为create
                $count = DB::table('hostNames')->where('fromUserId', Admin::user()->id)->count();
                // 添加fromUserId
                $form->model()->fromUserId = Admin::user()->id;
                $count = (string)((int)$count + 1);
                $username = Admin::user()->username;
                // 检查是否有重复
                if (DB::table('hostNames')->where('hostName', $form->hostName)->count() > 0 and $form->hostName != ''){
                    $error = new MessageBag([
                        'title'   => '错误',
                        'message' => '该域名已经添加，请勿重复添加',
                    ]);
                    return back()->with(compact('error'));
                }
                // HTTP必须输入域名
                if ($form->hostName == '' and $form->type === 'HTTP'){
                    $error = new MessageBag([
                        'title'   => '错误',
                        'message' => 'HTTP必须输入域名',
                    ]);
                    return back()->with(compact('error'));
                }
            }else{
                // 如果为update
                $count = DB::table('hostNames')->where('fromUserId', $form->model()->fromUserId)->count();
                $username = DB::table('admin_users')->where('id', $form->model()->fromUserId)->value('username');
            }

            // 拼接cname域名
                $this->cname = $username."-".$count.".".$primaryDomain;
                $sub_domain = $username."-".$count;
                while(DB::table('hostNames')->where('cname', $this->cname)->count() > 0){
                    // 如果cname重名
                    $count = (string)((int)$count + 1);
                    $this->cname = $username."-".$count.".".$primaryDomain;
                    $sub_domain = $username."-".$count;
                }

            // 赋值cname
                $form->model()->cname = $this->cname;

            // port 拆分
                $port_all = $this->split_port($form->port);

            // 输入合法检测
                // 检测端口输入是否合法
                foreach ($port_all as $v)
                {
                    if(!is_numeric($v) or strpos($v,'.') !== false)
                    {
                        $error = new MessageBag([
                            'title'   => '错误',
                            'message' => '端口输入存在非法字符',
                        ]);
                        return back()->with(compact('error'));
                    }
                }

                // HTTP仅限80/443
                if ($form->type === 'HTTP'){
                    foreach ($port_all as $port){
                        if ($port !== '80' and $port !== '443'){
                            $error = new MessageBag([
                                'title'   => '错误',
                                'message' => 'HTTP仅限80/443端口',
                            ]);
                            return back()->with(compact('error'));
                        }
                        if ($port === '443'){
                            if ($page_id == null and ($form->ssl_certificate_key == null or $form->ssl_certificate == null)){
                                // 443_create且未上传证书
                                $error = new MessageBag([
                                    'title'   => '错误',
                                    'message' => '您使用了443端口，但未上传证书',
                                ]);
                                return back()->with(compact('error'));
                            }elseif ($page_id != null and ( ($form->ssl_certificate_key == null and $form->ssl_certificate != null) or ($form->ssl_certificate_key != null and $form->ssl_certificate == null) )){
                                // 443_update且只更改一个文件
                                $error = new MessageBag([
                                    'title'   => '错误',
                                    'message' => '如果更改证书，请两个文件同时更改',
                                ]);
                                return back()->with(compact('error'));
                            }
                        }
                    }
                    $form->ip_send_proxy = null;
                }

                // TCP端口检查是否重复
                if ($form->type === 'TCP'){
                    $used_tcp_ports_obj= DB::table('transfer')->where('type', $username)->pluck('tcpPorts');
                    if (count($used_tcp_ports_obj) > 0){
                        $used_tcp_ports_string = $used_tcp_ports_obj[0];
                    }else {
                        $used_tcp_ports_string = '';
                    }

                    $used_tcp_ports = explode(',', $used_tcp_ports_string);
                    // update时排除当前条目端口
                    if ($page_id != null){
                        $current_id_used = DB::table('hostNames')->where('id', $page_id)->value('port');
                        $used_tcp_ports = array_diff($used_tcp_ports, explode(',', $current_id_used));
                    }
                    if (count($common = array_intersect($used_tcp_ports, $port_all)) > 0){
                        // 出现重复端口
                        $error = new MessageBag([
                            'title'   => '错误',
                            'message' => sprintf('%s端口已经使用', implode(",", $common)),
                        ]);
                        return back()->with(compact('error'));
                    }
                }

                // UDP端口检查是否重复
                if ($form->type === 'UDP'){
                    $used_udp_ports_obj= DB::table('transfer')->where('type', $username)->pluck('udpPorts');
                    if (count($used_udp_ports_obj) > 0){
                        $used_udp_ports_string = $used_udp_ports_obj[0];
                    }else {
                        $used_udp_ports_string = '';
                    }

                    $used_udp_ports = explode(',', $used_udp_ports_string);
                    // update时排除当前条目端口
                    if ($page_id != null){
                        $current_id_used = DB::table('hostNames')->where('id', $page_id)->value('port');
                        $used_udp_ports = array_diff($used_udp_ports, explode(',', $current_id_used));
                    }
                    if (count($common = array_intersect($used_udp_ports, $port_all)) > 0){
                        // 出现重复端口
                        $error = new MessageBag([
                            'title'   => '错误',
                            'message' => sprintf('%s端口已经使用', implode(",", $common)),
                        ]);
                        return back()->with(compact('error'));
                    }
                    $form->ip_send_proxy = null;
                }


            // dnspod构造参数，(实际调用在create_etcd/del_etcd中)
                $login_token = $etcdConf = DB::table('sysParameter')->where('parameterName', 'dnspod_login_token')->value('parameterValue');
                $domain_id = $etcdConf = DB::table('sysParameter')->where('parameterName', 'domain_id')->value('parameterValue');
                $format='json';
                $record_type='A';
                $record_line='默认';
                if($form->type === 'HTTP') {
                    $value = DB::table('transfer')->where([
                            ['type', 'HTTP'], ['runStatus', 1],
                        ])->value('ipAddress');
                    if ($value == null){
                        $value = '1.1.1.1';
                    }
                }elseif ($form->type === 'TCP'){
                    $value = '1.1.1.1';
                }elseif ($form->type === 'UDP'){
                    $value = '1.1.1.1';
                }else{
                    $error = new MessageBag([
                        'title'   => '失败',
                        'message' => '操作异常',
                    ]);
                    return back()->with(compact('error'));
                }
                $data = array('login_token' => $login_token, 'domain_id' => $domain_id, 'format' => $format, 'record_type' => $record_type, 'record_line' => $record_line, 'value' => $value, 'sub_domain' => $sub_domain);



            // etcd
                if ($page_id == null) {
                    // create
                    if (is_array($res = $this->create_etcd($form, $username, $port_all, $data))){
                        // 出错
                        $error = new MessageBag([
                            'title'   => $res[0],
                            'message' => $res[1],
                        ]);
                        return back()->with(compact('error'));
                    }
                }else {
                    // update
                    if (is_array($res = $this->del_etcd($form->hostName, $form->ip, $form->type, $username, $port_all, $login_token, $domain_id, $page_id)) and $res[0] === '错误'){
                        // 出错
                        $error = new MessageBag([
                            'title'   => $res[0],
                            'message' => $res[1],
                        ]);
                        return back()->with(compact('error'));
                    }
                    if (is_array($res = $this->create_etcd($form, $username, $port_all, $data, $res))){
                        // 出错
                        $error = new MessageBag([
                            'title'   => $res[0],
                            'message' => $res[1],
                        ]);
                        return back()->with(compact('error'));
                    }
                }


        });

        //  ------------------------ 保存前回调 end ------------------------


        // 保存后回调
        $form->saved(function (Form $form) {
            $success = new MessageBag([
                'title'   => '成功',
                'message' => '服务开启成功，请把域名cname解析到【'.$this->cname.'】 '.'<a href="/hostNames">返回列表</a>',
            ]);

            return back()->with(compact('success'));
        });


        // 删除前回调
        $form->deleting(function () {
            $page_id = isset(request()->route()->parameters()['hostName']) ? request()->route()->parameters()['hostName'] : null;

            $results = DB::table('hostNames')->where('id', $page_id);
            $hostName = $results->value("hostName");
            $ip = $results->value("ip");
            $type = $results->value("type");

            $port_all = $this->split_port($results->value("port"));
            $username = DB::table('admin_users')->where('id', $results->value("fromUserId"))->value('username');

            $login_token = $etcdConf = DB::table('sysParameter')->where('parameterName', 'dnspod_login_token')->value('parameterValue');
            $domain_id = $etcdConf = DB::table('sysParameter')->where('parameterName', 'domain_id')->value('parameterValue');

            if (is_array($res = $this->del_etcd($hostName, $ip, $type, $username, $port_all, $login_token, $domain_id, $page_id)) and $res[0] === '错误'){
                // 出错
                return response()->json([
                    'status'  => false,
                    'message' => $res[1],
                ]);
            }
        });


        // 删除后回调
        $form->deleted(function () {

        });

        return $form;
    }


    /**
     * 把port字符串拆分成array
     *
     * @return Port
     */
    protected function split_port($port){
        // port拆分
        $port_all = array();
        if(strpos($port,',') !== false) {
            $port = explode(",", $port);
            foreach ($port as $temp){
                if(strpos($temp,'-') !== false){
                    $ttemp = explode('-', $temp);
                    $start = $ttemp[0];
                    $end = $ttemp[1];
                    foreach (range($start, $end) as $ttemp){
                        if(strlen($ttemp) > 0){
                            array_push($port_all, $ttemp);
                        }
                    }
                }else{
                    if(strlen($temp) > 0){
                        array_push($port_all, $temp);
                    }
                }
            }
        }elseif (strpos($port,'-') !== false){
            $ttemp = explode('-', $port);
            $start = $ttemp[0];
            $end = $ttemp[1];
            foreach (range($start, $end) as $ttemp){
                if(strlen($ttemp) > 0){
                    array_push($port_all, $ttemp);
                }
            }
        }else {
            if(strlen($port) > 0){
                array_push($port_all, $port);
            }
        }

        return array_unique($port_all);
    }

    /**
     * etcd 创建过程
     *
     * @return null
     * 出错返回数组。
     */
    protected function create_etcd($form, $username, $port_all, $data, $del_callback_res=''){
        $hostName = $form->hostName;
        $ip = $form->ip;
        $type = $form->type;

        $etcdConf = DB::table('sysParameter')->where('parameterName', 'etcdConf')->value('parameterValue');
        $client = new \Etcd\Client($etcdConf);

        // 判断类型
        if($type == 'HTTP' and count($port_all) === 1 and $port_all[0] === '80'){
            // dnspod添加记录
            if (is_array($res = $this->create_dnspod($data))){
                return $res;
            }
            $client->put('/HTTP/'.$hostName, sprintf('{"HOST_NAME": "%s", "IP": ["%s"], "RECORD_ID": "%s"}', $hostName, $ip, $res));
        }elseif ($type == 'HTTP' and count($port_all) === 1 and $port_all[0] === '443'){
            // 如果证书新增或更改、传输https证书
            if ($form->ssl_certificate_key != null){
                $res = $this->send_ssl($form);
                if($res[0] === '错误'){
                    return $res;
                }
            }else {
                // 如果为update，接收来自del_etcd的ssl路径
                $res = $del_callback_res;
            }

            // dnspod添加记录
            if (is_array($res_dnspod = $this->create_dnspod($data))){
                return $res_dnspod;
            }
            $client->put('/HTTPS/'.$hostName, sprintf('{"HOST_NAME": "%s", "IP": ["%s"], "RECORD_ID": "%s", "SSL_CERTIFICATE_PATH": "%s", "SSL_CERTIFICATE_KEY_PATH": "%s"}', $hostName, $ip, $res_dnspod, $res[0], $res[1]));
        }elseif ($type == 'HTTP' and count($port_all) === 2){
            // 如果证书新增或更改、传输https证书
            if ($form->ssl_certificate_key != null){
                $res = $this->send_ssl($form);
                if($res[0] === '错误'){
                    return $res;
                }
            }else {
                // 如果为update，接收来自del_etcd的ssl路径
                $res = $del_callback_res;
            }

            // dnspod添加记录
            if (is_array($res_dnspod = $this->create_dnspod($data))){
                return $res_dnspod;
            }
            $client->put('/HTTP/'.$hostName, sprintf('{"HOST_NAME": "%s", "IP": ["%s"], "RECORD_ID": "%s"}', $hostName, $ip, $res_dnspod));
            $client->put('/HTTPS/'.$hostName, sprintf('{"HOST_NAME": "%s", "IP": ["%s"], "RECORD_ID": "%s", "SSL_CERTIFICATE_PATH": "%s", "SSL_CERTIFICATE_KEY_PATH": "%s"}', $hostName, $ip, $res_dnspod, $res[0], $res[1]));
        }elseif ($type == 'TCP'){
            $this->config_tcp_udp_confd('TCP', $username, $port_all);
            // dnspod添加记录
            if (is_array($res_dnspod = $this->create_dnspod($data))){
                return $res_dnspod;
            }
            // 端口数组转为string
            $port_all_string = implode("\",\"", $port_all);
            // 是否开启ip透传
            if ($form->ip_send_proxy === 'on'){
                $ip_send_proxy = 'send-proxy';
            }else {
                $ip_send_proxy = '';
            }
            $client->put('/TCP/'.$username.'/'.$ip, sprintf('{"IP": ["%s"], "RECORD_ID": "%s", "PORTS": ["%s"], "USERNAME": "%s", "IP_SEND_PROXY": "%s"}', $ip, $res_dnspod, $port_all_string, $username, $ip_send_proxy));
        }elseif ($type == 'UDP'){
            $this->config_tcp_udp_confd('UDP', $username, $port_all);
            // dnspod添加记录
            if (is_array($res_dnspod = $this->create_dnspod($data))){
                return $res_dnspod;
            }
            // 端口数组转为string
            $port_all_string = implode("\",\"", $port_all);
            $client->put('/UDP/'.$username.'/'.$ip, sprintf('{"IP": ["%s"], "RECORD_ID": "%s", "PORTS": ["%s"]}', $ip, $res_dnspod, $port_all_string));
        }

        return true;
    }



    /**
     * etcd 删除过程
     *
     * @return null
     * 出错返回数组。
     */
    protected function del_etcd($hostName, $ip, $type, $username, $port_all, $login_token, $domain_id, $page_id){
        $etcdConf = DB::table('sysParameter')->where('parameterName', 'etcdConf')->value('parameterValue');
        $client = new \Etcd\Client($etcdConf);

        // 判断类型
        if($type == 'HTTP' and count($port_all) === 1 and $port_all[0] === '80'){
            // dnspod删除记录
            $record_id = @json_decode($client->get('/HTTP/'.$hostName)['kvs'][0]['value'], 1);
            if (!is_array($record_id)) {
                return array('错误', '读取信息错误，请联系管理员');
            }
            $record_id = $record_id['RECORD_ID'];
            if (is_array($res = $this->del_dnspod($login_token, $domain_id, $record_id))){
                return $res;
            }
            $client->del('/HTTP/'.$hostName);
        }elseif ($type == 'HTTP' and count($port_all) === 1 and $port_all[0] === '443'){
            // dnspod删除记录
            $etcd_content = @json_decode($client->get('/HTTPS/'.$hostName)['kvs'][0]['value'], 1);
            if (!is_array($etcd_content)) {
                return array('错误', '读取信息错误，请联系管理员');
            }
            $record_id = $etcd_content['RECORD_ID'];
            if (is_array($res = $this->del_dnspod($login_token, $domain_id, $record_id))){
                return $res;
            }
            $client->del('/HTTPS/'.$hostName);
            // ssl_delete_callback
            return array($etcd_content['SSL_CERTIFICATE_PATH'], $etcd_content['SSL_CERTIFICATE_KEY_PATH']);
        }elseif ($type == 'HTTP' and count($port_all) === 2){
            $etcd_content = @json_decode($client->get('/HTTP/'.$hostName)['kvs'][0]['value'], 1);
            if (!is_array($etcd_content)) {
                return array('错误', '读取信息错误，请联系管理员');
            }
            $record_id = $etcd_content['RECORD_ID'];
            if (is_array($res = $this->del_dnspod($login_token, $domain_id, $record_id))){
                return $res;
            }
            $client->del('/HTTP/'.$hostName);
            $client->del('/HTTPS/'.$hostName);
            // ssl_delete_callback
            return array($etcd_content['SSL_CERTIFICATE_PATH'], $etcd_content['SSL_CERTIFICATE_KEY_PATH']);
        }elseif ($type == 'TCP'){
            $etcd_content = @json_decode($client->get('/TCP/'.$username.'/'.$ip)['kvs'][0]['value'], 1);
            if (!is_array($etcd_content)) {
                return array('错误', '读取信息错误，请联系管理员');
            }
            $record_id = $etcd_content['RECORD_ID'];
            if (is_array($res = $this->del_dnspod($login_token, $domain_id, $record_id))){
                return $res;
            }
            $del_ports = $etcd_content['PORTS'];
            $this->del_used_ports('TCP', $username, $del_ports);
            $client->del('/TCP/'.$username.'/'.$ip);
        }elseif ($type == 'UDP'){
            $etcd_content = @json_decode($client->get('/UDP/'.$username.'/'.$ip)['kvs'][0]['value'], 1);
            if (!is_array($etcd_content)) {
                return array('错误', '读取信息错误，请联系管理员');
            }
            $record_id = $etcd_content['RECORD_ID'];
            if (is_array($res = $this->del_dnspod($login_token, $domain_id, $record_id))){
                return $res;
            }
            $del_ports = $etcd_content['PORTS'];
            $this->del_used_ports('UDP', $username, $del_ports);
            $client->del('/UDP/'.$username.'/'.$ip);
        }

        return true;
    }



    /**
     * curl_post_date
     *
     * @return $result
     */
    protected function post_data($url, $data, $cookie='') {
        $ch = @curl_init();
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_POST, 1);
        curl_setopt($ch, CURLOPT_HEADER, 1);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, 0);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);
        curl_setopt($ch, CURLOPT_COOKIE, $cookie);
        curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($data));
        curl_setopt($ch, CURLOPT_USERAGENT, 'DNSPod API');
        $result = curl_exec($ch);
        curl_close($ch);

        return $result;
    }



    /**
     * dnspod创建记录
     *
     * @return $result
     * 出错返回数组。
     */
    protected function create_dnspod($data){
        $res = $this->post_data('https://dnsapi.cn/Record.Create', $data);
        $res = explode("\r\n\r\n", $res);
        $results = @json_decode($res[1], 1);

        if (!is_array($results)) {
            return array('错误', '域名解析错误，请联系管理员');
        }

        if ($results['status']['code'] != 1) {
            return array('错误', '错误id：'.$results['status']['code'].'，请联系管理员');
        }

        return $results['record']['id'];

    }



    /**
     * dnspod删除记录
     *
     * @return $result
     * 出错返回数组。
     */
    protected function del_dnspod($login_token, $domain_id, $record_id){
        $data = array('login_token' => $login_token, 'domain_id' => $domain_id, 'format' => 'json', 'record_id' => $record_id);
        $res = $this->post_data('https://dnsapi.cn/Record.Remove', $data);
        $res = explode("\r\n\r\n", $res);
        $results = @json_decode($res[1], 1);

        if (!is_array($results)) {
            return array('错误', '域名解析错误，请联系管理员');
        }

        if ($results['status']['code'] != 1) {
            return array('错误', '错误id：'.$results['status']['code'].'，请联系管理员');
        }

        return true;

    }



    /**
     * https证书 传输到中转机
     *
     * @return $result
     * 成功返回 $result[0]=ssl_certificate_path, $result[1]=ssl_certificate_key_path
     * 出错返回 $result[0] == '错误'
     */
    protected function send_ssl($form){
        $hostname = $form->hostName;
        // 获取表单文件
        $ssl_certificate = $form->ssl_certificate;
        $ssl_certificate_key = $form->ssl_certificate_key;
        // 获取文件后缀
        $ssl_certificate_ext = $ssl_certificate->getClientOriginalExtension();
        $ssl_certificate_key_ext = $ssl_certificate_key->getClientOriginalExtension();
        // 获取临时路径
        $ssl_certificate_temp_path = $ssl_certificate->getPathname();
        $ssl_certificate_key_temp_path = $ssl_certificate_key->getPathname();
        // 拼接目的路径
        $ssl_certificate_path = "/root/https/".$hostname."-cert.".$ssl_certificate_ext;
        $ssl_certificate_key_path = "/root/https/".$hostname."-cert_key.".$ssl_certificate_key_ext;
        $all_transfer_ip = DB::table('transfer')->where('type', 'HTTP')->pluck('ipAddress');

        foreach ($all_transfer_ip as $ip){
            $connection = ssh2_connect($ip, 22, array('hostkey'=>'ssh-rsa'));
            if (ssh2_auth_pubkey_file($connection, 'root', base_path('id_rsa.pub'), base_path('id_rsa'))){
                ssh2_scp_send($connection, $ssl_certificate_temp_path, $ssl_certificate_path, 0644);
                ssh2_scp_send($connection, $ssl_certificate_key_temp_path, $ssl_certificate_key_path, 0644);
            }else {
                return array('错误', '证书传输连接失败，请联系管理员');
            }
        }

        return array($ssl_certificate_path, $ssl_certificate_key_path);
    }



    /**
     * 配置中转机confd，同步tcp/udp指定用户名
     *
     * @return $result
     *
     * 出错返回 $result[0] == '错误'
     */
    protected function config_tcp_udp_confd($type, $username, $port_all){
        // 当前开通的个数
        $server_open_count = DB::table('admin_users')->where('username', $username)->value('serverCount');
        // 当前使用的个数
        $server_used_count = DB::table('transfer')->where('type', $username)->count();
        // 当前使用的端口
        if ($type === 'TCP'){
            if ($server_used_count > 0){
                $port_used_string = DB::table('transfer')->where('type', $username)->value('tcpPorts');
            }else {
                $port_used_string = '';
            }

        }elseif ($type === 'UDP'){
            if ($server_used_count > 0){
                $port_used_string = DB::table('transfer')->where('type', $username)->value('udpPorts');
            }else {
                $port_used_string = '';
            }
        }

        // 如果相同
        if ($server_open_count === $server_used_count){

        }elseif ($server_open_count > $server_used_count){
            // 加机器

            $difference = $server_open_count - $server_used_count;
            $all_transfer_ip_obj = DB::table('transfer')->where([
                ['type', 'FREE'], ['runStatus', 1]])->pluck('ipAddress');
            $all_transfer_ip_array = array();
            foreach ($all_transfer_ip_obj as $ip){
                array_push($all_transfer_ip_array, $ip);
            }
            $selected_ip = array_slice($all_transfer_ip_array, 0, $difference);

            foreach ($selected_ip as $ip){
                $connection = ssh2_connect($ip, 22, array('hostkey'=>'ssh-rsa'));
                if (ssh2_auth_pubkey_file($connection, 'root', base_path('id_rsa.pub'), base_path('id_rsa'))){
                    // 修改confd haproxy username
                    ssh2_exec($connection, sprintf("/bin/cp -rf /etc/confd/templates/haproxy.cfg.tmpl.example /etc/confd/templates/haproxy.cfg.tmpl && /bin/sed -i \"s/this_is_the_username/%s/g\" /etc/confd/templates/haproxy.cfg.tmpl", $username));
                    ssh2_exec($connection, sprintf("/bin/cp -rf /etc/confd/templates/nginx-udp.conf.tmpl.example /etc/confd/templates/nginx.conf.tmpl && /bin/sed -i \"s/this_is_the_username/%s/g\" /etc/confd/templates/nginx.conf.tmpl && pkill -f confd", $username));
                    // 修改type为当前用用户名
                    DB::table('transfer')->where('ipAddress', $ip)->update(['type' => $username]);
                }else {
                    return array('错误', '同步失败，请联系管理员');
                }
            }


        }elseif ($server_open_count < $server_used_count){
            // 减少机器

            $difference = $server_used_count - $server_open_count;
            $all_used_ip_obj = DB::table('transfer')->where('type', $username)->pluck('ipAddress');
            $all_used_ip_array = array();
            foreach ($all_used_ip_obj as $ip){
                array_push($all_used_ip_array, $ip);
            }
            $selected_ip = array_slice($all_used_ip_array, 0, $difference);

            foreach ($selected_ip as $ip){
                // 修改type为FREE
                DB::table('transfer')->where('ipAddress', $ip)->update(['type' => 'FREE', 'tcpPorts' => '', 'udpPorts' => '']);
            }

        }

        // 更新已使用的中转机端口
        if (strlen($port_used_string) > 0){
            $port_used_array = explode(',', $port_used_string);
        }else {
            $port_used_array = array();
        }
        if ($type === 'TCP'){
            $merge_port = array_unique(array_merge($port_used_array, $port_all));
            // 转为字符串，然后写入数据库
            $new_port_string = implode(',', $merge_port);
            DB::table('transfer')->where('type', $username)->update(['tcpPorts' => $new_port_string]);

        }elseif ($type === 'UDP'){
            $merge_port = array_unique(array_merge($port_used_array, $port_all));
            // 转为字符串，然后写入数据库
            $new_port_string = implode(',', $merge_port);
            DB::table('transfer')->where('type', $username)->update(['udpPorts' => $new_port_string]);
        }

        return true;
    }


    /**
     * 删除条目时，删除使用的端口
     *
     * @return $result
     *
     * 出错返回 $result[0] == '错误'
     */
    protected function del_used_ports($type, $username, $del_ports){
        if ($type === 'TCP'){
            $port_used_string = DB::table('transfer')->where('type', $username)->value('tcpPorts');
            $port_used_array = explode(',', $port_used_string);
            $diff_array = array_diff($port_used_array, $del_ports);
            $new_port_string = implode(',', $diff_array);
            DB::table('transfer')->where('type', $username)->update(['tcpPorts' => $new_port_string]);
        }elseif ($type === 'UDP'){
            $port_used_string = DB::table('transfer')->where('type', $username)->value('udpPorts');
            $port_used_array = explode(',', $port_used_string);
            $diff_array = array_diff($port_used_array, $del_ports);
            $new_port_string = implode(',', $diff_array);
            DB::table('transfer')->where('type', $username)->update(['udpPorts' => $new_port_string]);
        }
    }

}
