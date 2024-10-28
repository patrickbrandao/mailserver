<?php

    /*

        API para acionamento de envio de emails integrado ao PostfixAdmin

            - Requer execucao no mesmo servidor do Postfix+Mariadb+PostfixAdmin
            - Conecta-se na porta 25/SMTP em localhost sem TLS

        Caminho recomendado no HTTP/HTTPS:
            /mailapi/index.php

            Pasta para colocar os arquivos de template (.tpl):
            - Na mesma pasta do index.php, crie a pasta "templates"
            ./templates/

        Exemplo de arquivo template:
            ./templates/html-otp-pt-br.tpl
            #--------------------------------------------------------------------------
                Subject: Seu código de ativação %otp%
                Content-Type: text/html; charset=utf-8

                Oi %to_name%,

                Seu código de login temporário para acessar o site %site% é %otp%

                Por favor não responda este email.

                Se você recebeu este email por engano, por favor ignore este email.
                Se você não solicitou esse código manualmente no site %site% mas alguma
                pessoa pediu esse código, não informe o código a tal pessoal.
            #--------------------------------------------------------------------------


        Exemplo de envio de senha OTP usando MailAPI (shell-script em Linux):

            # Variaveis:

            # - URL da API:
            API="https://mail.intranet.br/mailapi/index.php"

            # - Destinatario:
            TO="Sr. Destino <destino@intranet.br>"

            # - Remetente
            FROM="Sr. Origem <no-reply@intranet.br>"

            # - Nome do template
            TEMPLATE="html-otp-pt-br"

            # - Codigo OTP a enviar (gerar randomicamente)
            OTP="123-456"

            # - Login da conta no postfixadmin
            #   (sera validado no postfixadmin via SQL e usado para autenticar SMTP)
            USER="no-reply@intranet.br"
            PASS="tulipa_mail2024"

            # - Acionando URL da API e enviando dados vitais (acima) e variaveis adicionais:
            curl -X POST "$API" \
                 -d "user=$USER" \
                 -d "pass=$PASS" \
                 \
                 -d "from=$FROM" \
                 -d "to=$TO" \
                 -d "template=$TEMPLATE" \
                 -d "otp=$OTP"

    */

    // Incluir modulos PEAR Mail
    require_once "Mail.php";

    // Funcoes
    function http_die($http_code, $output_error=''){
        $http = 'HTTP/1.1';
        switch($code){
            case 400: header($http . " ".$http_code." Bad Request\n"); break; 
            case 403: header($http . " ".$http_code." Forbidden\n"); break; 
            case 404: header($http . " ".$http_code." Not Found\n"); break; 
            case 405: header($http . " ".$http_code." Method Not Allowed\n"); break; 
            case 406: header($http . " ".$http_code." Not Acceptable\n"); break; 
            case 407: header($http . " ".$http_code." Unused\n"); break; 
            case 408: header($http . " ".$http_code." Request Timeout\n"); break; 
            case 409: header($http . " ".$http_code." Conflict\n"); break; 
            case 410: header($http . " ".$http_code." Gone\n"); break; 
            case 500: header($http . " ".$http_code." Internal Server Error\n"); break; 
            case 501: header($http . " ".$http_code." Not Implemented\n"); break; 
            case 502: header($http . " ".$http_code." Bad Gateway\n"); break; 
            case 503: header($http . " ".$http_code." Service Unavailable\n"); break; 
            case 504: header($http . " ".$http_code." Gateway Timeout\n"); break; 
            case 505: header($http . " ".$http_code." HTTP Version Not Supported\n"); break;
        }
        if($output_error!=''){
            header('X-Error: '.$output_error);
            echo $output_error,"\n";
        }
        exit();
    }

    // Obter variaveis de request (GET ou POST)
    // que estejam presentes num array modelo
    function &request_list($list){
        if(!is_array($_REQUEST)) return $list;
        foreach ($list as $vname=>$stdvle)
            if(array_key_exists($vname, $_REQUEST))
                $list[$vname] = is_int($stdvle) ? (int)$_REQUEST[$vname] : $_REQUEST[$vname];
            //-
        //-
        return $list;
    }
    // retornar todas as variaveis de envio
    function &request_getall(){
        $_r = $_REQUEST;
        return $_r;
    }
    // procurar variavel do servidor
    function &server($vname, $df=''){
        if(is_array($_SERVER) && array_key_exists($vname, $_SERVER)){
            $_r = &$_SERVER[$vname];
        }else{
            $_r = $df;
        }
        return $_r;
    }
    // filtro de strings sanatizadas de ataques oportunistas
    function str_bypass($input_str){
        $output_str = $input_str;

        // Caracteres permitidos
        $charlist = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ01234567890.-_@";

        // Contar caracteres permitidos na string,
        // se for igual o tamanho total da string significa que
        // apenas caracteres permitidos foram enviados
        $lpn = strspn($input_str, $charlist);
        $len = strlen($input_str);
        if($lpn == $len){
            // Enviou apenas caracteres permitidos
            return $input_str;
        }
        return '';
    }

    // - eregi php5 to php7/php8
    if(!function_exists('eregi')){
        function eregi($regex, $str){
            return preg_match("/".$regex."/i", $str);
        }
    }

    // verificar se um e-mail é sintaticamente correto
    function vlib_email($email){
        // formatos corretos
        if(strpos($email, '@')===false) return false;
        $checklist = array();
        $checklist[] = '^[a-z0-9]+[a-z0-9._-]*[a-z0-9]+@';
        $checklist[] = '.*@[0-9a-z-]+\\.[a-z0-9-]+';
        // formatos errados
        $errlist = array(
            0=> '^[0-9a-z_.-]+$', 1=> '@@', 2=> '@.*@', 3=> '\\.\\.', 4=> '\\.[0-9]+\\.',
            5=> '^[_.-]', 6=> '[_.-]$', 7=> '^@', 8=> '[._@-]$'
        );
        foreach($errlist as $k=>$v) if(@eregi($v, $email)) return false;
        foreach($checklist as $k=>$v) if(!@eregi($v, $email)) return false;
        return true;
    }

    // Ler contato de email
    // Entrada:
    //   xpto@intranet.br
    //   XPTO P <xpto@intranet.br>
    function &mail_contact_read($str){
        $str = trim($str);
        $contact = array(
            'name' => '',
            'email' => ''
        );
        // Localizar tag do email
        $p = strpos($str, '<');
        if($p!==false){
            $contact['name'] = trim(substr($str, 0, $p));
            $contact['email'] = str_bypass(trim(substr($str, $p), '<>'));
        }
        // Localizar email em partes
        if($contact['email']==''){
            $parts = explode(' ', $str);
            foreach($parts as $k=>$v) if(vlib_email($v)) $contact['email'] = $v;
        }
        return $contact;
    }

    // autenticar no postfixadmin
    // retorno:
    // 0 = ok
    // 1 = usuario/senha nao conferem
    // 2 = falta dados de acesso
    // 3 = erro de acesso ao banco de dados
    // 4 = falha na execucao de acesso SQL
    // 5 = registro nao encontrado
    function postfix_admin_auth($user, $pass){
        $stdno = 0;

        // Senha armazenada em MD5, converter senha
        // plana em hash md5
        $md5pass = md5($pass);

        // Incluir config do postfixadmin
        $dbcfg = '/etc/postfixadmin/dbconfig.inc.php';
        if(!is_file($dbcfg)){ $stdno = 2; return $stdno; }
        include $dbcfg;

        // Acessar banco de dados
        $conn = new mysqli($dbserver, $dbuser, $dbpass, $dbname);

        // Caso a conexao tenha falhado
        if ($conn->connect_error){ $stdno = 3; return $stdno; }

        // Buscar cadastro do email/conta ativa
        $sql = 'SELECT username AS user, password FROM mailbox WHERE username = ? AND active = 1';
        if ($stmt = $conn->prepare($sql)) {
            $stmt->bind_param('s', $user);
            $stmt->execute();
            $mailbox_user = '';
            $mailbox_password = '';
            $stmt->bind_result($mailbox_user, $mailbox_password);
            // Obter o resultado
            if ($stmt->fetch()) {
                // Encontrou o registro
                if(strtolower($user)==strtolower($mailbox_user)){
                    // usuario ok
                    if($md5pass==$mailbox_password){
                        // senha ok
                        $stdno = 0;
                    }else{
                        // senha nao confere ou o formato
                        // esta incompativel
                        $stdno = 1;
                    }
                }else{
                    // usuario difere em upper/lower-case
                    $stdno = 1;
                }
                // - conferir senha

                
            }else{
                // incapaz de encontrar o registro
                $stdno = 5;
            }
            $stmt->close();
        } else {
            // erro de preparacao de sql, ou erro de sintaxe
            $stdno = 4;
        }
        // Fechar database
        $conn->close();    

        return $stdno;
    }

    // // Encerrar com problemas de servicos internos
    // http_die(503, 'Database connect error');
    // exit();
    // http_die(403, 'Access denied-1');
    // http_die(400, 'Database prepare error');

    // Dados de entrada
    $vars = array(
        'user' => '',
        'pass' => '',
        'from' => '',
        'from_name' => '',
        'from_email' => '',
        'from_contact' => '',
        'to' => '',
        'to_name' => '',
        'to_email' => '',
        'to_contact' => '',
        'content-type' => 'text/plain; charset=UTF-8',
        'subject' => '',
        'message' => '',
        'template' => ''
    );
    // - todos os dados enviados
    $INPUTS =& request_getall();

    // - dados imperativos
    $DATA   =& request_list($vars);

    // - tratar dados imperativos
    $DATA['user'] = str_bypass($DATA['user']);
    $DATA['template'] = str_bypass($DATA['template']);

    // - tratar 'from' para separar nome do email do remetente
    if($DATA['from']!=''){
        $contact =& mail_contact_read($DATA['from']);
        if($contact['name']!=''  && $DATA['from_name']=='') $DATA['from_name'] = $contact['name'];
        if($contact['email']!='' && $DATA['from_email']=='') $DATA['from_email'] = $contact['email'];
        $DATA['from'] = $DATA['from_email'];
    }
    if(!vlib_email($DATA['from'])) http_die(400, 'Missed data: from');
    if(!vlib_email($DATA['from_email'])) $DATA['from_email'] = $DATA['from'];
    // Proibir uso de email invalido
    $DATA['from_email'] = str_bypass($DATA['from_email']);
    // Recompor contato
    $DATA['from_contact'] = ($DATA['from_name']=='' ? $DATA['from_email'] : $DATA['from_name'].' <'.$DATA['from_email'].'>');

    // - tratar 'to' para separar nome e email do destinatario
    if($DATA['to']!=''){
        $contact =& mail_contact_read($DATA['to']);
        if($contact['name']!=''  && $DATA['to_name']=='') $DATA['to_name'] = $contact['name'];
        if($contact['email']!='' && $DATA['to_email']=='') $DATA['to_email'] = $contact['email'];
        $DATA['to'] = $DATA['to_email'];
    }
    if(!vlib_email($DATA['to'])) http_die(400, 'Missed data: to');
    if(!vlib_email($DATA['to_email'])) $DATA['to_email'] = $DATA['to'];
    // Proibir uso de email invalido
    $DATA['to_email'] = str_bypass($DATA['to_email']);
    // Recompor contato
    $DATA['to_contact'] = ($DATA['to_name']=='' ? $DATA['to_email'] : $DATA['to_name'].' <'.$DATA['to_email'].'>');


    // Usuario padrao, mesmo do FROM
    if($DATA['user']=='') $DATA['user'] = $DATA['from_email'];


    // Devolver para array principal
    foreach($DATA as $k=>$v) $INPUTS[$k] = $v;
    $INPUTS['datebr'] = date('d/m/Y H:i:s');

    // Critica basica
    if($DATA['user']=='') http_die(400, 'Auth user missed');
    if($DATA['pass']=='') http_die(400, 'Auth pass missed');

    // Autenticacao no postfixadmin
    $auth_stdno = postfix_admin_auth($DATA['user'], $DATA['pass']);
    if($auth_stdno) http_die(403, 'Access denied');


    // Processamento de template
    $template = $DATA['template'];
    $tpl_header = '';
    $tpl_body = '';
    $tpl_conf = array();
    if($template!=''){
        // Pasta de templates na mesma pasta desse codigo PHP
        $local_pwd = dirname(server('SCRIPT_FILENAME'));
        $template_pwd = $local_pwd.'/templates';
        $template_file = $template_pwd.'/'.$template.'.tpl';
        if(!is_dir($template_pwd)) http_die(404, 'Template directory '.$template_pwd.' not found');
        if(!is_file($template_file)) http_die(404, 'Template file '.$template_file.' not found');
        $tpl_content = file_get_contents($template_file);

        // Separar opcoes de cabecalho de corpo baseado no primeiro \n\n
        $p = strpos($tpl_content, "\n\n");
        $tpl_header = trim(substr($tpl_content, 0, $p));
        $tpl_body = trim(substr($tpl_content, $p));
        if($tpl_body!='') $DATA['message'] = $tpl_body;

        // Processar cabecalho
        $tpl_conf = array();
        $tpl_header_lines = explode("\n", $tpl_header);
        foreach($tpl_header_lines as $k=>$v){
            $v = trim($v);
            $p = strpos($v, ':');
            if($p===false) continue;
            $key = substr($v, 0, $p);
            $vle = trim(substr($v, $p+1));
            $lkey = strtolower($key);
            if(isset($DATA[$lkey])){
                $DATA[$lkey] = $vle;
                continue;
            }
            $tpl_conf[$key] = $vle;
        }
    }
    $DATA['tpl_conf'] = $tpl_conf;
    $DATA['tpl_header'] = $tpl_header;
    $DATA['tpl_body'] = $tpl_body;


    // Ajustar mensagem com variaveis
    $message = $DATA['message'];
    $subject = $DATA['subject'];
    $DATA['vars'] = array();
    foreach($INPUTS as $vname=>$vstr){
        $vkey = '%'.$vname.'%';
        if($vname=='subject'||$vname=='message') continue;
        $DATA['vars'][$vkey] = $vstr;
        $subject = str_replace($vkey, $vstr, $subject);
        $message = str_replace($vkey, $vstr, $message);
    }


    // Atualizar array de dados
    $DATA['subject'] = $subject;
    $DATA['message'] = $message;


    // - Cabecalho do email
    $DATA['smtp_headers'] = array(
        'From' => $DATA['from_contact'],
        'To' => $DATA['to_contact'],
        'Subject' => $DATA['subject'],
        'MIME-Version' => '1.0',
        'Content-type' => $DATA['content-type']
    );

    // - Acesso SMTP
    $DATA['smtp_config'] = array(
        'host' => '127.0.0.1',
        //'port' => 587,
        'port' => 25,
        'auth' => true,
        'secure' => false,
        'username' => $DATA['user'],
        'password' => $DATA['pass'],
        'timeout' => 3,
        'socket_options' => array(
            'ssl' => array(
                'verify_peer' => false,
                'verify_peer_name' => false,
                'allow_self_signed' => true,
            )
        )
    );

    // Debug, nao enviar
    if($INPUTS['debug']=='yes'){
         print_r($DATA);
         exit();
    }

    // Criar objeto
    $XSMTP = Mail::factory('smtp', $DATA['smtp_config']);

    // Enviando o e-mail
    $xmail_ret = $XSMTP->send($DATA['to_email'], $DATA['smtp_headers'], $DATA['message']);
    if (PEAR::isError($xmail_ret)) {
        http_die(502, 'Sendmail error');
    } else {
        echo "OK";
    }

    exit();


?>
