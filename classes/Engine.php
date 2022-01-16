<?php 
use \Firebase\JWT\JWT;
use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;
class Engine{

    public static $ck = 'J~iZ6acNvO8CnE9XlbGwMLj2ehro#PmxRzd?Dp%4QJSX{zsnX6~yMWM9rqz8QCzVV%BLr3Gl}R2wXIktWs85*Kpj5jR496AzUQY6q~H{ejboCI1Wr~sviIPc75eGZKs3A|sQ#L4cXpC}iq69VMydK{@2GBz%rO~JeYEvFDxbn6q~jtK5|#RxWbwS3quz23A%j|8rR2Azo}#WhV$kpUJyPfnI*3ca9imtXDSZu@lBvxhQbSjPx54{uDp?T783R2Ok';

    public static function checkToken($token) {
        try{
            JWT::decode($token, Engine::$ck, array('HS256'));
        }catch(DomainException | Exception $e) {
            throw $e;
        }
    }

    public static function getUserId($token) {
        try {
            $data = JWT::decode($token, Engine::$ck, array('HS256'));
            return $data->userId;
        }catch(DomainException | Exception $e) {
            return false;
        }
    }

    public static function checkAuth($token){

        try{
            if(isset($token)) $userInfo = Engine::checkToken($token);
            else return false;
        }
        catch (DomainException | Exception $e ){
            return false;
        }

        return true;

    }

    public static function isAdmin($token) {
        try{
            $token_info = JWT::decode($token, Engine::$ck, array('HS256'));
            if ($token_info->status == 1) {
                return true;
            }

        }catch(DomainException | Exception $e) {
            
        }
        return false;
    }

    public static function removeDirectory($dir) {
        if ($objs = glob($dir."/*")) {
            foreach($objs as $obj) {
                is_dir($obj) ? Engine::removeDirectory($obj) : unlink($obj);
            }
        }
        rmdir($dir);
    }

    public static function rus2translit($string) {
        $converter = array(
            'а' => 'a',   'б' => 'b',   'в' => 'v',
            'г' => 'g',   'д' => 'd',   'е' => 'e',
            'ё' => 'e',   'ж' => 'zh',  'з' => 'z',
            'и' => 'i',   'й' => 'y',   'к' => 'k',
            'л' => 'l',   'м' => 'm',   'н' => 'n',
            'о' => 'o',   'п' => 'p',   'р' => 'r',
            'с' => 's',   'т' => 't',   'у' => 'u',
            'ф' => 'f',   'х' => 'h',   'ц' => 'c',
            'ч' => 'ch',  'ш' => 'sh',  'щ' => 'sch',
            'ь' => '',  'ы' => 'y',   'ъ' => '',
            'э' => 'e',   'ю' => 'yu',  'я' => 'ya',
            
            'А' => 'A',   'Б' => 'B',   'В' => 'V',
            'Г' => 'G',   'Д' => 'D',   'Е' => 'E',
            'Ё' => 'E',   'Ж' => 'Zh',  'З' => 'Z',
            'И' => 'I',   'Й' => 'Y',   'К' => 'K',
            'Л' => 'L',   'М' => 'M',   'Н' => 'N',
            'О' => 'O',   'П' => 'P',   'Р' => 'R',
            'С' => 'S',   'Т' => 'T',   'У' => 'U',
            'Ф' => 'F',   'Х' => 'H',   'Ц' => 'C',
            'Ч' => 'Ch',  'Ш' => 'Sh',  'Щ' => 'Sch',
            'Ь' => '',  'Ы' => 'Y',   'Ъ' => '',
            'Э' => 'E',   'Ю' => 'Yu',  'Я' => 'Ya', ' ' => '_'
        );
        return strtr($string, $converter);
    }

    public static function generate_code($number) {
        $arr = array('a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z','1','2','3','4','5','6','7','8','9','0');
        $pass = "";
        for($i=0;$i<$number;$i++) {
          $index = rand(0, count($arr) - ($i==0?11:1));
          $pass .= $arr[$index];
        }
        return $pass;
    }

    public static function sendMail($mailTo, $subject, $body) {
        $mail = new PHPMailer;
            $mail->CharSet = 'UTF-8';
            
            // Настройки SMTP
            $mail->isSMTP();
            $mail->SMTPAuth = true;
            $mail->SMTPDebug = 0;
            
            $mail->Host = 'ssl://smtp.yandex.ru';
            $mail->Port = 465;
            $mail->Username = 'service@gotdoc.ru';
            $mail->Password = 'ZM2ZbLi6OgQhyz9YcjLt';
            
            // От кого
            $mail->setFrom('service@gotdoc.ru', 'Сервис "Готовые документы"');		
            
            // Кому
            $mail->addAddress($mailTo["email"], $mailTo["name"]);
            
            // Тема письма
            $mail->Subject = $subject;
            
            // Тело письма
            $body = $body;
            $mail->msgHTML($body);
            
            $mail->send();
    }

    public static function encrypt($decrypted, $password, $salt) { 
        $key = hash('SHA256', $salt . $password, true);
        srand();
        $iv = substr(md5(uniqid()), 16);
        $iv_base64 = rtrim(base64_encode($iv), '=');
        $encrypted = rtrim(openssl_encrypt($decrypted . md5($decrypted), 'AES-256-CTR', $key, false, $iv),'=');
        return $iv_base64 . $encrypted;
    }

    public static function decrypt($encrypted, $password, $salt) {
        $key = hash('SHA256', $salt . $password, true);
        $iv = base64_decode(substr($encrypted, 0, 22) . '==');
        $encrypted = substr($encrypted, 22);
        $decrypted = openssl_decrypt($encrypted, 'AES-256-CTR', $key, false, $iv);
        $hash = substr($decrypted, -32);
        $decrypted = substr($decrypted, 0, -32);
        if (md5($decrypted) != $hash) return false;
        return $decrypted;
    }

    public static function file_force_download($file) {
        if (file_exists($file)) {
            // сбрасываем буфер вывода PHP, чтобы избежать переполнения памяти выделенной под скрипт
            // если этого не сделать файл будет читаться в память полностью!
            if (ob_get_level()) {
                ob_end_clean();
            }
            header('Content-Description: File Transfer');
            header('Access-Control-Allow-Origin: *');
            header('Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS');
            header('Access-Control-Allow-Headers: Content-Type, Authorization, authorization, Content-Disposition, Content-Transfer-Encoding');
            header('Access-Control-Allow-Credentials: true');
            // заставляем браузер показать окно сохранения файла
            header('Content-Type: application/octet-stream');
            header('Content-Disposition: attachment; filename=' . basename($file));
            header('Content-Transfer-Encoding: binary');
            header('Expires: 0');
            header('Cache-Control: must-revalidate');
            header('Pragma: public');
            header('Content-Length: ' . filesize($file));
            // читаем файл и отправляем его пользователю
            readfile($file);
        }
    }

}

?>