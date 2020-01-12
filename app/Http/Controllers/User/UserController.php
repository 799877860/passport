<?php

namespace App\Http\Controllers\User;

use App\Http\Controllers\Controller;
use App\Model\UserModel;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Redis;

class UserController extends Controller
{
    /**
     * 用户注册
     */
    public function reg(Request $request)
    {
        // echo "<pre>";print_r($_POST);echo "</pre>";
        $pass1 = $request->input('pass1');
        $pass2 = $request->input('pass2');

        // 验证两次输入的密码是否一致
        if ($pass1 != $pass2) {
            echo "两次密码输入不一致";
            die;
        }

        $name   = $request->input('name');
        $email  = $request->input('email');
        $mobile = $request->input('mobile');
        // 验证是否注册
        $u = UserModel::where(['name' => $name])->first();
        //验证name
        if ($u) {
            $response = [
                'err_num' => 8002,
                'err_msg' => "用户名已存在"
            ];
            die(json_encode($response, JSON_UNESCAPED_UNICODE));
        }

        //验证email
        $u = UserModel::where(['email' => $email])->first();
        if ($u) {
            $response = [
                'err_num' => 8003,
                'err_msg' => "Email已存在"
            ];
            die(json_encode($response, JSON_UNESCAPED_UNICODE));
        }

        //验证mobile
        $u = UserModel::where(['mobile' => $mobile])->first();
        if ($u) {
            $response = [
                'err_num' => 8005,
                'err_msg' => "电话号已存在"
            ];
            die(json_encode($response, JSON_UNESCAPED_UNICODE));
        }

        //生成密码
        $password = password_hash($pass1, PASSWORD_BCRYPT);

        //入库
        $user_info = [
            'email'    => $email,
            'name'     => $name,
            'mobile'   => $mobile,
            'password' => $password
        ];
        $uid       = UserModel::insertGetId($user_info);
        if ($uid) {
            $response = [
                'err_num' => 8000,
                'err_msg' => "注册成功"
            ];
        } else {
            $response = [
                'err_num' => 8001,
                'err_msg' => "服务器内部错误,请稍后再试"
            ];
        }
        die(json_encode($response));
    }

    /**
     * 用户登录
     */
    public function login(Request $request)
    {
        // echo '<pre>';print_r($_POST);echo '</pre>';
        $value = $request->input('name');
        $pass  = $request->input('pass');
        // 按name找记录
        $u1 = UserModel::where(['name' => $value])->first();
        $u2 = UserModel::where(['email' => $value])->first();
        $u3 = UserModel::where(['mobile' => $value])->first();

        if ($u1 == NULL && $u2 == NULL && $u3 == NULL) {
            $response = [
                'err_num' => 7001,
                'err_msg' => "用户不存在"
            ];
            return $response;
        }

        // 使用用户名登录
        if ($u1) {
            if (password_verify($pass, $u1->password)) {
                $uid = $u1->id;
            } else {
                $response = [
                    'err_num' => 7002,
                    'err_msg' => '密码错误'
                ];
                return $response;
            }
        }
        //使用 email 登录
        if ($u2) {
            if (password_verify($pass, $u2->password)) {
                $uid = $u2->id;
            } else {
                $response = [
                    'err_num' => 7002,
                    'err_msg' => '密码错误'
                ];
                return $response;
            }
        }
        // 使用电话号登录
        if ($u3) {
            if (password_verify($pass, $u3->password)) {
                $uid = $u3->id;
            } else {
                $response = [
                    'err_num' => 7002,
                    'err_msg' => '密码错误'
                ];
                return $response;
            }
        }
        $token           = $this->getToken($uid);      //生成token
        $redis_token_key = 'str:user:token:' . $uid;
        //echo $redis_token_key;
        Redis::set($redis_token_key, $token, 86400);  // 生成token  设置过期时间

        $response = [
            'err_num' => 7000,
            'err_msg' => '登录成功',
            'data'    => [
                'uid'   => $uid,
                'token' => $token
            ]
        ];
        return $response;
    }

    /**
     * 生成用户token
     * @param $uid
     * @return false|string
     */
    protected function getToken($uid)
    {
        $token = md5(time() . mt_rand(11111, 99999) . $uid);
        return substr($token, 5, 20);
    }

    /**
     * 获取用户信息接口
     */
    public function userInfo()
    {
        if (empty($_SERVER['HTTP_TOKEN']) || empty($_SERVER['HTTP_UID'])) {
            $response = [
                'err_num' => 6003,
                'err_msg' => 'Token Not Valid!'
            ];
            return $response;
        }

        //获取客户端的 token
        $token           = $_SERVER['HTTP_TOKEN'];
        $uid             = $_SERVER['HTTP_UID'];
        $redis_token_key = 'str:user:token:' . $uid;
        //验证token是否有效
        $cache_token = Redis::get($redis_token_key);
        if ($token == $cache_token)        // token 有效
        {
            $data     = date("Y-m-d H:i:s");
            $response = [
                'err_num' => 6000,
                'err_msg' => 'ok',
                'data'    => $data
            ];
        } else {
            $response = [
                'err_num' => 6003,
                'err_msg' => 'Token Not Valid!'
            ];
        }
        return $response;
    }
}
