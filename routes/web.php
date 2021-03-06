<?php

/*
|--------------------------------------------------------------------------
| Web Routes
|--------------------------------------------------------------------------
|
| Here is where you can register web routes for your application. These
| routes are loaded by the RouteServiceProvider within a group which
| contains the "web" middleware group. Now create something great!
|
*/

Route::get('/', function () {
    return view('welcome');
});

///////////////////////// TEST ////////////////////////////
Route::get('test/check','TestController@md5');     //注册
Route::post('test/check2','TestController@check2'); 	// 验签
///////////////////////// TEST ////////////////////////////

Route::post('user/reg','User\UserController@reg');     //注册
Route::post('user/login','User\UserController@login'); // 登录
Route::get('user/info','User\UserController@userInfo'); // 获取用户信息
Route::post('user/auth','User\UserController@auth'); // 鉴权
