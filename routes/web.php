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

Route::post('user/reg','User\UserController@reg');     //注册
Route::post('user/login','User\UserController@login'); // 登录
Route::get('user/info','User\UserController@userInfo'); // 获取用户信息
Route::post('/api/auth','User\UserController@auth'); // 鉴权
