<?php

use Illuminate\Routing\Router;

Admin::registerAuthRoutes();

Route::group([
    'prefix'        => config('admin.route.prefix'),
    'namespace'     => config('admin.route.namespace'),
    'middleware'    => config('admin.route.middleware'),
], function (Router $router) {

    //$router->get('/', 'HomeController@index');
    //$router->redirect('/', 'hostNames');
    $router->resource('sysParameter', SysParameterController::class);
    $router->resource('transfer', TransferController::class);
    $router->resource('hostNames', HostNamesController::class);

});
