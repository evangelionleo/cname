<?php

namespace App\Admin\Controllers;

use App\Models\Transfer;
use App\Http\Controllers\Controller;
use Encore\Admin\Controllers\HasResourceActions;
use Encore\Admin\Form;
use Encore\Admin\Grid;
use Encore\Admin\Layout\Content;
use Encore\Admin\Show;

class TransferController extends Controller
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
            ->header('中转机')
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
            ->header('中转机')
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
            ->header('中转机')
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
            ->header('中转机')
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
        $grid = new Grid(new Transfer);

        $grid->id('Id');
        $grid->ipAddress('ip地址');
        $grid->type('类型');
        $grid->tcpPorts('已使用tcp端口');
        $grid->udpPorts('已使用udp端口');
        $grid->runStatus('存活状态');

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
        $show = new Show(Transfer::findOrFail($id));

        $show->id('Id');
        $show->ipAddress('ip地址');
        $show->type('类型');
        $show->tcpPorts('已使用tcp端口');
        $show->udpPorts('已使用udp端口');
        $show->runStatus('存活状态');
        $show->created_at('创建时间');
        $show->updated_at('修改时间');

        return $show;
    }

    /**
     * Make a form builder.
     *
     * @return Form
     */
    protected function form()
    {
        $form = new Form(new Transfer);

        $form->text('ipAddress', 'ip地址');
        $form->text('type', '类型');
        $form->text('tcpPorts', '已使用tcp端口')->help("（多个端口用英文逗号分割）");
        $form->text('udpPorts', '已使用udp端口')->help("（多个端口用英文逗号分割）");
        $form->number('runStatus', '存活状态');

        return $form;
    }
}
