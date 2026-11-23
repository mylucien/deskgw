'use strict';
'require view';
'require form';
'require fs';
'require ui';

return view.extend({
	render: function() {
		var m, s, o;

		m = new form.Map('deskgw',
			_('deskgw 远程桌面网关'),
			_('本页配置网关服务的监听参数与存储位置。远程桌面的 Web 管理界面由同一进程提供，默认端口为 8443。'));

		s = m.section(form.NamedSection, 'main', 'deskgw', _('基本设置'));

		o = s.option(form.Flag, 'enabled', _('启用'));
		o.default = '1';

		o = s.option(form.Value, 'listen', _('监听地址'),
			_('HTTPS 监听地址与端口，默认 0.0.0.0:8443。'));
		o.placeholder = '0.0.0.0:8443';
		o.rmempty = false;

		o = s.option(form.Value, 'cert_names', _('证书名称'),
			_('自签证书中写入的域名或 IP，以逗号分隔。实际访问地址应包含在内，以避免名称不匹配告警。修改后重启服务会按新设置重签自签证书；自备证书不会被改动。'));
		o.placeholder = '192.168.1.1,deskgw.lan';
		o.rmempty = true;

		o = s.option(form.Value, 'data_dir', _('数据目录'),
			_('存放证书、SQLite 数据库与初始管理员密码的目录。须可写且能持久保留。'));
		o.placeholder = '/etc/deskgw';
		o.rmempty = false;

		o = s.option(form.ListValue, 'cookie_secure', _('安全 Cookie'),
			_('启用后会话 Cookie 仅通过 HTTPS 传输。公网部署时须保持启用。'));
		o.value('1', _('启用'));
		o.value('0', _('停用'));
		o.default = '1';

		o = s.option(form.Value, 'session_idle_min', _('会话空闲超时（分钟）'));
		o.datatype = 'uinteger';
		o.default = '30';

		o = s.option(form.Value, 'max_upload_mb', _('单文件上传上限（MB）'));
		o.datatype = 'uinteger';
		o.default = '2048';

		s = m.section(form.NamedSection, 'main', 'deskgw', _('运维操作'));

		o = s.option(form.Button, '_fp', _('查看证书指纹'));
		o.inputstyle = 'action';
		o.onclick = function() {
			return fs.exec('/usr/libexec/deskgw/cert-fingerprint.sh').then(function(res) {
				var fp = (res.code === 0) ? String(res.stdout || '').trim()
					: _('读取失败，请确认服务已启动至少一次');
				ui.showModal(_('HTTPS 证书指纹'), [
					E('p', {}, _('该指纹用于校验服务端证书，长度为 64 位十六进制字符。')),
					E('pre', { 'style': 'word-break:break-all;white-space:pre-wrap' }, fp),
				]);
			});
		};

		o = s.option(form.Button, '_restart', _('重启服务'));
		o.inputstyle = 'action';
		o.onclick = function() {
			return fs.exec('/etc/init.d/deskgw', [ 'restart' ]).then(function() {
				ui.showModal(_('操作完成'), [ E('p', {}, _('deskgw 服务已重启。')) ]);
			});
		};

		o = s.option(form.Button, '_open', _('打开管理界面'));
		o.inputstyle = 'action';
		o.onclick = function() {
			// LuCI 渲染出的输入框 id 形如 cbid.deskgw.main.listen，没有 data-name；
			// 用 id 后缀匹配，取不到时回落到默认端口。
			var el = document.querySelector('input[id$=".listen"]') ||
				document.querySelector('input[data-name="listen"]');
			var port = (el && el.value) || '0.0.0.0:8443';
			var p = port.split(':').pop() || '8443';
			window.open('https://' + window.location.hostname + ':' + p + '/', '_blank');
		};

		return m.render();
	}
});
