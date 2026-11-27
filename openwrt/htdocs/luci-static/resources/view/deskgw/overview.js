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
			_('存放证书、SQLite 数据库与初始管理员密码的目录。须可写且能持久保留。' +
			  '注意：默认值 /etc/deskgw 在 overlay 上，审计、会话与 WAL 会持续写入闪存；' +
			  '长期运行建议改到外部存储（如 /mnt/usb/deskgw）并确保挂载先于本服务。'));
		o.placeholder = '/etc/deskgw';
		o.rmempty = false;

		o = s.option(form.ListValue, 'cookie_secure', _('安全 Cookie'),
			_('启用后会话 Cookie 仅通过 HTTPS 传输。公网部署时须保持启用。'));
		o.value('1', _('启用'));
		o.value('0', _('停用'));
		o.default = '1';

		o = s.option(form.Value, 'session_idle_min', _('会话空闲超时（分钟）'),
			_('仅在后台从未保存过设置时作为初始值。后台「设置」页保存过一次后以数据库为准，' +
			  '这里的修改不再生效；要改请到后台设置页。'));
		o.datatype = 'uinteger';
		o.default = '30';

		o = s.option(form.Value, 'max_upload_mb', _('单文件上传上限（MB）'),
			_('同上：仅在后台从未保存过设置时作为初始值，之后以数据库为准。'));
		o.datatype = 'uinteger';
		o.default = '2048';

		o = s.option(form.Value, 'gomemlimit', _('Go 内存软上限（高级）'),
			_('Go 运行时的内存软上限，例如 160MiB。留空则按物理内存的 40% 自动计算，' +
			  '下限 96MiB、上限 256MiB。小内存路由器上不设的话，几次并发登录就可能把内存顶到 OOM。'));
		o.placeholder = _('留空则自动计算（96–256MiB）');
		o.rmempty = true;

		o = s.option(form.Value, 'redirect_listen', _('HTTP 跳转监听地址（高级）'),
			_('留空关闭。填写后在该地址上监听明文 HTTP，并跳转到 HTTPS 监听端口，' +
			  '例如 0.0.0.0:80。只适合局域网，注意不要和主监听端口冲突。'));
		o.placeholder = _('留空则关闭');
		o.rmempty = true;

		s = m.section(form.NamedSection, 'main', 'deskgw', _('性能模式'),
			_('接收 Airhand 被控端的 QUIC 连接。修改后点页面底部的「重启服务」生效。'));

		o = s.option(form.Flag, 'perf_enabled', _('启用性能模式'),
			_('默认关闭，不影响普通远程桌面。'));
		o.default = '0';

		o = s.option(form.Value, 'perf_listen', _('QUIC 监听地址'),
			_('UDP 监听地址与端口，默认 0.0.0.0:4433。建议绑定 LAN 接口（如 192.168.1.1:4433），不要把 UDP 端口暴露到公网。'));
		o.placeholder = '0.0.0.0:4433';
		o.rmempty = false;

		o = s.option(form.Value, 'perf_cert', _('QUIC 证书'),
			_('首次启动自动生成，一般不需要修改。'));
		o.placeholder = '/etc/deskgw/perf.crt';
		o.readonly = true;

		o = s.option(form.Value, 'perf_key', _('QUIC 私钥'),
			_('首次启动自动生成，一般不需要修改。'));
		o.placeholder = '/etc/deskgw/perf.key';
		o.readonly = true;

		o = s.option(form.Value, 'perf_identity', _('控制端身份私钥'),
			_('X25519 私钥，权限 600，首次启动自动生成。丢失或替换后，所有被控端都要重新预置配对，请纳入备份。'));
		o.placeholder = '/etc/deskgw/perf_identity';
		o.readonly = true;

		o = s.option(form.Flag, 'perf_udp_tune', _('优化 UDP 接收缓冲'),
			_('仅在启用性能模式时生效：服务启动时把内核的 UDP 收发缓冲上限调整为下方指定值，' +
			  '并写入 /etc/sysctl.conf 以便重启后继续生效。' +
			  '高码率视频传输依赖较大的接收缓冲；缓冲不足会导致丢包与画面卡顿。' +
			  '关闭性能模式或关闭本项时，会移除此前写入的 sysctl 配置（内核当前值保留到下次重启）。'));
		o.default = '1';

		o = s.option(form.Value, 'perf_udp_buf_mb', _('UDP 缓冲上限（MiB）'),
			_('对应 net.core.rmem_max 与 net.core.wmem_max 的目标值，默认 8 MiB。' +
			  '数值越大越能吸收网络抖动，但会相应增加内核内存占用；仅在开启缓冲优化时生效。'));
		o.datatype = 'uinteger';
		o.placeholder = '8';
		o.default = '8';
		o.rmempty = false;

		s = m.section(form.NamedSection, 'main', 'deskgw', _('运维操作'));

		o = s.option(form.Button, '_fp', _('HTTPS 证书指纹（普通模式）'));
		o.inputstyle = 'action';
		o.onclick = function() {
			return fs.exec('/usr/libexec/deskgw/cert-fingerprint.sh').then(function(res) {
				var fp = (res.code === 0) ? String(res.stdout || '').trim()
					: _('读取失败，请确认服务已启动至少一次');
				ui.showModal(_('HTTPS 证书指纹（普通模式）'), [
					E('p', {}, _('8443 端口的 HTTPS 证书指纹，供普通远程桌面的客户端校验。' +
					             '不要填进性能模式被控端的 server_fp，那里需要下面的 QUIC 指纹。')),
					E('pre', { 'style': 'word-break:break-all;white-space:pre-wrap' }, fp),
				]);
			});
		};

		o = s.option(form.Button, '_fp_perf', _('QUIC 证书指纹（性能模式）'));
		o.inputstyle = 'action';
		o.onclick = function() {
			// 和「打开管理界面」一样用 id 后缀取输入框里的路径，取不到回落到默认值。
			var el = document.querySelector('input[id$=".perf_cert"]') ||
				document.querySelector('input[data-name="perf_cert"]');
			var cert = (el && el.value) || '/etc/deskgw/perf.crt';
			return fs.exec('/usr/libexec/deskgw/cert-fingerprint.sh', [ cert ]).then(function(res) {
				var fp = (res.code === 0) ? String(res.stdout || '').trim()
					: _('读取失败，请确认性能模式已启用并至少启动过一次');
				ui.showModal(_('QUIC 证书指纹（性能模式）'), [
					E('p', {}, _('填进被控端 config.toml 的 server_fp（64 位十六进制）。' +
					             '控制端公钥 [[paired]].key 不在这里，请到管理后台「性能模式」页复制。')),
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
