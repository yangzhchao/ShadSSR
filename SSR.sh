＃！/ usr / bin / env bash
PATH = / bin中：/ sbin目录：在/ usr / bin中：/ usr / sbin目录：在/ usr / local / bin目录：在/ usr / local / sbin中：〜/ bin中
出口PATH

＃=================================================
#System System：CentOS 6 + / Debian 6 + / Ubuntu 14.04+
＃说明：安装ShadowsocksR服务器
＃Version：2.0.38
＃作者：东洋
＃Blog：https：//doub.io/ss-jc42/
＃=================================================

sh_ver = “2.0.38”
filepath = $（cd“$（dirname”$ 0“）”; pwd）
file = $（echo -e“$ {filepath}”| awk -F“$ 0”'{print $ 1}'）
ssr_folder = “/ USR /本地/ shadowsocksr”
ssr_ss_file = “$ {ssr_folder} / 2.6.8”
CONFIG_FILE = “$ {} ssr_folder /config.json”
config_folder = “的/ etc / shadowsocksr”
config_user_file = “$ {} config_folder /user-config.json”
ssr_log_file = “$ {} ssr_ss_file /ssserver.log”
Libsodiumr_file = “在/ usr / local / lib目录/ libsodium.so”
Libsodiumr_ver_backup = “1.0.13”
Server_Speeder_file = “/ serverspeeder /斌/ serverSpeeder.sh”
LotServer_file = “/ APPEX /斌/ serverSpeeder.sh”
BBR_file = “$ {}文件/bbr.sh”
jq_file = “$ {ssr_folder} / JQ”
Green_font_prefix = “\ 033 [32米” && Red_font_prefix = “\ 033 [31米” && Green_background_prefix = “\ 033 [42;37米” && Red_background_prefix = “\ 033 [41;37米” && Font_color_suffix = “\ 033 [0米”
信息= “$ {} Green_font_prefix [信息] $ {} Font_color_suffix”
错误= “$ {Red_font_prefix} [错误] $ {Font_color_suffix}”
提示= “$ {Green_font_prefix} [注意] $ {Font_color_suffix}”
Separator_1 = “------------------------------”

check_root（）{
	[[$ EUID！= 0]] && echo -e“$ {Error}当前账号非ROOT（或没有ROOT权限），无法继续操作，请使用$ {Green_background_prefix} sudo su $ {Font_color_suffix}来获取临时ROOT权限（执行后会提示输入当前账号的密码）。“&&退出1
}
check_sys（）{
	if [[-f / etc / redhat-release]]; 然后
		释放= “centos的”
	elif cat / etc / issue | grep -q -E -i“debian”; 然后
		释放= “Debian的”
	elif cat / etc / issue | grep -q -E -i“ubuntu”; 然后
		释放= “Ubuntu的”
	elif cat / etc / issue | grep -q -E -i“centos | red hat | redhat”; 然后
		释放= “centos的”
	elif cat / proc / version | grep -q -E -i“debian”; 然后
		释放= “Debian的”
	elif cat / proc / version | grep -q -E -i“ubuntu”; 然后
		释放= “Ubuntu的”
	elif cat / proc / version | grep -q -E -i“centos | red hat | redhat”; 然后
		释放= “centos的”
    科幻
	bit =`uname -m`
}
check_pid（）{
	PID =`ps -ef | grep -v grep | grep server.py | awk'{print $ 2}'`
}
SSR_installation_status（）{
	[[！-e $ {config_user_file}]] && echo -e“$ {错误}没有发现ShadowsocksR配置文件，请检查！” &&退出1
	[[！-e $ {ssr_folder}]] && echo -e“$ {错误}没有发现ShadowsocksR文件夹，请检查！” &&退出1
}
Server_Speeder_installation_status（）{
	[[！-e $ {Server_Speeder_file}]] && echo -e“$ {Error}没有安装锐速（Server Speeder），请检查！” &&退出1
}
LotServer_installation_status（）{
	[[！-e $ {LotServer_file}]] && echo -e“$ {Error}没有安装LotServer，请检查！” &&退出1
}
BBR_installation_status（）{
	如果[[！-e $ {BBR_file}]]; 然后
		echo -e“$ {错误}没有发现BBR脚本，开始下载......”
		cd“$ {file}”
		如果！wget -N --no-check-certificate https://raw.githubusercontent.com/ToyoDAdoubi/doubi/master/bbr.sh; 然后
			echo -e“$ {Error} BBR脚本下载失败！” &&退出1
		其他
			echo -e“$ {Info} BBR脚本下载完成！”
			chmod + x bbr.sh
		科幻
	科幻
}
＃设置防火墙规则
Add_iptables（）{
	iptables -I INPUT -m state --state NEW -m tcp -p tcp --dport $ {ssr_port} -j ACCEPT
	iptables -I INPUT -m state --state NEW -m udp -p udp --dport $ {ssr_port} -j ACCEPT
	ip6tables -I INPUT -m state --state NEW -m tcp -p tcp --dport $ {ssr_port} -j ACCEPT
	ip6tables -I INPUT -m state --state NEW -m udp -p udp --dport $ {ssr_port} -j ACCEPT
}
Del_iptables（）{
	iptables -D INPUT -m state --state NEW -m tcp -p tcp --dport $ {port} -j ACCEPT
	iptables -D INPUT -m state --state NEW -m udp -p udp --dport $ {port} -j ACCEPT
	ip6tables -D INPUT -m state --state NEW -m tcp -p tcp --dport $ {port} -j ACCEPT
	ip6tables -D INPUT -m state --state NEW -m udp -p udp --dport $ {port} -j ACCEPT
}
Save_iptables（）{
	if [[$ {release} ==“centos”]]; 然后
		服务iptables保存
		服务ip6tables保存
	其他
		iptables-save> /etc/iptables.up.rules
		ip6tables-save> /etc/ip6tables.up.rules
	科幻
}
Set_iptables（）{
	if [[$ {release} ==“centos”]]; 然后
		服务iptables保存
		服务ip6tables保存
		chkconfig --level 2345 iptables on
		chkconfig --level 2345 ip6tables on
	其他
		iptables-save> /etc/iptables.up.rules
		ip6tables-save> /etc/ip6tables.up.rules
		回波-e '＃！/斌/庆典\ N / sbin目录/ iptables的-恢复</etc/iptables.up.rules\n/sbin/ip6tables-restore </etc/ip6tables.up.rules'>的/ etc /网络/if-pre-up.d/iptables
		chmod + x /etc/network/if-pre-up.d/iptables
	科幻
}
＃读取配置信息
Get_IP（）{
	ip = $（wget -qO- -t1 -T2 ipinfo.io/ip）
	if [[-z“$ {ip}”]]; 然后
		ip = $（wget -qO- -t1 -T2 api.ip.sb/ip）
		if [[-z“$ {ip}”]]; 然后
			ip = $（wget -qO- -t1 -T2 members.3322.org/dyndns/getip）
			if [[-z“$ {ip}”]]; 然后
				IP = “VPS_IP”
			科幻
		科幻
	科幻
}
GET_USER（）{
	[[！-e $ {jq_file}]] && echo -e“$ {Error} JQ解析器不存在，请检查！” &&退出1
	port =`$ {jq_file}'。server_port'$ {config_user_file}`
	password =`$ {jq_file}'。password' $ {config_user_file} | sed's /^.//; s /.$//'`
	method =`$ {jq_file}'。method' $ {config_user_file} | sed's /^.//; s /.$//'`
	protocol =`$ {jq_file}'.protocol'$ {config_user_file} | sed's /^.//; s /.$//'`
	obfs =`$ {jq_file}'。obfs'$ {config_user_file} | sed's /^.//; s /.$//'`
	protocol_param =`$ {jq_file}'.protocol_param'$ {config_user_file} | sed's /^.//; s /.$//'`
	speed_limit_per_con =`$ {jq_file}'。speed_limit_per_con'$ {config_user_file}`
	speed_limit_per_user =`$ {jq_file}'。speed_limit_per_user'$ {config_user_file}`
	connect_verbose_info =`$ {jq_file}'。connect_verbose_info'$ {config_user_file}`
}
urlsafe_base64（）{
	date = $（echo -n“$ 1”| base64 | sed'：a; N; s / \ n / / g; ta'| sed's / // g; s / = // g; s / + / -  /克; S / \ // _ / G'）
	echo -e“$ {date}”
}
ss_link_qr（）{
	SSbase64 = $（urlsafe_base64“$ {method}：$ {password} @ $ {ip}：$ {port}”）
	SSurl = “SS：// $ {} SSbase64”
	SSQRcode = “http://doub.pw/qr/qr.php?text=${SSurl}”
	ss_link =“SS链接：$ {Green_font_prefix} $ {SSurl} $ {Font_color_suffix} \ n SS二维码：$ {Green_font_prefix} $ {SSQRcode} $ {Font_color_suffix}”
}
ssr_link_qr（）{
	SSRprotocol = $（echo $ {protocol} | sed's / _compatible // g'）
	SSRobfs = $（echo $ {obfs} | sed's / _compatible // g'）
	SSRPWDbase64 = $（urlsafe_base64“$ {password}”）
	SSRbase64 = $（urlsafe_base64“$ {ip}：$ {port}：$ {SSRprotocol}：$ {method}：$ {SSRobfs}：$ {SSRPWDbase64}”）
	SSRurl = “SSR：// $ {} SSRbase64”
	SSRQRcode = “http://doub.pw/qr/qr.php?text=${SSRurl}”
	ssr_link =“SSR链接：$ {Red_font_prefix} $ {SSRurl} $ {Font_color_suffix} \ n SSR二维码：$ {Red_font_prefix} $ {SSRQRcode} $ {Font_color_suffix} \ n”
}
ss_ssr_determine（）{
	protocol_suffix =`echo $ {protocol} | awk -F“_”'{print $ NF}'`
	obfs_suffix =`echo $ {obfs} | awk -F“_”'{print $ NF}'`
	if [[$ {protocol} =“origin”]]; 然后
		if [[$ {obfs} =“plain”]]; 然后
			ss_link_qr
			ssr_link = “”
		其他
			if [[$ {obfs_suffix}！=“compatible”]]; 然后
				ss_link = “”
			其他
				ss_link_qr
			科幻
		科幻
	其他
		if [[$ {protocol_suffix}！=“compatible”]]; 然后
			ss_link = “”
		其他
			if [[$ {obfs_suffix}！=“compatible”]]; 然后
				if [[$ {obfs_suffix} =“plain”]]; 然后
					ss_link_qr
				其他
					ss_link = “”
				科幻
			其他
				ss_link_qr
			科幻
		科幻
	科幻
	ssr_link_qr
}
＃显示配置信息
View_User（）{
	SSR_installation_status
	Get_IP
	GET_USER
	now_mode = $（cat“$ {config_user_file}”| grep'“port_password”'）
	[[-z $ {protocol_param}]] && protocol_param =“0（无限）”
	if [[-z“$ {now_mode}”]]; 然后
		ss_ssr_determine
		清除&& echo“============================================== =====“&& echo
		echo -e“ShadowsocksR账号配置信息：”&& echo
		echo -e“IP \ t：$ {Green_font_prefix} $ {ip} $ {Font_color_suffix}”
		echo -e“端口\ t：$ {Green_font_prefix} $ {port} $ {Font_color_suffix}”
		echo -e“密码\ t：$ {Green_font_prefix} $ {password} $ {Font_color_suffix}”
		echo -e“加密\ t：$ {Green_font_prefix} $ {method} $ {Font_color_suffix}”
		echo -e“协议\ t：$ {Red_font_prefix} $ {protocol} $ {Font_color_suffix}”
		echo -e“混淆\ t：$ {Red_font_prefix} $ {obfs} $ {Font_color_suffix}”
		echo -e“设备数限制：$ {Green_font_prefix} $ {protocol_param} $ {Font_color_suffix}”
		echo -e“单线程限速：$ {Green_font_prefix} $ {speed_limit_per_con} KB / S $ {Font_color_suffix}”
		echo -e“端口总限速：$ {Green_font_prefix} $ {speed_limit_per_user} KB / S $ {Font_color_suffix}”
		echo -e“$ {ss_link}”
		echo -e“$ {ssr_link}”
		echo -e“$ {Green_font_prefix}提示：$ {Font_color_suffix}
 在浏览器中，打开二维码链接，就可以看到二维码图片。
 协议和混淆后面的[_compatible]，指的是兼容原版协议/混淆。“
		echo && echo“============================================== =====”
	其他
		user_total =`$ {jq_file}'。port_password'$ {config_user_file} | sed'$ d'| sed“1d”| wc -l`
		[[$ {user_total} =“0”]] && echo -e“$ {Error}没有发现多端口用户，请检查！” &&退出1
		清除&& echo“============================================== =====“&& echo
		echo -e“ShadowsocksR账号配置信息：”&& echo
		echo -e“IP \ t：$ {Green_font_prefix} $ {ip} $ {Font_color_suffix}”
		echo -e“加密\ t：$ {Green_font_prefix} $ {method} $ {Font_color_suffix}”
		echo -e“协议\ t：$ {Red_font_prefix} $ {protocol} $ {Font_color_suffix}”
		echo -e“混淆\ t：$ {Red_font_prefix} $ {obfs} $ {Font_color_suffix}”
		echo -e“设备数限制：$ {Green_font_prefix} $ {protocol_param} $ {Font_color_suffix}”
		echo -e“单线程限速：$ {Green_font_prefix} $ {speed_limit_per_con} KB / S $ {Font_color_suffix}”
		echo -e“端口总限速：$ {Green_font_prefix} $ {speed_limit_per_user} KB / S $ {Font_color_suffix}”&& echo
		for（（integer = $ {user_total}; integer> = 1; integer--））
		做
			port =`$ {jq_file}'。port_password'$ {config_user_file} | sed'$ d'| sed“1d”| awk -F“：”'{print $ 1}'| sed -n“$ {integer} p”| sed -r's /.* \“（。+）\”。* / \ 1 /'`
			password =`$ {jq_file}'。port_password'$ {config_user_file} | sed'$ d'| sed“1d”| awk -F“：”'{print $ 2}'| sed -n“$ {integer} p”| sed -r's /.* \“（。+）\”。* / \ 1 /'`
			ss_ssr_determine
			echo -e $ {Separator_1}
			echo -e“端口\ t：$ {Green_font_prefix} $ {port} $ {Font_color_suffix}”
			echo -e“密码\ t：$ {Green_font_prefix} $ {password} $ {Font_color_suffix}”
			echo -e“$ {ss_link}”
			echo -e“$ {ssr_link}”
		DONE
		echo -e“$ {Green_font_prefix}提示：$ {Font_color_suffix}
 在浏览器中，打开二维码链接，就可以看到二维码图片。
 协议和混淆后面的[_compatible]，指的是兼容原版协议/混淆。“
		echo && echo“============================================== =====”
	科幻
}
＃设置配置信息
Set_config_port（）{
	虽然如此
	做
	echo -e“请输入要设置的ShadowsocksR账号端口”
	read -e -p“（默认：2333）：”ssr_port
	[[-z“$ ssr_port”]] && ssr_port =“2333”
	echo $（（$ {ssr_port} +0））＆> / dev / null
	如果[[$？== 0]]; 然后
		if [[$ {ssr_port} -ge 1]] && [[$ {ssr_port} -le 65535]]; 然后
			echo && echo $ {Separator_1} && echo -e“端口：$ {Green_font_prefix} $ {ssr_port} $ {Font_color_suffix}”&& echo $ {Separator_1} && echo
			打破
		其他
			echo -e“$ {Error}请输入正确的数字（1-65535）”
		科幻
	其他
		echo -e“$ {Error}请输入正确的数字（1-65535）”
	科幻
	DONE
}
Set_config_password（）{
	echo“请输入要设置的ShadowsocksR账号密码”
	read -e -p“（默认：doub.io）：”ssr_password
	[[-z“$ {ssr_password}”]] && ssr_password =“doub.io”
	echo && echo $ {Separator_1} && echo -e“密码：$ {Green_font_prefix} $ {ssr_password} $ {Font_color_suffix}”&& echo $ {Separator_1} && echo
}
Set_config_method（）{
	echo -e“请选择要设置的ShadowsocksR账号加密方式
	
 $ {Green_font_prefix} 1. $ {Font_color_suffix}无
 $ {Tip}如果使用auth_chain_a协议，请加密方式选择none，混淆随意（建议plain）
 
 $ {Green_font_prefix} 2. $ {Font_color_suffix} rc4
 $ {Green_font_prefix} 3. $ {Font_color_suffix} rc4-md5
 $ {Green_font_prefix} 4. $ {Font_color_suffix} rc4-md5-6
 
 $ {Green_font_prefix} 5. $ {Font_color_suffix} aes-128-ctr
 $ {Green_font_prefix} 6. $ {Font_color_suffix} aes-192-ctr
 $ {Green_font_prefix} 7. $ {Font_color_suffix} aes-256-ctr
 
 $ {Green_font_prefix} 8. $ {Font_color_suffix} aes-128-cfb
 $ {Green_font_prefix} 9. $ {Font_color_suffix} aes-192-cfb
 $ {Green_font_prefix} 10. $ {Font_color_suffix} aes-256-cfb
 
 $ {Green_font_prefix} 11. $ {Font_color_suffix} aes-128-cfb8
 $ {Green_font_prefix} 12. $ {Font_color_suffix} aes-192-cfb8
 $ {Green_font_prefix} 13。$ {Font_color_suffix} aes-256-cfb8
 
 $ {Green_font_prefix} 14. $ {Font_color_suffix} salsa20
 $ {Green_font_prefix} 15. $ {Font_color_suffix} chacha20
 $ {Green_font_prefix} 16。$ {Font_color_suffix} chacha20-ietf
 $ {Tip} salsa20 / chacha20- *系列加密方式，需要额外安装依赖libsodium，否则会无法启动ShadowsocksR！“&& echo
	read -e -p“（默认：5. aes-128-ctr）：”ssr_method
	[[-z“$ {ssr_method}”]] && ssr_method =“5”
	if [[$ {ssr_method} ==“1”]]; 然后
		ssr_method = “无”
	elif [[$ {ssr_method} ==“2”]]; 然后
		ssr_method = “RC4”
	elif [[$ {ssr_method} ==“3”]]; 然后
		ssr_method = “RC4-MD5”
	elif [[$ {ssr_method} ==“4”]]; 然后
		ssr_method = “RC4-md5-6”
	elif [[$ {ssr_method} ==“5”]]; 然后
		ssr_method = “AES-128-CTR”
	elif [[$ {ssr_method} ==“6”]]; 然后
		ssr_method = “AES-192-CTR”
	elif [[$ {ssr_method} ==“7”]]; 然后
		ssr_method = “AES-256-CTR”
	elif [[$ {ssr_method} ==“8”]]; 然后
		ssr_method = “AES-128-CFB”
	elif [[$ {ssr_method} ==“9”]]; 然后
		ssr_method = “AES-192-CFB”
	elif [[$ {ssr_method} ==“10”]]; 然后
		ssr_method = “AES-256-CFB”
	elif [[$ {ssr_method} ==“11”]]; 然后
		ssr_method = “AES-128-CFB8”
	elif [[$ {ssr_method} ==“12”]]; 然后
		ssr_method = “AES-192-CFB8”
	elif [[$ {ssr_method} ==“13”]]; 然后
		ssr_method = “AES-256-CFB8”
	elif [[$ {ssr_method} ==“14”]]; 然后
		ssr_method = “salsa20”
	elif [[$ {ssr_method} ==“15”]]; 然后
		ssr_method = “chacha20”
	elif [[$ {ssr_method} ==“16”]]; 然后
		ssr_method = “chacha20-IETF”
	其他
		ssr_method = “AES-128-CTR”
	科幻
	echo && echo $ {Separator_1} && echo -e“加密：$ {Green_font_prefix} $ {ssr_method} $ {Font_color_suffix}”&& echo $ {Separator_1} && echo
}
Set_config_protocol（）{
	echo -e“请选择要设置的ShadowsocksR账号协议插件
	
 $ {Green_font_prefix} 1. $ {Font_color_suffix}来源
 $ {Green_font_prefix} 2. $ {Font_color_suffix} auth_sha1_v4
 $ {Green_font_prefix} 3. $ {Font_color_suffix} auth_aes128_md5
 $ {Green_font_prefix} 4. $ {Font_color_suffix} auth_aes128_sha1
 $ {Green_font_prefix} 5. $ {Font_color_suffix} auth_chain_a
 $ {Green_font_prefix} 6. $ {Font_color_suffix} auth_chain_b
 $ {Tip}如果使用auth_chain_a协议，请加密方式选择none，混淆随意（建议plain）“&& echo
	read -e -p“（默认：2。auth_sha1_v4）：”ssr_protocol
	[[-z“$ {ssr_protocol}”]] && ssr_protocol =“2”
	如果[[$ {ssr_protocol} ==“1”]]; 然后
		ssr_protocol = “原点”
	elif [[$ {ssr_protocol} ==“2”]]; 然后
		ssr_protocol = “auth_sha1_v4”
	elif [[$ {ssr_protocol} ==“3”]]; 然后
		ssr_protocol = “auth_aes128_md5”
	elif [[$ {ssr_protocol} ==“4”]]; 然后
		ssr_protocol = “auth_aes128_sha1”
	elif [[$ {ssr_protocol} ==“5”]]; 然后
		ssr_protocol = “auth_chain_a”
	elif [[$ {ssr_protocol} ==“6”]]; 然后
		ssr_protocol = “auth_chain_b”
	其他
		ssr_protocol = “auth_sha1_v4”
	科幻
	echo && echo $ {Separator_1} && echo -e“协议：$ {Green_font_prefix} $ {ssr_protocol} $ {Font_color_suffix}”&& echo $ {Separator_1} && echo
	if [[$ {ssr_protocol}！=“origin”]]; 然后
		if [[$ {ssr_protocol} ==“auth_sha1_v4”]]; 然后
			read -e -p“是否设置协议插件兼容原版（_compatible）？[Y / n]”ssr_protocol_yn
			[[-z“$ {ssr_protocol_yn}”]] && ssr_protocol_yn =“y”
			[[$ ssr_protocol_yn == [Yy]]] && ssr_protocol = $ {ssr_protocol}“_ compatible”
			回声
		科幻
	科幻
}
Set_config_obfs（）{
	echo -e“请选择要设置的ShadowsocksR账号混淆插件
	
 $ {Green_font_prefix} 1. $ {Font_color_suffix} plain
 $ {Green_font_prefix} 2. $ {Font_color_suffix} http_simple
 $ {Green_font_prefix} 3. $ {Font_color_suffix} http_post
 $ {Green_font_prefix} 4. $ {Font_color_suffix} random_head
 $ {Green_font_prefix} 5. $ {Font_color_suffix} tls1.2_ticket_auth
 $ {Tip}如果使用ShadowsocksR加速游戏，请选择混淆兼容原版或普通混淆，然后客户端选择plain，否则会增加延迟！
 另外，如果你选择了tls1.2_ticket_auth，那么客户端可以选择tls1.2_ticket_fastauth，这样即能伪装又不会增加延迟！
 如果你是在日本，美国等热门地区搭建，那么选择普通混淆可能被墙几率更低！“&& echo
	read -e -p“（默认：1。plain）：”ssr_obfs
	[[-z“$ {ssr_obfs}”]] && ssr_obfs =“1”
	if [[$ {ssr_obfs} ==“1”]]; 然后
		ssr_obfs = “普通”
	elif [[$ {ssr_obfs} ==“2”]]; 然后
		ssr_obfs = “http_simple”
	elif [[$ {ssr_obfs} ==“3”]]; 然后
		ssr_obfs = “HTTP_POST”
	elif [[$ {ssr_obfs} ==“4”]]; 然后
		ssr_obfs = “random_head”
	elif [[$ {ssr_obfs} ==“5”]]; 然后
		ssr_obfs = “tls1.2_ticket_auth”
	其他
		ssr_obfs = “普通”
	科幻
	echo && echo $ {Separator_1} && echo -e“混淆：$ {Green_font_prefix} $ {ssr_obfs} $ {Font_color_suffix}”&& echo $ {Separator_1} && echo
	if [[$ {ssr_obfs}！=“plain”]]; 然后
			read -e -p“是否设置混淆插件兼容原版（_compatible）？[Y / n]”ssr_obfs_yn
			[[-z“$ {ssr_obfs_yn}”]] && ssr_obfs_yn =“y”
			[[$ ssr_obfs_yn == [Yy]]] && ssr_obfs = $ {ssr_obfs}“_ compatible”
			回声
	科幻
}
Set_config_protocol_param（）{
	虽然如此
	做
	echo -e“请输入要设置的ShadowsocksR账号欲限制的设备数（$ {Green_font_prefix} auth_ *系列协议不兼容原版才有效$ {Font_color_suffix}）”
	echo -e“$ {Tip}设备数限制：每个端口同一时间能链接的客户端数量（多端口模式，每个端口都是独立计算），建议最少2个。”
	read -e -p“（默认：无限）：”ssr_protocol_param
	[[-z“$ ssr_protocol_param”]] && ssr_protocol_param =“”&& echo && break
	echo $（（$ {ssr_protocol_param} +0））＆> / dev / null
	如果[[$？== 0]]; 然后
		if [[$ {ssr_protocol_param} -ge 1]] && [[$ {ssr_protocol_param} -le 9999]]; 然后
			echo && echo $ {Separator_1} && echo -e“设备数限制：$ {Green_font_prefix} $ {ssr_protocol_param} $ {Font_color_suffix}”&& echo $ {Separator_1} && echo
			打破
		其他
			echo -e“$ {Error}请输入正确的数字（1-9999）”
		科幻
	其他
		echo -e“$ {Error}请输入正确的数字（1-9999）”
	科幻
	DONE
}
Set_config_speed_limit_per_con（）{
	虽然如此
	做
	echo -e“请输入要设置的每个端口单线程限速上限（单位：KB / S）”
	echo -e“$ {Tip}单线程限速：每个端口单线程的限速上限，多线程即无效。”
	read -e -p“（默认：无限）：”ssr_speed_limit_per_con
	[[-z“$ ssr_speed_limit_per_con”]] && ssr_speed_limit_per_con = 0 && echo && break
	echo $（（$ {ssr_speed_limit_per_con} +0））＆> / dev / null
	如果[[$？== 0]]; 然后
		if [[$ {ssr_speed_limit_per_con} -ge 1]] && [[$ {ssr_speed_limit_per_con} -le 131072]]; 然后
			echo && echo $ {Separator_1} && echo -e“单线程限速：$ {Green_font_prefix} $ {ssr_speed_limit_per_con} KB / S $ {Font_color_suffix}”&& echo $ {Separator_1} && echo
			打破
		其他
			echo -e“$ {Error}请输入正确的数字（1-131072）”
		科幻
	其他
		echo -e“$ {Error}请输入正确的数字（1-131072）”
	科幻
	DONE
}
Set_config_speed_limit_per_user（）{
	虽然如此
	做
	回声
	echo -e“请输入要设置的每个端口总速度限速上限（单位：KB / S）”
	echo -e“$ {Tip}端口总限速：每个端口总速度限速上限，单个端口整体限速。”
	read -e -p“（默认：无限）：”ssr_speed_limit_per_user
	[[-z“$ ssr_speed_limit_per_user”]] && ssr_speed_limit_per_user = 0 && echo && break
	echo $（（$ {ssr_speed_limit_per_user} +0））＆> / dev / null
	如果[[$？== 0]]; 然后
		if [[$ {ssr_speed_limit_per_user} -ge 1]] && [[$ {ssr_speed_limit_per_user} -le 131072]]; 然后
			echo && echo $ {Separator_1} && echo -e“端口总限速：$ {Green_font_prefix} $ {ssr_speed_limit_per_user} KB / S $ {Font_color_suffix}”&& echo $ {Separator_1} && echo
			打破
		其他
			echo -e“$ {Error}请输入正确的数字（1-131072）”
		科幻
	其他
		echo -e“$ {Error}请输入正确的数字（1-131072）”
	科幻
	DONE
}
Set_config_all（）{
	Set_config_port
	Set_config_password
	Set_config_method
	Set_config_protocol
	Set_config_obfs
	Set_config_protocol_param
	Set_config_speed_limit_per_con
	Set_config_speed_limit_per_user
}
＃修改配置信息
Modify_config_port（）{
	sed -i's /“server_port”：'“$（echo $ {port}）”'/“server_port”：'“$（echo $ {ssr_port}）”'/ g'$ {config_user_file}
}
Modify_config_password（）{
	sed -i's /“password”：“'”$（echo $ {password}）“'”/“password”：“'”$（echo $ {ssr_password}）“'”/ g'$ {config_user_file}
}
Modify_config_method（）{
	sed -i's /“method”：“'”$（echo $ {method}）“'”/“method”：“'”$（echo $ {ssr_method}）“'”/ g'$ {config_user_file}
}
Modify_config_protocol（）{
	sed -i's /“protocol”：“'”$（echo $ {protocol}）“'”/“protocol”：“'”$（echo $ {ssr_protocol}）“'”/ g'$ {config_user_file}
}
Modify_config_obfs（）{
	sed -i's /“obfs”：“'”$（echo $ {obfs}）“'”/“obfs”：“'”$（echo $ {ssr_obfs}）“'”/ g'$ {config_user_file}
}
Modify_config_protocol_param（）{
	sed -i's /“protocol_param”：“'”$（echo $ {protocol_param}）“'”/“protocol_param”：“'”$（echo $ {ssr_protocol_param}）“'”/ g'$ {config_user_file}
}
Modify_config_speed_limit_per_con（）{
	SED -i的/ “speed_limit_per_con”： ' “$（回声$ {speed_limit_per_con}）”'/ “speed_limit_per_con”： ' “$（回声$ {ssr_speed_limit_per_con}）”'/ G'$ {config_user_file}
}
Modify_config_speed_limit_per_user（）{
	sed -i's /“speed_limit_per_user”：'“$（echo $ {speed_limit_per_user}）”'/“speed_limit_per_user”：'“$（echo $ {ssr_speed_limit_per_user}）”'/ g'$ {config_user_file}
}
Modify_config_connect_verbose_info（）{
	SED -i的/ “connect_verbose_info”： ' “$（回声$ {connect_verbose_info}）”'/ “connect_verbose_info”： ' “$（回声$ {ssr_connect_verbose_info}）”'/ G'$ {config_user_file}
}
Modify_config_all（）{
	Modify_config_port
	Modify_config_password
	Modify_config_method
	Modify_config_protocol
	Modify_config_obfs
	Modify_config_protocol_param
	Modify_config_speed_limit_per_con
	Modify_config_speed_limit_per_user
}
Modify_config_port_many（）{
	sed -i's /“'”$（echo $ {port}）“'”：/“'”$（echo $ {ssr_port}）“'”：/ g'$ {config_user_file}
}
Modify_config_password_many（）{
	sed -i's /“'”$（echo $ {password}）“'”/“'”$（echo $ {ssr_password}）“'”/ g'$ {config_user_file}
}
＃写入配置信息
Write_configuration（）{
	cat> $ {config_user_file} <<  -  EOF
{
    “server”：“0.0.0.0”，
    “server_ipv6”：“::”，
    “server_port”：$ {ssr_port}，
    “local_address”：“127.0.0.1”，
    “local_port”：1080，

    “password”：“$ {ssr_password}”，
    “method”：“$ {ssr_method}”，
    “protocol”：“$ {ssr_protocol}”，
    “protocol_param”：“$ {ssr_protocol_param}”，
    “obfs”：“$ {ssr_obfs}”，
    “obfs_param”：“”，
    “speed_limit_per_con”：$ {ssr_speed_limit_per_con}，
    “speed_limit_per_user”：$ {ssr_speed_limit_per_user}，

    “additional_ports”：{}，
    “超时”：120，
    “udp_timeout”：60，
    “dns_ipv6”：false，
    “connect_verbose_info”：0，
    “重定向”：“”，
    “fast_open”：false
}
EOF
}
Write_configuration_many（）{
	cat> $ {config_user_file} <<  -  EOF
{
    “server”：“0.0.0.0”，
    “server_ipv6”：“::”，
    “local_address”：“127.0.0.1”，
    “local_port”：1080，

    “port_password”：{
        “$ {} ssr_port”： “$ {} ssr_password”
    }，
    “method”：“$ {ssr_method}”，
    “protocol”：“$ {ssr_protocol}”，
    “protocol_param”：“$ {ssr_protocol_param}”，
    “obfs”：“$ {ssr_obfs}”，
    “obfs_param”：“”，
    “speed_limit_per_con”：$ {ssr_speed_limit_per_con}，
    “speed_limit_per_user”：$ {ssr_speed_limit_per_user}，

    “additional_ports”：{}，
    “超时”：120，
    “udp_timeout”：60，
    “dns_ipv6”：false，
    “connect_verbose_info”：0，
    “重定向”：“”，
    “fast_open”：false
}
EOF
}
Check_python（）{
	python_ver =`python -h`
	if [[-z $ {python_ver}]]; 然后
		echo -e“$ {Info}没有安装Python，开始安装......”
		if [[$ {release} ==“centos”]]; 然后
			yum install -y python
		其他
			apt-get install -y python
		科幻
	科幻
}
Centos_yum（）{
	百胜更新
	cat / etc / redhat-release | grep 7 \ .. * | grep -i centos> / dev / null
	如果[[$？= 0]]; 然后
		yum install -y vim unzip net-tools
	其他
		yum install -y vim unzip
	科幻
}
Debian_apt（）{
	apt-get update
	cat / etc / issue | grep 9 \ .. *> / dev / null
	如果[[$？= 0]]; 然后
		apt-get install -y vim unzip net-tools
	其他
		apt-get install -y vim unzip
	科幻
}
＃下载ShadowsocksR
Download_SSR（）{
	cd“/ usr / local /”
	wget -N --no-check-certificate“https://github.com/ToyoDAdoubiBackup/shadowsocksr/archive/manyuser.zip”
	#git config --global http.sslVerify false
	#env GIT_SSL_NO_VERIFY = true git clone -b manyuser https://github.com/ToyoDAdoubiBackup/shadowsocksr.git
	＃[[！-e $ {ssr_folder}]] && echo -e“$ {Error} ShadowsocksR服务端下载失败！” &&退出1
	[[！-e“manyuser.zip”]] && echo -e“$ {Error} ShadowsocksR服务端压缩包下载失败！” && rm -rf manyuser.zip &&退出1
	解压缩“manyuser.zip”
	[[！-e“/ usr / local / shadowsocksr-manyuser /”]] && echo -e“$ {Error} ShadowsocksR服务端解压失败！” && rm -rf manyuser.zip &&退出1
	mv“/ usr / local / shadowsocksr-manyuser /”“/ usr / local / shadowsocksr /”
	[[！-e“/ usr / local / shadowsocksr /”]] && echo -e“$ {Error} ShadowsocksR服务端重命名失败！” && rm -rf manyuser.zip && rm -rf“/ usr / local / shadowsocksr-manyuser /”&& exit 1
	rm -rf manyuser.zip
	[[-e $ {config_folder}]] && rm -rf $ {config_folder}
	mkdir $ {config_folder}
	[[！-e $ {config_folder}]] && echo -e“$ {Error} ShadowsocksR配置文件的文件夹建立失败！” &&退出1
	echo -e“$ {Info} ShadowsocksR服务端下载完成！”
}
Service_SSR（）{
	如果[[$ {release} =“centos”]]; 然后
		如果！wget --no-check-certificate https://raw.githubusercontent.com/ToyoDAdoubi/doubi/master/service/ssr_centos -O /etc/init.d/ssr; 然后
			echo -e“$ {Error} ShadowsocksR服务管理脚本下载失败！” &&退出1
		科幻
		chmod + x /etc/init.d/ssr
		chkconfig --add ssr
		chkconfig ssr on
	其他
		如果！wget --no-check-certificate https://raw.githubusercontent.com/ToyoDAdoubi/doubi/master/service/ssr_debian -O /etc/init.d/ssr; 然后
			echo -e“$ {Error} ShadowsocksR服务管理脚本下载失败！” &&退出1
		科幻
		chmod + x /etc/init.d/ssr
		update-rc.d -f ssr默认值
	科幻
	echo -e“$ {Info} ShadowsocksR服务管理脚本下载完成！”
}
＃安装JQ解析器
JQ_install（）{
	如果[[！-e $ {jq_file}]]; 然后
		cd“$ {ssr_folder}”
		如果[[$ {bit} =“x86_64”]]; 然后
			mv“jq-linux64”“jq”
			#wget --no-check-certificate“https://github.com/stedolan/jq/releases/download/jq-1.5/jq-linux64”-O $ {jq_file}
		其他
			mv“jq-linux32”“jq”
			#wget --no-check-certificate“https://github.com/stedolan/jq/releases/download/jq-1.5/jq-linux32”-O $ {jq_file}
		科幻
		[[！-e $ {jq_file}]] && echo -e“$ {Error} JQ解析器重命名失败，请检查！” &&退出1
		chmod + x $ {jq_file}
		echo -e“$ {Info} JQ解析器安装完成，继续...” 
	其他
		echo -e“$ {Info} JQ解析器已安装，继续...”
	科幻
}
＃安装依赖
Installation_dependency（）{
	if [[$ {release} ==“centos”]]; 然后
		Centos_yum
	其他
		Debian_apt
	科幻
	[[！-e“/ usr / bin / unzip”]] && echo -e“$ {Error}依赖unzip（解压压缩包）安装失败，多半是软件包源的问题，请检查！” &&退出1
	Check_python
	#echo“nameserver 8.8.8.8”> /etc/resolv.conf
	#echo“nameserver 8.8.4.4”>> /etc/resolv.conf
	\ cp -f / usr / share / zoneinfo / Asia / Shanghai / etc / localtime
}
Install_SSR（）{
	check_root
	[[-e $ {config_user_file}]] && echo -e“$ {Error} ShadowsocksR配置文件已存在，请检查（如安装失败或者存在旧版本，请先卸载）！” &&退出1
	[[-e $ {ssr_folder}]] && echo -e“$ {Error} ShadowsocksR文件夹已存在，请检查（如安装失败或者存在旧版本，请先卸载）！” &&退出1
	echo -e“$ {Info}开始设置ShadowsocksR账号配置......”
	Set_config_all
	echo -e“$ {Info}开始安装/配置ShadowsocksR依赖...”
	Installation_dependency
	echo -e“$ {Info}开始下载/安装ShadowsocksR文件......”
	Download_SSR
	echo -e“$ {Info}开始下载/安装ShadowsocksR服务脚本（init）......”
	Service_SSR
	echo -e“$ {Info}开始下载/安装JSNO解析器JQ ...”
	JQ_install
	echo -e“$ {Info}开始写入ShadowsocksR配置文件......”
	Write_configuration
	echo -e“$ {Info}开始设置iptables防火墙......”
	Set_iptables
	echo -e“$ {Info}开始添加iptables防火墙规则......”
	Add_iptables
	echo -e“$ {Info}开始保存iptables防火墙规则......”
	Save_iptables
	echo -e“$ {Info}所有步骤安装完毕，开始启动ShadowsocksR服务端......”
	Start_SSR
}
Update_SSR（）{
	SSR_installation_status
	echo -e“因破娃暂停更新ShadowsocksR服务端，所以此功能临时禁用。”
	#cd $ {ssr_folder}
	#git pull
	#Restart_SSR
}
Uninstall_SSR（）{
	[[！-e $ {config_user_file}]] && [[！-e $ {ssr_folder}]] && echo -e“$ {错误}没有安装ShadowsocksR，请检查！” &&退出1
	echo“确定要卸载ShadowsocksR？[y / N]”&& echo
	read -e -p“（默认：n）：”unyn
	[[-z $ {unyn}]] && unyn =“n”
	如果[[$ {unyn} == [Yy]]]; 然后
		check_pid
		[[！-z“$ {PID}”]] && kill -9 $ {PID}
		if [[-z“$ {now_mode}”]]; 然后
			port =`$ {jq_file}'。server_port'$ {config_user_file}`
			Del_iptables
			Save_iptables
		其他
			user_total =`$ {jq_file}'。port_password'$ {config_user_file} | sed'$ d'| sed“1d”| wc -l`
			for（（integer = 1; integer <= $ {user_total}; integer ++））
			做
				port =`$ {jq_file}'。port_password'$ {config_user_file} | sed'$ d'| sed“1d”| awk -F“：”'{print $ 1}'| sed -n“$ {integer} p”| sed -r's /.* \“（。+）\”。* / \ 1 /'`
				Del_iptables
			DONE
			Save_iptables
		科幻
		如果[[$ {release} =“centos”]]; 然后
			chkconfig --del ssr
		其他
			update-rc.d -f ssr remove
		科幻
		rm -rf $ {ssr_folder} && rm -rf $ {config_folder} && rm -rf /etc/init.d/ssr
		echo && echo“ShadowsocksR卸载完成！” && echo
	其他
		echo && echo“卸载已取消......”&& echo
	科幻
}
Check_Libsodium_ver（）{
	echo -e“$ {Info}开始获取libsodium最新版本......”
	Libsodiumr_ver = $（wget -qO-“https://github.com/jedisct1/libsodium/tags"|grep”/ jedisct1 / libsodium / releases / tag /“| head -1 | sed -r's /.* tag \ /（+）\“> * / \ 1 /'）
	[[-z $ {Libsodiumr_ver}]] && Libsodiumr_ver = $ {Libsodiumr_ver_backup}
	echo -e“$ {Info} libsodium最新版本为$ {Green_font_prefix} $ {Libsodiumr_ver} $ {Font_color_suffix}！”
}
Install_Libsodium（）{
	if [[-e $ {Libsodiumr_file}]]; 然后
		echo -e“$ {Error} libsodium已安装，是否覆盖安装（更新）？[y / N]”
		read -e -p“（默认：n）：”yn
		[[-z $ {yn}]] && yn =“n”
		if [[$ {yn} == [Nn]]]; 然后
			echo“已取消......”&&退出1
		科幻
	其他
		echo -e“$ {Info} libsodium未安装，开始安装...”
	科幻
	Check_Libsodium_ver
	if [[$ {release} ==“centos”]]; 然后
		百胜更新
		echo -e“$ {Info}安装依赖......”
		yum -y groupinstall“开发工具”
		echo -e“$ {Info}下载......”
		wget --no-check-certificate -N“https://github.com/jedisct1/libsodium/releases/download/${Libsodiumr_ver}/libsodium-${Libsodiumr_ver}.tar.gz”
		echo -e“$ {Info}解压......”
		tar -xzf libsodium  -  $ {Libsodiumr_ver} .tar.gz && cd libsodium  -  $ {Libsodiumr_ver}
		echo -e“$ {Info}编译安装......”
		./configure --disable-maintainer-mode && make -j2 && make install
		echo / usr / local / lib> /etc/ld.so.conf.d/usr_local_lib.conf
	其他
		apt-get update
		echo -e“$ {Info}安装依赖......”
		apt-get install -y build-essential
		echo -e“$ {Info}下载......”
		wget --no-check-certificate -N“https://github.com/jedisct1/libsodium/releases/download/${Libsodiumr_ver}/libsodium-${Libsodiumr_ver}.tar.gz”
		echo -e“$ {Info}解压......”
		tar -xzf libsodium  -  $ {Libsodiumr_ver} .tar.gz && cd libsodium  -  $ {Libsodiumr_ver}
		echo -e“$ {Info}编译安装......”
		./configure --disable-maintainer-mode && make -j2 && make install
	科幻
	LDCONFIG
	cd .. && rm -rf libsodium  -  $ {Libsodiumr_ver} .tar.gz && rm -rf libsodium  -  $ {Libsodiumr_ver}
	[[！-e $ {Libsodiumr_file}]] && echo -e“$ {Error} libsodium安装失败！” &&退出1
	echo && echo -e“$ {Info} libsodium安装成功！” && echo
}
＃显示连接信息
debian_View_user_connection_info（）{
	format_1 = $ 1
	if [[-z“$ {now_mode}”]]; 然后
		now_mode =“单端口”&& user_total =“1”
		IP_total =`netstat -anp | grep'ESTABLISHED'| grep'python'| grep'tcp6'| awk'{print $ 5}'| awk -F“：”'{print $ 1}'| sort -u | grep -E -o“（[0-9] {1,3} [\。]）{3} [0-9] {1,3}”| wc -l`
		user_port =`$ {jq_file}'。server_port'$ {config_user_file}`
		user_IP_1 =`netstat -anp | grep'ESTABLISHED'| grep'python'| grep'tcp6'| grep“：$ {user_port}”| awk'{print $ 5}'| awk -F“：”'{print $ 1} '| sort -u | grep -E -o“（[0-9] {1,3} [\。]）{3} [0-9] {1,3}”`
		if [[-z $ {user_IP_1}]]; 然后
			user_IP_total = “0”
		其他
			user_IP_total =`echo -e“$ {user_IP_1}”| wc -l`
			if [[$ {format_1} ==“IP_address”]]; 然后
				get_IP_address
			其他
				user_IP =`echo -e“\ n $ {user_IP_1}”`
			科幻
		科幻
		user_list_all =“端口：$ {Green_font_prefix}”$ {user_port}“$ {Font_color_suffix} \ t链接IP总数：$ {Green_font_prefix}”$ {user_IP_total}“$ {Font_color_suffix} \ t当前链接IP：$ {Green_font_prefix} $ {user_IP} $ {Font_color_suffix} \ n”
		user_IP = “”
		echo -e“当前模式：$ {Green_background_prefix}”$ {now_mode}“$ {Font_color_suffix}链接IP总数：$ {Green_background_prefix}”$ {IP_total}“$ {Font_color_suffix}”
		echo -e“$ {user_list_all}”
	其他
		now_mode =“多端口”&& user_total =`$ {jq_file}'。port_password'$ {config_user_file} | sed'$ d; 1d'| wc -l`
		IP_total =`netstat -anp | grep'ESTABLISHED'| grep'python'| grep'tcp6'| awk'{print $ 5}'| awk -F“：”'{print $ 1}'| sort -u | grep -E -o“（[0-9] {1,3} [\。]）{3} [0-9] {1,3}”| wc -l`
		user_list_all = “”
		for（（integer = $ {user_total}; integer> = 1; integer--））
		做
			user_port =`$ {jq_file}'。port_password'$ {config_user_file} | sed'$ d; 1d'| awk -F“：”'{print $ 1}'| sed -n“$ {integer} p”| sed  - r's /.* \“（。+）\”。* / \ 1 /'`
			user_IP_1 =`netstat -anp | grep'ESTABLISHED'| grep'python'| grep'tcp6'| grep“$ {user_port}”| awk'{print $ 5}'| awk -F“：”'{print $ 1}' | sort -u | grep -E -o“（[0-9] {1,3} [\。]）{3} [0-9] {1,3}”`
			if [[-z $ {user_IP_1}]]; 然后
				user_IP_total = “0”
			其他
				user_IP_total =`echo -e“$ {user_IP_1}”| wc -l`
				if [[$ {format_1} ==“IP_address”]]; 然后
					get_IP_address
				其他
					user_IP =`echo -e“\ n $ {user_IP_1}”`
				科幻
			科幻
			user_list_all = $ {user_list_all}“端口：$ {Green_font_prefix}”$ {user_port}“$ {Font_color_suffix} \ t链接IP总数：$ {Green_font_prefix}”$ {user_IP_total}“$ {Font_color_suffix} \ t当前链接IP：$ {Green_font_prefix} $ {user_IP} $ {Font_color_suffix} \ n”
			user_IP = “”
		DONE
		echo -e“当前模式：$ {Green_background_prefix}”$ {now_mode}“$ {Font_color_suffix}用户总数：$ {Green_background_prefix}”$ {user_total}“$ {Font_color_suffix}链接IP总数：$ {Green_background_prefix}”$ {IP_total }“$ {Font_color_suffix}”
		echo -e“$ {user_list_all}”
	科幻
}
centos_View_user_connection_info（）{
	format_1 = $ 1
	if [[-z“$ {now_mode}”]]; 然后
		now_mode =“单端口”&& user_total =“1”
		IP_total =`netstat -anp | grep'ESTABLISHED'| grep'python'| grep'tcp'| grep':: ffff：'| awk'{print $ 5}'| awk -F“：”'{print $ 4}' | sort -u | grep -E -o“（[0-9] {1,3} [\。]）{3} [0-9] {1,3}”| wc -l`
		user_port =`$ {jq_file}'。server_port'$ {config_user_file}`
		user_IP_1 =`netstat -anp | grep'ESTABLISHED'| grep'python'| grep'tcp'| grep“：$ {user_port}”| grep':: ffff：'| awk'{print $ 5}'| awk -F“：”'{print $ 4}'| sort -u | grep -E -o“（[0-9] {1,3} [\。]）{3} [0-9] {1,3}“`
		if [[-z $ {user_IP_1}]]; 然后
			user_IP_total = “0”
		其他
			user_IP_total =`echo -e“$ {user_IP_1}”| wc -l`
			if [[$ {format_1} ==“IP_address”]]; 然后
				get_IP_address
			其他
				user_IP =`echo -e“\ n $ {user_IP_1}”`
			科幻
		科幻
		user_list_all =“端口：$ {Green_font_prefix}”$ {user_port}“$ {Font_color_suffix} \ t链接IP总数：$ {Green_font_prefix}”$ {user_IP_total}“$ {Font_color_suffix} \ t当前链接IP：$ {Green_font_prefix} $ {user_IP} $ {Font_color_suffix} \ n”
		user_IP = “”
		echo -e“当前模式：$ {Green_background_prefix}”$ {now_mode}“$ {Font_color_suffix}链接IP总数：$ {Green_background_prefix}”$ {IP_total}“$ {Font_color_suffix}”
		echo -e“$ {user_list_all}”
	其他
		now_mode =“多端口”&& user_total =`$ {jq_file}'。port_password'$ {config_user_file} | sed'$ d; 1d'| wc -l`
		IP_total =`netstat -anp | grep'ESTABLISHED'| grep'python'| grep'tcp'| grep':: ffff：'| awk'{print $ 5}'| awk -F“：”'{print $ 4}'| sort -u | grep -E -o“（[0-9] {1,3} [\。]）{3} [0-9] {1,3}“| wc -l`
		user_list_all = “”
		for（（integer = 1; integer <= $ {user_total}; integer ++））
		做
			user_port =`$ {jq_file}'。port_password'$ {config_user_file} | sed'$ d; 1d'| awk -F“：”'{print $ 1}'| sed -n“$ {integer} p”| sed  - r's /.* \“（。+）\”。* / \ 1 /'`
			user_IP_1 =`netstat -anp | grep'ESTABLISHED'| grep'python'| grep'tcp'| grep“$ {user_port}”| grep':: ffff：'| awk'{print $ 5}'| awk -F“ ：“'{print $ 4}'| sort -u | grep -E -o”（[0-9] {1,3} [\。]）{3} [0-9] {1,3}“`
			if [[-z $ {user_IP_1}]]; 然后
				user_IP_total = “0”
			其他
				user_IP_total =`echo -e“$ {user_IP_1}”| wc -l`
				if [[$ {format_1} ==“IP_address”]]; 然后
					get_IP_address
				其他
					user_IP =`echo -e“\ n $ {user_IP_1}”`
				科幻
			科幻
			user_list_all = $ {user_list_all}“端口：$ {Green_font_prefix}”$ {user_port}“$ {Font_color_suffix} \ t链接IP总数：$ {Green_font_prefix}”$ {user_IP_total}“$ {Font_color_suffix} \ t当前链接IP：$ {Green_font_prefix} $ {user_IP} $ {Font_color_suffix} \ n”
			user_IP = “”
		DONE
		echo -e“当前模式：$ {Green_background_prefix}”$ {now_mode}“$ {Font_color_suffix}用户总数：$ {Green_background_prefix}”$ {user_total}“$ {Font_color_suffix}链接IP总数：$ {Green_background_prefix}”$ {IP_total }“$ {Font_color_suffix}”
		echo -e“$ {user_list_all}”
	科幻
}
View_user_connection_info（）{
	SSR_installation_status
	echo && echo -e“请选择要显示的格式：
 $ {Green_font_prefix} 1. $ {Font_color_suffix}显示IP格式
 $ {Green_font_prefix} 2. $ {Font_color_suffix}显示IP + IP归属地格式“&& echo
	read -e -p“（默认：1）：”ssr_connection_info
	[[-z“$ {ssr_connection_info}”]] && ssr_connection_info =“1”
	if [[$ {ssr_connection_info} ==“1”]]; 然后
		View_user_connection_info_1“”
	elif [[$ {ssr_connection_info} ==“2”]]; 然后
		echo -e“$ {Tip}检测IP归属地（ipip.net），如果IP较多，可能时间会比较长...”
		View_user_connection_info_1“IP_address”
	其他
		echo -e“$ {Error}请输入正确的数字（1-2）”&&退出1
	科幻
}
View_user_connection_info_1（）{
	格式= $ 1
	如果[[$ {release} =“centos”]]; 然后
		cat / etc / redhat-release | grep 7 \ .. * | grep -i centos> / dev / null
		如果[[$？= 0]]; 然后
			debian_View_user_connection_info“$ format”
		其他
			centos_View_user_connection_info“$ format”
		科幻
	其他
		debian_View_user_connection_info“$ format”
	科幻
}
get_IP_address（）{
	#echo“user_IP_1 = $ {user_IP_1}”
	如果[[！-z $ {user_IP_1}]]; 然后
	#echo“user_IP_total = $ {user_IP_total}”
		for（（integer_1 = $ {user_IP_total}; integer_1> = 1; integer_1--））
		做
			IP =`echo“$ {user_IP_1}”| sed -n“$ integer_1”p`
			#echo“IP = $ {IP}”
			IP_address =`wget -qO- -t1 -T2 http://freeapi.ipip.net/${IP}|sed's's/ \“// g; s /，// g; s / \ [// g ; S / \] // g'`
			#echo“IP_address = $ {IP_address}”
			user_IP = “$ {user_IP} \ N $ {IP}（$ {IP_地址}）”
			#echo“user_IP = $ {user_IP}”
			睡1s
		DONE
	科幻
}
＃修改用户配置
Modify_Config（）{
	SSR_installation_status
	if [[-z“$ {now_mode}”]]; 然后
		echo && echo -e“当前模式：单端口，你要做什么？
 $ {Green_font_prefix} 1. $ {Font_color_suffix}修改用户端口
 $ {Green_font_prefix} 2. $ {Font_color_suffix}修改用户密码
 $ {Green_font_prefix} 3. $ {Font_color_suffix}修改加密方式
 $ {Green_font_prefix} 4. $ {Font_color_suffix}修改协议插件
 $ {Green_font_prefix} 5. $ {Font_color_suffix}修改混淆插件
 $ {Green_font_prefix} 6. $ {Font_color_suffix}修改设备数限制
 $ {Green_font_prefix} 7. $ {Font_color_suffix}修改单线程限速
 $ {Green_font_prefix} 8. $ {Font_color_suffix}修改端口总限速
 $ {Green_font_prefix} 9. $ {Font_color_suffix}修改全部配置“&& echo
		read -e -p“（默认：取消）：”ssr_modify
		[[-z“$ {ssr_modify}”]] && echo“已取消......”&&退出1
		GET_USER
		如果[[$ {ssr_modify} ==“1”]]; 然后
			Set_config_port
			Modify_config_port
			Add_iptables
			Del_iptables
			Save_iptables
		elif [[$ {ssr_modify} ==“2”]]; 然后
			Set_config_password
			Modify_config_password
		elif [[$ {ssr_modify} ==“3”]]; 然后
			Set_config_method
			Modify_config_method
		elif [[$ {ssr_modify} ==“4”]]; 然后
			Set_config_protocol
			Modify_config_protocol
		elif [[$ {ssr_modify} ==“5”]]; 然后
			Set_config_obfs
			Modify_config_obfs
		elif [[$ {ssr_modify} ==“6”]]; 然后
			Set_config_protocol_param
			Modify_config_protocol_param
		elif [[$ {ssr_modify} ==“7”]]; 然后
			Set_config_speed_limit_per_con
			Modify_config_speed_limit_per_con
		elif [[$ {ssr_modify} ==“8”]]; 然后
			Set_config_speed_limit_per_user
			Modify_config_speed_limit_per_user
		elif [[$ {ssr_modify} ==“9”]]; 然后
			Set_config_all
			Modify_config_all
		其他
			echo -e“$ {Error}请输入正确的数字（1-9）”&&退出1
		科幻
	其他
		echo && echo -e“当前模式：多端口，你要做什么？
 $ {Green_font_prefix} 1. $ {Font_color_suffix}添加用户配置
 $ {Green_font_prefix} 2. $ {Font_color_suffix}删除用户配置
 $ {Green_font_prefix} 3. $ {Font_color_suffix}修改用户配置
----------
 $ {Green_font_prefix} 4. $ {Font_color_suffix}修改加密方式
 $ {Green_font_prefix} 5. $ {Font_color_suffix}修改协议插件
 $ {Green_font_prefix} 6. $ {Font_color_suffix}修改混淆插件
 $ {Green_font_prefix} 7. $ {Font_color_suffix}修改设备数限制
 $ {Green_font_prefix} 8. $ {Font_color_suffix}修改单线程限速
 $ {Green_font_prefix} 9. $ {Font_color_suffix}修改端口总限速
 $ {Green_font_prefix} 10. $ {Font_color_suffix}修改全部配置“&& echo
		read -e -p“（默认：取消）：”ssr_modify
		[[-z“$ {ssr_modify}”]] && echo“已取消......”&&退出1
		GET_USER
		如果[[$ {ssr_modify} ==“1”]]; 然后
			Add_multi_port_user
		elif [[$ {ssr_modify} ==“2”]]; 然后
			Del_multi_port_user
		elif [[$ {ssr_modify} ==“3”]]; 然后
			Modify_multi_port_user
		elif [[$ {ssr_modify} ==“4”]]; 然后
			Set_config_method
			Modify_config_method
		elif [[$ {ssr_modify} ==“5”]]; 然后
			Set_config_protocol
			Modify_config_protocol
		elif [[$ {ssr_modify} ==“6”]]; 然后
			Set_config_obfs
			Modify_config_obfs
		elif [[$ {ssr_modify} ==“7”]]; 然后
			Set_config_protocol_param
			Modify_config_protocol_param
		elif [[$ {ssr_modify} ==“8”]]; 然后
			Set_config_speed_limit_per_con
			Modify_config_speed_limit_per_con
		elif [[$ {ssr_modify} ==“9”]]; 然后
			Set_config_speed_limit_per_user
			Modify_config_speed_limit_per_user
		elif [[$ {ssr_modify} ==“10”]]; 然后
			Set_config_method
			Set_config_protocol
			Set_config_obfs
			Set_config_protocol_param
			Set_config_speed_limit_per_con
			Set_config_speed_limit_per_user
			Modify_config_method
			Modify_config_protocol
			Modify_config_obfs
			Modify_config_protocol_param
			Modify_config_speed_limit_per_con
			Modify_config_speed_limit_per_user
		其他
			echo -e“$ {Error}请输入正确的数字（1-9）”&&退出1
		科幻
	科幻
	Restart_SSR
}
＃显示多端口用户配置
List_multi_port_user（）{
	user_total =`$ {jq_file}'。port_password'$ {config_user_file} | sed'$ d'| sed“1d”| wc -l`
	[[$ {user_total} =“0”]] && echo -e“$ {Error}没有发现多端口用户，请检查！” &&退出1
	user_list_all = “”
	for（（integer = $ {user_total}; integer> = 1; integer--））
	做
		user_port =`$ {jq_file}'。port_password'$ {config_user_file} | sed'$ d'| sed“1d”| awk -F“：”'{print $ 1}'| sed -n“$ {integer} p”| sed -r's /.* \“（。+）\”。* / \ 1 /'`
		user_password =`$ {jq_file}'。port_password'$ {config_user_file} | sed'$ d'| sed“1d”| awk -F“：”'{print $ 2}'| sed -n“$ {integer} p”| sed -r's /.* \“（。+）\”。* / \ 1 /'`
		user_list_all = $ {user_list_all}“端口：”$ {user_port}“密码：”$ {user_password}“\ n”
	DONE
	echo && echo -e“用户总数$ {Green_font_prefix}”$ {user_total}“$ {Font_color_suffix}”
	echo -e $ {user_list_all}
}
＃添加多端口用户配置
Add_multi_port_user（）{
	Set_config_port
	Set_config_password
	sed -i“8 i \”\“$ {ssr_port} \”：\“$ {ssr_password} \”，“$ {config_user_file}
	sed -i“8s / ^ \”//“$ {config_user_file}
	Add_iptables
	Save_iptables
	echo -e“$ {Info}多端口用户添加完成$ {Green_font_prefix} [端口：$ {ssr_port}，密码：$ {ssr_password}] $ {Font_color_suffix}”
}
＃修改多端口用户配置
Modify_multi_port_user（）{
	List_multi_port_user
	echo && echo -e“请输入要修改的用户端口”
	read -e -p“（默认：取消）：”modify_user_port
	[[-z“$ {modify_user_port}”]] && echo -e“已取消......”&&退出1
	del_user =`cat $ {config_user_file} | grep'“'”$ {modify_user_port}“'”'`
	如果[[！-z“$ {del_user}”]]; 然后
		端口= “$ {} modify_user_port”
		password =`echo -e $ {del_user} | awk -F“：”'{print $ NF}'| sed -r's /.* \“（。+）\”。* / \ 1 /'`
		Set_config_port
		Set_config_password
		sed -i's /“'$（echo $ {port}）'”：“'$（echo $ {password}）'”/“'$（echo $ {ssr_port}）'”：“'$ $（echo $ {ssr_password}）'“/ g'$ {config_user_file}
		Del_iptables
		Add_iptables
		Save_iptables
		echo -e“$ {Inof}多端口用户修改完成$ {Green_font_prefix} [旧：$ {modify_user_port} $ {密码}，新：$ {ssr_port} $ {ssr_password}] $ {Font_color_suffix}”
	其他
		echo -e“$ {Error}请输入正确的端口！” &&退出1
	科幻
}
＃删除多端口用户配置
Del_multi_port_user（）{
	List_multi_port_user
	user_total =`$ {jq_file}'。port_password'$ {config_user_file} | sed'$ d'| sed“1d”| wc -l`
	[[“$ {user_total}”=“1”]] && echo -e“$ {错误}多端口用户仅剩1个，不能删除！” &&退出1
	echo -e“请输入要删除的用户端口”
	read -e -p“（默认：取消）：”del_user_port
	[[-z“$ {del_user_port}”]] && echo -e“已取消......”&&退出1
	del_user =`cat $ {config_user_file} | grep'“'”$ {del_user_port}“'”'`
	如果[[！-z $ {del_user}]]; 然后
		端口= $ {} del_user_port
		Del_iptables
		Save_iptables
		del_user_determine =`echo $ {del_user：（（$ {#del_user}  -  1））}`
		if [[$ {del_user_determine}！=“，”]]; 然后
			del_user_num = $（sed -n -e“/ $ {port} / =”$ {config_user_file}）
			echo $（（$ {ssr_protocol_param} +0））＆> / dev / null
			del_user_num = $（echo $（（$ {del_user_num} -1）））
			sed -i“$ {del_user_num} s /，// g”$ {config_user_file}
		科幻
		sed -i“/ $ {port} / d”$ {config_user_file}
		echo -e“$ {Info}多端口用户删除完成$ {Green_font_prefix} $ {del_user_port} $ {Font_color_suffix}”
	其他
		echo“$ {Error}请输入正确的端口！” &&退出1
	科幻
}
＃手动修改用户配置
Manually_Modify_Config（）{
	SSR_installation_status
	port =`$ {jq_file}'。server_port'$ {config_user_file}`
	vi $ {config_user_file}
	if [[-z“$ {now_mode}”]]; 然后
		ssr_port =`$ {jq_file}'。server_port'$ {config_user_file}`
		Del_iptables
		Add_iptables
	科幻
	Restart_SSR
}
＃切换端口模式
Port_mode_switching（）{
	SSR_installation_status
	if [[-z“$ {now_mode}”]]; 然后
		echo && echo -e“当前模式：$ {Green_font_prefix}单端口$ {Font_color_suffix}”&& echo
		echo -e“确定要切换为多端口模式？[y / N]”
		read -e -p“（默认：n）：”mode_yn
		[[-z $ {mode_yn}]] && mode_yn =“n”
		if [[$ {mode_yn} == [Yy]]]; 然后
			port =`$ {jq_file}'。server_port'$ {config_user_file}`
			Set_config_all
			Write_configuration_many
			Del_iptables
			Add_iptables
			Save_iptables
			Restart_SSR
		其他
			echo && echo“已取消......”&& echo
		科幻
	其他
		echo && echo -e“当前模式：$ {Green_font_prefix}多端口$ {Font_color_suffix}”&& echo
		echo -e“确定要切换为单端口模式？[y / N]”
		read -e -p“（默认：n）：”mode_yn
		[[-z $ {mode_yn}]] && mode_yn =“n”
		if [[$ {mode_yn} == [Yy]]]; 然后
			user_total =`$ {jq_file}'。port_password'$ {config_user_file} | sed'$ d'| sed“1d”| wc -l`
			for（（integer = 1; integer <= $ {user_total}; integer ++））
			做
				port =`$ {jq_file}'。port_password'$ {config_user_file} | sed'$ d'| sed“1d”| awk -F“：”'{print $ 1}'| sed -n“$ {integer} p”| sed -r's /.* \“（。+）\”。* / \ 1 /'`
				Del_iptables
			DONE
			Set_config_all
			Write_configuration
			Add_iptables
			Restart_SSR
		其他
			echo && echo“已取消......”&& echo
		科幻
	科幻
}
Start_SSR（）{
	SSR_installation_status
	check_pid
	[[！-z $ {PID}]] && echo -e“$ {Error} ShadowsocksR正在运行！” &&退出1
	/etc/init.d/ssr start
	check_pid
	[[！-z $ {PID}]] && View_User
}
Stop_SSR（）{
	SSR_installation_status
	check_pid
	[[-z $ {PID}]] && echo -e“$ {Error} ShadowsocksR未运行！” &&退出1
	/etc/init.d/ssr停止
}
Restart_SSR（）{
	SSR_installation_status
	check_pid
	[[！-z $ {PID}]] && /etc/init.d/ssr stop
	/etc/init.d/ssr start
	check_pid
	[[！-z $ {PID}]] && View_User
}
查看日志（）{
	SSR_installation_status
	[[！-e $ {ssr_log_file}]] && echo -e“$ {Error} ShadowsocksR日志文件不存在！” &&退出1
	echo && echo -e“$ {Tip}按$ {Red_font_prefix} Ctrl + C $ {Font_color_suffix}终止查看日志”&& echo -e“如果需要查看完整日志内容，请用$ {Red_font_prefix} cat $ {ssr_log_file} $ {Font_color_suffix}命令。“&& echo
	tail -f $ {ssr_log_file}
}
＃锐速
Configure_Server_Speeder（）{
	echo && echo -e“你要做什么？
 $ {Green_font_prefix} 1. $ {Font_color_suffix}安装锐速
 $ {Green_font_prefix} 2. $ {Font_color_suffix}卸载锐速
--------
 $ {Green_font_prefix} 3. $ {Font_color_suffix}启动锐速
 $ {Green_font_prefix} 4. $ {Font_color_suffix}停止锐速
 $ {Green_font_prefix} 5. $ {Font_color_suffix}重启锐速
 $ {Green_font_prefix} 6. $ {Font_color_suffix}查看锐速状态
 
 注意：锐速和LotServer不能同时安装/启动！“&& echo
	read -e -p“（默认：取消）：”server_speeder_num
	[[-z“$ {server_speeder_num}”]] && echo“已取消......”&&退出1
	if [[$ {server_speeder_num} ==“1”]]; 然后
		Install_ServerSpeeder
	elif [[$ {server_speeder_num} ==“2”]]; 然后
		Server_Speeder_installation_status
		Uninstall_ServerSpeeder
	elif [[$ {server_speeder_num} ==“3”]]; 然后
		Server_Speeder_installation_status
		$ {Server_Speeder_file}开始
		$ {Server_Speeder_file}状态
	elif [[$ {server_speeder_num} ==“4”]]; 然后
		Server_Speeder_installation_status
		$ {Server_Speeder_file}停止
	elif [[$ {server_speeder_num} ==“5”]]; 然后
		Server_Speeder_installation_status
		$ {Server_Speeder_file}重新启动
		$ {Server_Speeder_file}状态
	elif [[$ {server_speeder_num} ==“6”]]; 然后
		Server_Speeder_installation_status
		$ {Server_Speeder_file}状态
	其他
		echo -e“$ {Error}请输入正确的数字（1-6）”&&退出1
	科幻
}
Install_ServerSpeeder（）{
	[[-e $ {Server_Speeder_file}]] && echo -e“$ {Error}锐速（Server Speeder）已安装！” &&退出1
	cd / root
	＃借用91yun.rog的开心版锐速
	wget -N --no-check-certificate https://raw.githubusercontent.com/91yun/serverspeeder/master/serverspeeder.sh
	[[！-e“serverspeeder.sh”]] && echo -e“$ {Error}锐速安装脚本下载失败！” &&退出1
	bash serverspeeder.sh
	睡2s
	PID =`ps -ef | grep -v grep | grep“serverspeeder”| awk'{print $ 2}'`
	如果[[！-z $ {PID}]]; 然后
		rm -rf /root/serverspeeder.sh
		rm -rf / root / 91yunserverspeeder
		rm -rf /root/91yunserverspeeder.tar.gz
		echo -e“$ {Info}锐速（Server Speeder）安装完成！” &&退出1
	其他
		echo -e“$ {Error}锐速（Server Speeder）安装失败！” &&退出1
	科幻
}
Uninstall_ServerSpeeder（）{
	echo“确定要卸载锐速（Server Speeder）？[y / N]”&& echo
	read -e -p“（默认：n）：”unyn
	[[-z $ {unyn}]] && echo && echo“已取消...”&&退出1
	如果[[$ {unyn} == [Yy]]]; 然后
		chattr -i / serverspeeder / etc / apx *
		/serverspeeder/bin/serverSpeeder.sh uninstall -f
		echo && echo“锐速（Server Speeder）卸载完成！” && echo
	科幻
}
#LotServer
Configure_LotServer（）{
	echo && echo -e“你要做什么？
 $ {Green_font_prefix} 1. $ {Font_color_suffix}安装LotServer
 $ {Green_font_prefix} 2. $ {Font_color_suffix}卸载LotServer
--------
 $ {Green_font_prefix} 3. $ {Font_color_suffix}启动LotServer
 $ {Green_font_prefix} 4. $ {Font_color_suffix}停止LotServer
 $ {Green_font_prefix} 5. $ {Font_color_suffix}重启LotServer
 $ {Green_font_prefix} 6. $ {Font_color_suffix}查看LotServer状态
 
 注意：锐速和LotServer不能同时安装/启动！“&& echo
	read -e -p“（默认：取消）：”lotserver_num
	[[-z“$ {lotserver_num}”]] && echo“已取消......”&&退出1
	if [[$ {lotserver_num} ==“1”]]; 然后
		Install_LotServer
	elif [[$ {lotserver_num} ==“2”]]; 然后
		LotServer_installation_status
		Uninstall_LotServer
	elif [[$ {lotserver_num} ==“3”]]; 然后
		LotServer_installation_status
		$ {LotServer_file}开始
		$ {LotServer_file}状态
	elif [[$ {lotserver_num} ==“4”]]; 然后
		LotServer_installation_status
		$ {LotServer_file}停止
	elif [[$ {lotserver_num} ==“5”]]; 然后
		LotServer_installation_status
		$ {LotServer_file}重启
		$ {LotServer_file}状态
	elif [[$ {lotserver_num} ==“6”]]; 然后
		LotServer_installation_status
		$ {LotServer_file}状态
	其他
		echo -e“$ {Error}请输入正确的数字（1-6）”&&退出1
	科幻
}
Install_LotServer（）{
	[[-e $ {LotServer_file}]] && echo -e“$ {Error} LotServer已安装！” &&退出1
	#Github：https：//github.com/0oVicero0/serverSpeeder_Install
	wget --no-check-certificate -qO /tmp/appex.sh“https://raw.githubusercontent.com/0oVicero0/serverSpeeder_Install/master/appex.sh”
	[[！-e“/tmp/appex.sh”]] && echo -e“$ {Error} LotServer安装脚本下载失败！” &&退出1
	bash /tmp/appex.sh'install'
	睡2s
	PID =`ps -ef | grep -v grep | grep“appex”| awk'{print $ 2}'`
	如果[[！-z $ {PID}]]; 然后
		echo -e“$ {Info} LotServer安装完成！” &&退出1
	其他
		echo -e“$ {Error} LotServer安装失败！” &&退出1
	科幻
}
Uninstall_LotServer（）{
	echo“确定要卸载LotServer？[y / N]”&& echo
	read -e -p“（默认：n）：”unyn
	[[-z $ {unyn}]] && echo && echo“已取消...”&&退出1
	如果[[$ {unyn} == [Yy]]]; 然后
		wget --no-check-certificate -qO /tmp/appex.sh“https://raw.githubusercontent.com/0oVicero0/serverSpeeder_Install/master/appex.sh”&& bash /tmp/appex.sh'destall'
		echo && echo“LotServer卸载完成！” && echo
	科幻
}
#BBR
Configure_BBR（）{
	echo && echo -e“你要做什么？
	
 $ {Green_font_prefix} 1. $ {Font_color_suffix}安装BBR
--------
 $ {Green_font_prefix} 2. $ {Font_color_suffix}启动BBR
 $ {Green_font_prefix} 3. $ {Font_color_suffix}停止BBR
 $ {Green_font_prefix} 4. $ {Font_color_suffix}查看BBR状态“&& echo
echo -e“$ {Green_font_prefix} [安装前请注意] $ {Font_color_suffix}
1.安装开启BBR，需要更换内核，存在更换失败等风险（重启后无法开机）
2.本脚本仅支持Debian / Ubuntu系统更换内核，OpenVZ和Docker不支持更换内核
3. Debian更换内核过程中会提示[是否终止卸载内核]，请选择$ {Green_font_prefix} NO $ {Font_color_suffix}“&& echo
	read -e -p“（默认：取消）：”bbr_num
	[[-z“$ {bbr_num}”]] && echo“已取消......”&&退出1
	如果[[$ {bbr_num} ==“1”]]; 然后
		Install_BBR
	elif [[$ {bbr_num} ==“2”]]; 然后
		Start_BBR
	elif [[$ {bbr_num} ==“3”]]; 然后
		Stop_BBR
	elif [[$ {bbr_num} ==“4”]]; 然后
		Status_BBR
	其他
		echo -e“$ {Error}请输入正确的数字（1-4）”&&退出1
	科幻
}
Install_BBR（）{
	[[$ {release} =“centos”]] && echo -e“$ {Error}本脚本不支持CentOS系统安装BBR！” &&退出1
	BBR_installation_status
	bash“$ {BBR_file}”
}
Start_BBR（）{
	BBR_installation_status
	bash“$ {BBR_file}”开始
}
Stop_BBR（）{
	BBR_installation_status
	bash“$ {BBR_file}”停止
}
Status_BBR（）{
	BBR_installation_status
	bash“$ {BBR_file}”状态
}
＃其他功能
Other_functions（）{
	echo && echo -e“你要做什么？
	
  $ {Green_font_prefix} 1. $ {Font_color_suffix}配置BBR
  $ {Green_font_prefix} 2. $ {Font_color_suffix}配置锐速（ServerSpeeder）
  $ {Green_font_prefix} 3. $ {Font_color_suffix}配置LotServer（锐速母公司）
  注意：锐速/ LotServer / BBR不支持OpenVZ！
  注意：锐速/ LotServer / BBR不能共存！
------------
  $ {Green_font_prefix} 4. $ {Font_color_suffix}一键封禁BT / PT / SPAM（iptables）
  $ {Green_font_prefix} 5. $ {Font_color_suffix}一键解封BT / PT / SPAM（iptables）
  $ {Green_font_prefix} 6. $ {Font_color_suffix}切换ShadowsocksR日志输出模式
  - 说明：SSR默认只输出错误日志，此项可切换为输出详细的访问日志“&& echo
	read -e -p“（默认：取消）：”other_num
	[[-z“$ {other_num}”]] && echo“已取消......”&&退出1
	if [[$ {other_num} ==“1”]]; 然后
		Configure_BBR
	elif [[$ {other_num} ==“2”]]; 然后
		Configure_Server_Speeder
	elif [[$ {other_num} ==“3”]]; 然后
		Configure_LotServer
	elif [[$ {other_num} ==“4”]]; 然后
		BanBTPTSPAM
	elif [[$ {other_num} ==“5”]]; 然后
		UnBanBTPTSPAM
	elif [[$ {other_num} ==“6”]]; 然后
		Set_config_connect_verbose_info
	其他
		echo -e“$ {Error}请输入正确的数字[1-6]”&&退出1
	科幻
}
＃封禁BT PT SPAM
BanBTPTSPAM（）{
	wget -N --no-check-certificate https://raw.githubusercontent.com/ToyoDAdoubi/doubi/master/ban_iptables.sh&& chmod + x ban_iptables.sh && bash ban_iptables.sh banall
	rm -rf ban_iptables.sh
}
＃解封BT PT SPAM
UnBanBTPTSPAM（）{
	wget -N --no-check-certificate https://raw.githubusercontent.com/ToyoDAdoubi/doubi/master/ban_iptables.sh&& chmod + x ban_iptables.sh && bash ban_iptables.sh unbanall
	rm -rf ban_iptables.sh
}
Set_config_connect_verbose_info（）{
	SSR_installation_status
	GET_USER
	if [[$ {connect_verbose_info} =“0”]]; 然后
		echo && echo -e“当前日志模式：$ {Green_font_prefix}简单模式（只输出错误日志）$ {Font_color_suffix}”&& echo
		echo -e“确定要切换为$ {Green_font_prefix}详细模式（输出详细连接日志+错误日志）$ {Font_color_suffix}？[y / N]”
		read -e -p“（默认：n）：”connect_verbose_info_ny
		[[-z“$ {connect_verbose_info_ny}”]] && connect_verbose_info_ny =“n”
		if [[$ {connect_verbose_info_ny} == [Yy]]]; 然后
			ssr_connect_verbose_info = “1”
			Modify_config_connect_verbose_info
			Restart_SSR
		其他
			echo && echo“已取消......”&& echo
		科幻
	其他
		echo && echo -e“当前日志模式：$ {Green_font_prefix}详细模式（输出详细连接日志+错误日志）$ {Font_color_suffix}”&& echo
		echo -e“确定要切换为$ {Green_font_prefix}简单模式（只输出错误日志）$ {Font_color_suffix}？[y / N]”
		read -e -p“（默认：n）：”connect_verbose_info_ny
		[[-z“$ {connect_verbose_info_ny}”]] && connect_verbose_info_ny =“n”
		if [[$ {connect_verbose_info_ny} == [Yy]]]; 然后
			ssr_connect_verbose_info = “0”
			Modify_config_connect_verbose_info
			Restart_SSR
		其他
			echo && echo“已取消......”&& echo
		科幻
	科幻
}
Update_Shell（）{
	sh_new_ver = $（wget --no-check-certificate -qO- -t1 -T3“https://raw.githubusercontent.com/ToyoDAdoubi/doubi/master/ssr.sh"|grep'sh_ver =”'| awk  - F“=”'{print $ NF}'| sed's / \“// g'| head -1）&& sh_new_type =”github“
	[[-z $ {sh_new_ver}]] && echo -e“$ {Error}无法链接到Github！” &&退出0
	if [[-e“/etc/init.d/ssr”]]; 然后
		rm -rf /etc/init.d/ssr
		Service_SSR
	科幻
	wget -N --no-check-certificate“https://raw.githubusercontent.com/ToyoDAdoubi/doubi/master/ssr.sh”&& chmod + x ssr.sh
	echo -e“脚本已更新为最新版本[$ {sh_new_ver}]！（注意：因为更新方式为直接覆盖当前运行的脚本，所以可能下面会提示一些报错，无视即可）”&& exit 0
}
＃显示菜单状态
menu_status（）{
	if [[-e $ {config_user_file}]]; 然后
		check_pid
		如果[[！-z“$ {PID}”]]; 然后
			echo -e“当前状态：$ {Green_font_prefix}已安装$ {Font_color_suffix}并$ $ Green_font_prefix}已启动$ {Font_color_suffix}”
		其他
			echo -e“当前状态：$ {Green_font_prefix}已安装$ {Font_color_suffix}但$ {Red_font_prefix}未启动$ {Font_color_suffix}”
		科幻
		now_mode = $（cat“$ {config_user_file}”| grep'“port_password”'）
		if [[-z“$ {now_mode}”]]; 然后
			echo -e“当前模式：$ {Green_font_prefix}单端口$ {Font_color_suffix}”
		其他
			echo -e“当前模式：$ {Green_font_prefix}多端口$ {Font_color_suffix}”
		科幻
	其他
		echo -e“当前状态：$ {Red_font_prefix}未安装$ {Font_color_suffix}”
	科幻
}
check_sys
[[$ {release}！=“debian”]] && [[$ {release}！=“ubuntu”]] && [[$ {release}！=“centos”]] && echo -e“$ {Error}本脚本不支持当前系统$ {release}！“ &&退出1
echo -e“ShadowsocksR一键管理脚本$ {Red_font_prefix} [v $ {sh_ver}] $ {Font_color_suffix}
  ----东洋| doub.io/ss-jc42 ----

  $ {Green_font_prefix} 1. $ {Font_color_suffix}安装ShadowsocksR
  $ {Green_font_prefix} 2. $ {Font_color_suffix}更新ShadowsocksR
  $ {Green_font_prefix} 3. $ {Font_color_suffix}卸载ShadowsocksR
  $ {Green_font_prefix} 4. $ {Font_color_suffix}安装libsodium（chacha20）
------------
  $ {Green_font_prefix} 5. $ {Font_color_suffix}查看账号信息
  $ {Green_font_prefix} 6. $ {Font_color_suffix}显示连接信息
  $ {Green_font_prefix} 7. $ {Font_color_suffix}设置用户配置
  $ {Green_font_prefix} 8. $ {Font_color_suffix}手动修改配置
  $ {Green_font_prefix} 9. $ {Font_color_suffix}切换端口模式
------------
 $ {Green_font_prefix} 10. $ {Font_color_suffix}启动ShadowsocksR
 $ {Green_font_prefix} 11. $ {Font_color_suffix}停止ShadowsocksR
 $ {Green_font_prefix} 12. $ {Font_color_suffix}重启ShadowsocksR
 $ {Green_font_prefix} 13。$ {Font_color_suffix}查看ShadowsocksR日志
------------
 $ {Green_font_prefix} 14. $ {Font_color_suffix}其他功能
 $ {Green_font_prefix} 15. $ {Font_color_suffix}升级脚本
 “
menu_status
echo && read -e -p“请输入数字[1-15]：”num
案例“$ num”in
	1）
	Install_SSR
	;;
	2）
	Update_SSR
	;;
	3）
	Uninstall_SSR
	;;
	4）
	Install_Libsodium
	;;
	5）
	View_User
	;;
	6）
	View_user_connection_info
	;;
	7）
	Modify_Config
	;;
	8）
	Manually_Modify_Config
	;;
	9）
	Port_mode_switching
	;;
	10）
	Start_SSR
	;;
	11）
	Stop_SSR
	;;
	12）
	Restart_SSR
	;;
	13）
	查看日志
	;;
	14）
	Other_functions
	;;
	15）
	Update_Shell
	;;
	*）
	echo -e“$ {Error}请输入正确的数字[1-15]”
	;;
ESAC