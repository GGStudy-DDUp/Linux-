clear
echo ""
echo " ____________________________________________________________________ "
echo "|                                                                    |"
echo "|          Local Information gather Script for Linux                 |"
echo "|                                                                    |"
echo "|____________________________________________________________________|"
echo ""
echo ""

LOG_NAME="Local-Information_"`date +"%Y-%m-%d"`".log"

echo "" > "$LOG_NAME"
echo " ____________________________________________________________________ " >> "$LOG_NAME"
echo "|                                                                    |" >> "$LOG_NAME"
echo "|          Local Information gather Script for Linux                 |" >> "$LOG_NAME"
echo "|                                                                    |" >> "$LOG_NAME"
echo "|____________________________________________________________________|" >> "$LOG_NAME"
echo "" >> "$LOG_NAME"
echo "" >> "$LOG_NAME"
echo `hostname` >> "$LOG_NAME"
echo `uname -s` >> "$LOG_NAME"
echo `ifconfig -a | grep inet|grep -v "127.0.0.1" | awk '{print $2}'| head -n 3` >> "$LOG_NAME"

SSH_V=`openssl version | awk '{print $2}' | awk -F"." '{print $1}'`

passwd_rwx=`ls -la /etc/passwd | awk '{print $1}' | awk -F"." '{print $1}'`
group_rwx=`ls -la /etc/group | awk '{print $1}' | awk -F"." '{print $1}'`
shadow_rwx=`ls -la /etc/shadow | awk '{print $1}' | awk -F"." '{print $1}'`

ser_run=`service --status-all | grep running`

rhost=`find / -name '.rhosts'`
exrc=`find / -name '.exrc'`

sys_log=`ps -ef|grep syslogd`

# /etc/login.defs
PASS_MAX_DAYS=`cat /etc/login.defs | grep -v ^# | grep -v ^$ | grep -i PASS_MAX_DAYS | awk '{ print $2 }'`
PASS_MIN_DAYS=`cat /etc/login.defs | grep -v ^# | grep -v ^$ | grep -i PASS_MIN_DAYS | awk '{ print $2 }'`
PASS_MIN_LEN=`cat /etc/login.defs | grep -v ^# | grep -v ^$ | grep -i PASS_MIN_LEN | awk '{ print $2 }'`
PASS_WARN_AGE=`cat /etc/login.defs | grep -v ^# | grep -v ^$ | grep -i PASS_WARN_AGE | awk '{ print $2 }'`

# /etc/pam.d/system-auth
pam_cracklib=`cat /etc/pam.d/system-auth | grep -v ^# | grep -v ^$ | grep "pam_cracklib.so" | grep "minlen"`
pam_tally=`cat /etc/pam.d/system-auth | grep -v ^# | grep -v ^$ | grep pam_tally | grep deny`

# /etc/passwd
passwd_only=`cat /etc/passwd |awk -F: '{print $1,$3}'|sort -t ' ' -k 2n|uniq -f1 -D`
passwd_bash=`cat /etc/passwd | grep bash`

# /etc/shadow
shadow_p=`cat /etc/shadow | grep -v "\!" | grep -v "*" | awk -F: '$4==0 || $5==99999 {print $1}'`

# /etc/ssh/sshd_config
sshd_config=`cat /etc/ssh/sshd_config | grep -v ^# | grep -v ^$ | grep -i protocol`

# /etc/profile
profile_umask=`cat /etc/profile | grep -v ^# | grep -v " " | grep -v ^$ | grep umask`
profile_timeout=`cat /etc/profile | grep -v ^# | grep -v " " | grep -v ^$ | grep -i timeout`

# /etc/ftpusers
ftpusers=`cat /etc/ftpusers | grep -v ^# | grep -v ^$ | grep root`

# /etc/pam.d/login
login_pam=`cat /etc/pam.d/login | grep -v ^# | grep -v ^$ | grep pam_securetty.so`

# /etc/ssh/sshd_config
sshd_conf=`cat /etc/ssh/sshd_config | grep -v ^# | grep -v ^$ | grep -i PermitRootLogin | awk '{print $2}'`

# /etc/security/console.perms
console_dev=`cat /etc/security/console.perms | grep -v ^# | grep -v ^$`

# /etc/rsyslog.conf
rsyslog_rwx=`ls -la /etc/rsyslog.conf | awk '{print $1}' | awk -F"." '{print $1}'`
echo "######################################################################"
echo ""
echo "1.身份鉴别"
echo "" 
echo "######################################################################"
echo ""
echo "1.1.口令策略设置符合复杂度要求"
echo "######################################################################" >> "$LOG_NAME"
echo ""  >> "$LOG_NAME"
echo "1.身份鉴别" >> "$LOG_NAME"
echo ""  >> "$LOG_NAME"
echo "######################################################################" >> "$LOG_NAME"
echo ""  >> "$LOG_NAME"
echo "1.1.口令策略设置符合复杂度要求" >> "$LOG_NAME"
# 检查/etc/login.defs
if [ "$PASS_MAX_DAYS" -gt 180 ] || [ "$PASS_MIN_DAYS" -eq 0 ] || [ "$PASS_MIN_LEN" -gt 30 ] || [ "$PASS_WARN_AGE" -lt 8 ]
then
    echo "/etc/login.defs配置不合规"
    echo "/etc/login.defs配置不合规" >> "$LOG_NAME"
    echo "cat /etc/login.defs | grep -v ^# | grep -v ^$ | grep -i PASS" >> "$LOG_NAME"
    cat /etc/login.defs | grep -v ^# | grep -v ^$ | grep -i PASS >> "$LOG_NAME"
    echo ""  >> "$LOG_NAME"
fi
# 检查/etc/pam.d/system-auth
if [ "$pam_cracklib" = "" ]
then
    echo "/etc/pam.d/system-auth配置不合规"
    echo "/etc/pam.d/system-auth配置不合规" >> "$LOG_NAME"
    echo "cat /etc/pam.d/system-auth | grep -v ^# | grep -v ^$" >> "$LOG_NAME"
    cat /etc/pam.d/system-auth | grep -v ^# | grep -v ^$ >> "$LOG_NAME"
    echo ""  >> "$LOG_NAME"
fi
# 检查/etc/shadow
if [ "$shadow_p" != "" ]
then
    echo "/etc/shadow配置不合规"
    echo "/etc/shadow配置不合规" >> "$LOG_NAME"
    echo "cat /etc/shadow | grep -v "\!" | grep -v "*"" >> "$LOG_NAME"
    cat /etc/shadow | grep -v "\!" | grep -v "*" >> "$LOG_NAME"
    echo ""  >> "$LOG_NAME"
fi
echo "[OK]" 
echo "[OK]"  >> "$LOG_NAME"
echo ""
echo ""
echo ""  >> "$LOG_NAME"
echo ""  >> "$LOG_NAME"
echo "1.2.启用登录失败处理功能"
echo "1.2.启用登录失败处理功能" >> "$LOG_NAME"
# 检查/etc/pam.d/system-auth
if [ "$pam_tally" = "" ]
then
    echo "/etc/pam.d/system-auth配置不合规"
    echo "/etc/pam.d/system-auth配置不合规" >> "$LOG_NAME"
    echo "cat /etc/pam.d/system-auth | grep -v ^# | grep -v ^$" >> "$LOG_NAME"
    cat /etc/pam.d/system-auth | grep -v ^# | grep -v ^$ >> "$LOG_NAME"
    echo ""  >> "$LOG_NAME"
fi
echo "[OK]" 
echo "[OK]"  >> "$LOG_NAME"
echo ""
echo ""
echo ""  >> "$LOG_NAME"
echo ""  >> "$LOG_NAME"
echo "1.3.安全的远程登录方式"
echo "1.3.安全的远程登录方式" >> "$LOG_NAME"
# 检查/etc/ssh/sshd_config或SSH版本
if [ "$sshd_config" = "" ] || [ "$SSH_V" = "1" ]
then
    echo "安全的远程登录方式配置不合规"
    echo "安全的远程登录方式配置不合规" >> "$LOG_NAME"
    echo "cat /etc/ssh/sshd_config | grep -v ^# | grep -v ^$" >> "$LOG_NAME"
    cat /etc/ssh/sshd_config | grep -v ^# | grep -v ^$ >> "$LOG_NAME"
    echo ""  >> "$LOG_NAME"
    echo "openssl version" >> "$LOG_NAME"
    openssl version >> "$LOG_NAME"
    echo ""  >> "$LOG_NAME"
fi
echo "[OK]" 
echo "[OK]"  >> "$LOG_NAME"
echo ""
echo ""
echo ""  >> "$LOG_NAME"
echo ""  >> "$LOG_NAME"
echo "1.4.操作系统用户名唯一"
echo "1.4.操作系统用户名唯一" >> "$LOG_NAME"

# 检查/etc/passwd
if [ ! "$passwd_only" = "" ]
then
    echo "操作系统用户名不唯一"
    echo "操作系统用户名不唯一" >> "$LOG_NAME"
    echo "cat /etc/passwd |awk -F: '{print $1,$3}'|sort -t ' ' -k 2n|uniq -f1 -D" >> "$LOG_NAME"
    cat /etc/passwd |awk -F: '{print $1,$3}'|sort -t ' ' -k 2n|uniq -f1 -D >> "$LOG_NAME"
    echo ""  >> "$LOG_NAME"
fi
echo "[OK]" 
echo "[OK]"  >> "$LOG_NAME"
echo ""
echo ""
echo ""  >> "$LOG_NAME"
echo ""  >> "$LOG_NAME"
echo "######################################################################"
echo ""
echo "2.访问控制"
echo ""
echo "######################################################################"
echo ""
echo "2.1.启用目录访问控制功能"
echo "######################################################################" >> "$LOG_NAME"
echo ""  >> "$LOG_NAME"
echo "2.访问控制" >> "$LOG_NAME"
echo ""  >> "$LOG_NAME"
echo "######################################################################" >> "$LOG_NAME"
echo ""  >> "$LOG_NAME"
echo "2.1.启用目录访问控制功能" >> "$LOG_NAME"
# 检查/etc/profile
if [ "$profile_umask" = "" ]
then
    echo "/etc/profile配置不合规"
    echo "/etc/profile配置不合规" >> "$LOG_NAME"
    echo "cat /etc/profile | grep -v ^# | grep -v ^$" >> "$LOG_NAME"
    cat /etc/profile | grep -v ^# | grep -v ^$ >> "$LOG_NAME"
    echo ""  >> "$LOG_NAME"
fi
if [ "$passwd_rwx" != "-rw-r--r--" ] || [ "$group_rwx" != "-rw-r--r--" ] || [ "$shadow_rwx" != "-r--------" ]
then
    echo "文件和目录的权限不合规"
    echo "文件和目录的权限不合规" >> "$LOG_NAME"
    echo "ls -la /etc/passwd" >> "$LOG_NAME"
    ls -la /etc/passwd >> "$LOG_NAME"
    echo ""  >> "$LOG_NAME"
    echo "ls -la /etc/group" >> "$LOG_NAME"
    ls -la /etc/group >> "$LOG_NAME"
    echo ""  >> "$LOG_NAME"
    echo "ls -la /etc/shadow" >> "$LOG_NAME"
    ls -la /etc/shadow >> "$LOG_NAME"
    echo ""  >> "$LOG_NAME"
fi
echo "[OK]" 
echo "[OK]"  >> "$LOG_NAME"
echo ""
echo ""
echo ""  >> "$LOG_NAME"
echo ""  >> "$LOG_NAME"
echo "2.2.启用服务访问控制功能"
echo "2.2.启用服务访问控制功能" >> "$LOG_NAME"
# 检查服务
if [ "$ser_run" != "" ]
then
    echo "详情请看日志"
    echo "详情请看日志" >> "$LOG_NAME"
    echo "service --status-all | grep running" >> "$LOG_NAME"
    service --status-all | grep running >> "$LOG_NAME"
    echo ""  >> "$LOG_NAME"
fi
echo "[OK]" 
echo "[OK]"  >> "$LOG_NAME"
echo ""
echo ""
echo ""  >> "$LOG_NAME"
echo ""  >> "$LOG_NAME"
echo "2.3.限制默认账号权限"
echo "2.3.限制默认账号权限" >> "$LOG_NAME"
# 检查账户名及密码
echo "请咨询管理员"
echo "要求：应重命名系统默认账户（可选）；修改默认账户的默认口令。"
echo "请咨询管理员" >> "$LOG_NAME"
echo "要求：应重命名系统默认账户（可选）；修改默认账户的默认口令。" >> "$LOG_NAME"
echo ""  >> "$LOG_NAME"
echo "[OK]" 
echo "[OK]"  >> "$LOG_NAME"
echo ""
echo ""
echo ""  >> "$LOG_NAME"
echo ""  >> "$LOG_NAME"
echo "2.4.删除或禁用不必要的用户"
echo "2.4.删除或禁用不必要的用户" >> "$LOG_NAME"
# 检查/etc/passwd
if [ "$passwd_bash" != "" ]
then
    echo "详情请看日志"
    echo "详情请看日志" >> "$LOG_NAME"
    echo "cat /etc/passwd | grep bash" >> "$LOG_NAME"
    cat /etc/passwd | grep bash >> "$LOG_NAME"
    echo ""  >> "$LOG_NAME"
fi
echo "[OK]" 
echo "[OK]"  >> "$LOG_NAME"
echo ""
echo ""
echo ""  >> "$LOG_NAME"
echo ""  >> "$LOG_NAME"
echo "2.5.禁止root用户使用FTP"
echo "2.5.禁止root用户使用FTP" >> "$LOG_NAME"
# 检查/etc/ftpusers
if [ -f /etc/ftpusers ]
then
    if [ "$ftpusers" = "" ]
    then
        echo "未禁止root用户使用FTP"
        echo "未禁止root用户使用FTP" >> "$LOG_NAME"
        echo "cat /etc/ftpusers | grep -v ^# | grep -v ^$" >> "$LOG_NAME"
        cat /etc/ftpusers | grep -v ^# | grep -v ^$ >> "$LOG_NAME"
        echo ""  >> "$LOG_NAME"
    fi
else
    echo "不涉及"
    echo "不涉及" >> "$LOG_NAME"
    echo ""  >> "$LOG_NAME"
fi
echo "[OK]" 
echo "[OK]"  >> "$LOG_NAME"
echo ""
echo ""
echo ""  >> "$LOG_NAME"
echo ""  >> "$LOG_NAME"
echo "2.6.禁止root远程登录"
echo "2.6.禁止root远程登录" >> "$LOG_NAME"
# 检查/etc/pam.d/login及/etc/ssh/sshd_config
if [ "$login_pam" = "" ]
then
    echo "未禁止root远程登录"
    echo "未禁止root远程登录" >> "$LOG_NAME"
    echo "cat /etc/pam.d/login | grep -v ^# | grep -v ^$" >> "$LOG_NAME"
    cat /etc/pam.d/login | grep -v ^# | grep -v ^$ >> "$LOG_NAME"
    echo ""  >> "$LOG_NAME"
fi
if [ "$sshd_conf" = "" ] || [ "$sshd_conf" = "yes" ]
then
    echo "未禁止root远程登录"
    echo "未禁止root远程登录" >> "$LOG_NAME"
    echo "cat /etc/ssh/sshd_config | grep -v ^# | grep -v ^$" >> "$LOG_NAME"
    cat /etc/ssh/sshd_config | grep -v ^# | grep -v ^$ >> "$LOG_NAME"
    echo ""  >> "$LOG_NAME"
fi
echo "[OK]" 
echo "[OK]"  >> "$LOG_NAME"
echo ""
echo ""
echo ""  >> "$LOG_NAME"
echo ""  >> "$LOG_NAME"
echo "2.7.禁止用户挂载移动设备"
echo "2.7.禁止用户挂载移动设备" >> "$LOG_NAME"
# 检查/etc/security/console.perms
echo "详情请看日志"
echo "详情请看日志" >> "$LOG_NAME"
echo "cat /etc/security/console.perms | grep -v ^# | grep -v ^$" >> "$LOG_NAME"
cat /etc/security/console.perms | grep -v ^# | grep -v ^$ >> "$LOG_NAME"
echo ""  >> "$LOG_NAME"
echo "[OK]" 
echo "[OK]"  >> "$LOG_NAME"
echo ""
echo ""
echo ""  >> "$LOG_NAME"
echo ""  >> "$LOG_NAME"
echo "2.8.删除.rhosts、.exrc文件"
echo "2.8.删除.rhosts、.exrc文件" >> "$LOG_NAME"
# 检查.rhosts、.exrc文件
if [ "$rhost" != "" ] || [ "$exrc" != "" ]
then
    echo "未删除.rhosts、.exrc文件"
    echo "未删除.rhosts、.exrc文件" >> "$LOG_NAME"
    echo "find / -name '.rhosts'" >> "$LOG_NAME"
    find / -name '.rhosts' >> "$LOG_NAME"
    echo "find / -name '.exrc'" >> "$LOG_NAME"
    find / -name '.exrc' >> "$LOG_NAME"
    echo ""  >> "$LOG_NAME"
fi
echo "[OK]" 
echo "[OK]"  >> "$LOG_NAME"
echo ""
echo ""
echo ""  >> "$LOG_NAME"
echo ""  >> "$LOG_NAME"
echo "######################################################################"
echo ""
echo "3.安全审计"
echo ""
echo "######################################################################"
echo "" 
echo "3.1.启用日志功能"
echo "######################################################################" >> "$LOG_NAME"
echo ""  >> "$LOG_NAME"
echo "3.安全审计" >> "$LOG_NAME"
echo ""  >> "$LOG_NAME"
echo "######################################################################" >> "$LOG_NAME"
echo ""  >> "$LOG_NAME"
echo "3.1.启用日志功能" >> "$LOG_NAME"
# 检查进程
if [ "$sys_log" = "" ]
then
    echo "本地未启用日志功能，请咨询是否有第三方审计软件"
    echo "本地未启用日志功能，请咨询是否有第三方审计软件" >> "$LOG_NAME"
    echo "ps -ef|grep syslogd" >> "$LOG_NAME"
    ps -ef|grep syslogd >> "$LOG_NAME"
    echo ""  >> "$LOG_NAME"
fi
echo "[OK]" 
echo "[OK]"  >> "$LOG_NAME"
echo ""
echo ""
echo ""  >> "$LOG_NAME"
echo ""  >> "$LOG_NAME"
echo "3.2.设置审计内容"
echo "3.2.设置审计内容" >> "$LOG_NAME"
# 检查/etc/rsyslog.conf
if [ -f /etc/rsyslog.conf ]
then
    echo "请查看日志"
    echo "请查看日志" >> "$LOG_NAME"
    echo "cat /etc/rsyslog.conf | grep -v ^# | grep -v ^$" >> "$LOG_NAME"
    cat /etc/rsyslog.conf | grep -v ^# | grep -v ^$ >> "$LOG_NAME"
    echo ""  >> "$LOG_NAME"
else
    echo "询问是否有第三方审计系统"
    echo "询问是否有第三方审计系统" >> "$LOG_NAME"
fi
echo "[OK]" 
echo "[OK]"  >> "$LOG_NAME"
echo ""
echo ""
echo ""  >> "$LOG_NAME"
echo ""  >> "$LOG_NAME"
echo "3.3.审计历史记录"
echo "3.3.审计历史记录" >> "$LOG_NAME"
# 检查/.sh_history, /.bash_history
if [ ! -f /.sh_history ] || [ ! -f /.bash_history ]
then
    echo "审计历史记录不存在"
    echo "审计历史记录不存在" >> "$LOG_NAME"
    echo ""  >> "$LOG_NAME"
fi
echo "[OK]" 
echo "[OK]"  >> "$LOG_NAME"
echo ""
echo ""
echo ""  >> "$LOG_NAME"
echo ""  >> "$LOG_NAME"
echo "3.4.审计入侵痕迹检测记录"
echo "3.4.审计入侵痕迹检测记录" >> "$LOG_NAME"
# 检查/var/log/secure
echo "不做检查"
echo "不做检查" >> "$LOG_NAME"
echo ""  >> "$LOG_NAME"
echo "[OK]" 
echo "[OK]"  >> "$LOG_NAME"
echo ""
echo ""
echo ""  >> "$LOG_NAME"
echo ""  >> "$LOG_NAME"
echo "3.5.审计用户行为日志"
echo "3.5.审计用户行为日志" >> "$LOG_NAME"
# 检查/var/log/wtmp
echo "详情请看日志"
echo "详情请看日志" >> "$LOG_NAME"
echo "who /var/log/wtmp" >> "$LOG_NAME"
who /var/log/wtmp >> "$LOG_NAME"
echo ""  >> "$LOG_NAME"
echo "[OK]" 
echo "[OK]"  >> "$LOG_NAME"
echo ""
echo ""
echo ""  >> "$LOG_NAME"
echo ""  >> "$LOG_NAME"
echo "3.6.保护审计记录"
echo "3.6.保护审计记录" >> "$LOG_NAME"
# 检查/etc/rsyslog.conf
if [ "$rsyslog_rwx" != "-r--------" ] 
then
    echo "未保护审计记录"
    echo "未保护审计记录" >> "$LOG_NAME"
    echo "ls -la /etc/rsyslog.conf" >> "$LOG_NAME"
    ls -la /etc/rsyslog.conf >> "$LOG_NAME"
    echo ""  >> "$LOG_NAME"
fi
echo "[OK]" 
echo "[OK]"  >> "$LOG_NAME"
echo ""
echo ""
echo ""  >> "$LOG_NAME"
echo ""  >> "$LOG_NAME"
echo "3.7.审计日志保存日期"
echo "3.7.审计日志保存日期" >> "$LOG_NAME"
# 检查/var/log/
echo "详情请看日志"
echo "详情请看日志" >> "$LOG_NAME"
echo "ls -la /var/log/" >> "$LOG_NAME"
ls -la /var/log/ >> "$LOG_NAME"
echo ""  >> "$LOG_NAME"
echo "[OK]" 
echo "[OK]"  >> "$LOG_NAME"
echo ""
echo ""
echo ""  >> "$LOG_NAME"
echo ""  >> "$LOG_NAME"
echo "######################################################################"
echo ""
echo "4.资源控制"
echo ""
echo "######################################################################"
echo ""
echo "4.1.设置操作超时锁定"
echo "######################################################################" >> "$LOG_NAME"
echo ""  >> "$LOG_NAME"
echo "4.资源控制" >> "$LOG_NAME"
echo ""  >> "$LOG_NAME"
echo "######################################################################" >> "$LOG_NAME"
echo ""  >> "$LOG_NAME"
echo "4.1.设置操作超时锁定" >> "$LOG_NAME"
# 检查/etc/profile
if [ "$profile_timeout" = "" ]
then
    echo "未设置操作超时锁定"
    echo "未设置操作超时锁定" >> "$LOG_NAME"
    echo "cat /etc/profile | grep -v ^# | grep -v ^$" >> "$LOG_NAME"
    cat /etc/profile | grep -v ^# | grep -v ^$ >> "$LOG_NAME"
    echo ""  >> "$LOG_NAME"
fi
echo "[OK]" 
echo "[OK]"  >> "$LOG_NAME"
echo ""
echo ""
echo ""  >> "$LOG_NAME"
echo ""  >> "$LOG_NAME"

