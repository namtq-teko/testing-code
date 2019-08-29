#!/bin/bash

# Configurations
readonly SSH_USERS="namtq tuongpx quy-dev quyetnv"
readonly CRON_ALLOW_CONFIG_FILE="/etc/cron.allow"
readonly SSH_CONFIG_FILE="/etc/ssh/sshd_config"
readonly COMMON_PWD_CONFIG_FILE="/etc/pam.d/common-password"
readonly PAM_PWQUALITY_FILE="/etc/security/pwquality.conf"
readonly COMMON_AUTH_CONFIG_FILE="/etc/pam.d/common-auth"
readonly LOGIN_CONFIG_FILE="/etc/login.defs"

function print_banner() {
  echo "############################################"
  echo "## Security Hardening for Ubuntu 18.04    ##"
  echo "##                                 v1.0   ##"
  echo "############################################"
  echo ""
}

function backup_files() {
  TIME=$(date "+%H%M%S%m%d%y")
  BACKUP_DIR="backup-${TIME}"
  BACKUP_FILES=(
    ${CRON_ALLOW_CONFIG_FILE}
    ${SSH_CONFIG_FILE}
    ${COMMON_PWD_CONFIG_FILE}
    ${PAM_PWQUALITY_FILE}
    ${COMMON_AUTH_CONFIG_FILE}
    ${LOGIN_CONFIG_FILE}
  )
  mkdir ~/${BACKUP_DIR}
  for FILE in "${BACKUP_FILES[@]}"; do
    if [[ -f ${FILE} ]]; then
      cp ${FILE} ~/"${BACKUP_DIR}/"
    fi
  done
}

function has_config() {
  PATTERN=$1
  FILE=$2
  if [[ ! -f ${FILE} ]]; then
    echo "File ${FILE} does not exist"
    exit 1
  fi
  if ! egrep -qi ${PATTERN} ${FILE}; then
    return 0
  fi
  return 1
}

function mark_hardening() {
  FILE_NAME=$1
  has_config "^\s*#\s*Teko\s*Security\s*Hardening" ${FILE_NAME}
  if [[ $? -eq 0 ]]; then
    echo "" >> ${FILE_NAME}
    echo "# Teko Security Hardening" >> ${FILE_NAME}
  fi
}

function harden() {
  CHECKLIST=$1
  FILE_NAME=$2
  mark_hardening ${FILE_NAME}
  for ITEM in "${CHECKLIST[@]}"; do
    IFS='|' read -r CONFIG_NAME VALID_PATTERN VALID_CONFIG <<< ${ITEM}
    has_config "^\s*${CONFIG_NAME}" ${FILE_NAME}
    if [[ $? -eq 0 ]]; then
      echo ${VALID_CONFIG} >> ${FILE_NAME}
    else
      has_config ${VALID_PATTERN} ${FILE_NAME}
      if [[ $? -eq 0 ]]; then
        sed -i "s/^\s*${CONFIG_NAME}/# ${CONFIG_NAME}/" ${FILE_NAME}
        echo ${VALID_CONFIG} >> ${FILE_NAME}
      fi
    fi
  done
}

function configure_cron() {
  # Ensure permissions on
  # /etc/crontab
  # /etc/cron.hourly
  # /etc/cron.daily
  # /etc/cron.weekly
  # /etc/cron.monthly
  # /etc/cron.d
  # are configured
  chown root:root /etc/crontab /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /etc/cron.d
  chmod -R go-rwx /etc/crontab /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /etc/cron.d
  # Ensure at/cron is restricted to authorized users
  rm -f /etc/cron.deny /etc/at.deny
  touch /etc/cron.allow /etc/at.allow
  chown root:root /etc/cron.allow /etc/at.allow
  chmod og-rwx /etc/cron.allow /etc/at.allow
  CHECKLIST=("root|^\s*root\s*$|root")
  harden "${CHECKLIST}" "${CRON_ALLOW_CONFIG_FILE}"
}

function configure_ssh() {
  # Ensure permissions on /etc/ssh/sshd_config are configured
  chown root:root /etc/ssh/sshd_config
  chmod -R og-rwx /etc/ssh/sshd_config
  CHECKLIST=(
    # Ensure SSH Protocol is set to 2
    "Protocol|^\s*Protocol\s+2\s*$|Protocol 2"
    # Ensure SSH LogLevel is set to INFO
    "LogLevel|^\s*LogLevel\s+INFO\s*$|LogLevel INFO"
    # Ensure SSH X11 forwarding is disabled
    "X11Forwarding|^\s*X11Forwarding\s+no\s*$|X11Forwarding no"
    # Ensure SSH MaxAuthTries is set to 4 or less
    "MaxAuthTries|^\s*MaxAuthTries\s+4\s*$|MaxAuthTries 4"
    # Ensure SSH IgnoreRhosts is enabled
    "IgnoreRhosts|^\s*IgnoreRhosts\s+yes\s*$|IgnoreRhosts yes"
    # Ensure SSH HostbasedAuthentication is disabled
    "HostbasedAuthentication|^\s*HostbasedAuthentication\s+no\s*$|HostbasedAuthentication no"
    # Ensure SSH root login is disabled
    "PermitRootLogin|^\s*PermitRootLogin\s+no\s*$|PermitRootLogin no"
    # Ensure SSH PermitEmptyPasswords is disabled
    "PermitEmptyPasswords|^\s*PermitEmptyPasswords\s+no\s*$|PermitEmptyPasswords no"
    # Ensure SSH PermitUserEnvironment is disabled
    "PermitUserEnvironment|^\s*PermitUserEnvironment\s+no\s*$|PermitUserEnvironment no"
    # Ensure only approved MAC algorithms are used
    "MACs|^\s*MACs\s*hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-512,hmac-sha2-256,umac-128@openssh.com\s*$|MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-512,hmac-sha2-256,umac-128@openssh.com"
    # Ensure SSH Idle Timeout Interval is configured
    "ClientAliveInterval|^\s*ClientAliveInterval\s+300\s*$|ClientAliveInterval 300"
    "ClientAliveCountMax|^\s*ClientAliveCountMax\s+0\s*$|ClientAliveCountMax 0"
    # Ensure SSH LoginGraceTime is set to one minute or less
    "LoginGraceTime|^\s*LoginGraceTime\s+60\s*$|LoginGraceTime 60"
    # Ensure SSH access is limited
    "AllowUsers|^\s*AllowUsers\s+$SSH_USERS\s*$|AllowUsers $SSH_USERS"
  )
  harden "${CHECKLIST}" "${SSH_CONFIG_FILE}"
  # Ensure SSH warning banner is configured
  rm -f /etc/issue.net && touch /etc/issue.net
  chown root:root /etc/issue.net && chmod 644 /etc/issue.net
  echo "###################################################################" >> /etc/issue.net
  echo "#                             WELCOME                             #" >> /etc/issue.net
  echo "#           All connections are monitored and recorded            #" >> /etc/issue.net
  echo "#    Disconnect IMMEDIATELY if you are not an authorized user!    #" >> /etc/issue.net
  echo "###################################################################" >> /etc/issue.net
  has_config "^\s*Banner\s*\/etc\/issue.net\s*$" ${SSH_CONFIG_FILE}
  if [[ $? -eq 0 ]]; then
    echo "Banner /etc/issue.net" >> ${SSH_CONFIG_FILE}
  fi
}

function configure_pam() {

  # Install the pam_pwquality module
  cd ./libpam-pwquality
  dpkg -i libcrack2_2.9.2-5build1_amd64.deb
  dpkg -i cracklib-runtime_2.9.2-5build1_amd64.deb
  dpkg -i libpwquality-common_1.4.0-2_all.deb
  dpkg -i libpwquality1_1.4.0-2_amd64.deb
  dpkg -i wamerican_2017.08.24-1_all.deb
  dpkg -i libpam-pwquality_1.4.0-2_amd64.deb
  cd ..
  sleep 10s
  mark_hardening ${COMMON_PWD_CONFIG_FILE}
  # Ensure password creation requirements are configured
  has_config "^\s*password\s+requisite\s+pam_pwquality.so" ${COMMON_PWD_CONFIG_FILE}
  if [[ $? -eq 0 ]]; then
    echo "password requisite pam_pwquality.so retry=3" >> ${COMMON_PWD_CONFIG_FILE}
  else
    has_config "^\s*password\s+requisite\s+pam_pwquality.so\s+retry\s*=\s*3\s*$" ${COMMON_PWD_CONFIG_FILE}
    if [[ $? -eq 0 ]]; then
      sed -i 's/^\s*password\s\+requisite\s\+pam_pwquality.so/# password requisite pam_pwquality.so/' ${COMMON_PWD_CONFIG_FILE}
      echo "password requisite pam_pwquality.so retry=3" >> ${COMMON_PWD_CONFIG_FILE}
    fi
  fi
  CHECKLIST=(
    "minlen|^\s*minlen\s*=\s*14\s*$|minlen=14"
    "dcredit|^\s*dcredit\s*=\s*-1\s*$|dcredit=-1"
    "ucredit|^\s*ucredit\s*=\s*-1\s*$|ucredit=-1"
    "ocredit|^\s*ocredit\s*=\s*-1\s*$|ocredit=-1"
    "lcredit|^\s*lcredit\s*=\s*-1\s*$|lcredit=-1"
  )
  harden "${CHECKLIST}" "${PAM_PWQUALITY_FILE}"
  # Ensure lockout for failed password attempts is configured
  mark_hardening ${COMMON_AUTH_CONFIG_FILE}
  has_config "^\s*auth\s+required\s+pam_tally2.so" ${COMMON_AUTH_CONFIG_FILE}
  if [[ $? -eq 0 ]]; then
    echo "auth required pam_tally2.so onerr=fail audit silent deny=5 unlock_time=900" >> ${COMMON_AUTH_CONFIG_FILE}
  else
    has_config "^\s*auth\s+required\s+pam_tally2.so\s+onerr\s*=\s*fail\s+audit\s+silent\s+deny\s*=\s*5\s+unlock_time\s*=\s*900\s*$" ${COMMON_AUTH_CONFIG_FILE}
    if [[ $? -eq 0 ]]; then
      sed -i "s/^\s*auth\s\+required\s\+pam_tally2.so/# auth required pam_tally2.so/" ${COMMON_AUTH_CONFIG_FILE}
      echo "auth required pam_tally2.so onerr=fail audit silent deny=5 unlock_time=900" >> ${COMMON_AUTH_CONFIG_FILE}
    fi
  fi
  # Ensure password reuse is limited
  has_config "^\s*password\s+required\s+pam_pwhistory.so\s*" ${COMMON_PWD_CONFIG_FILE}
  if [[ $? -eq 0 ]]; then
    echo "password required pam_pwhistory.so remember=5" >> ${COMMON_PWD_CONFIG_FILE}
  else
    has_config "^\s*password\s+required\s+pam_pwhistory.so\s+remember\s*=\s*5\s*$" ${COMMON_PWD_CONFIG_FILE}
    if [[ $? -eq 0 ]]; then
      sed -i "s/^\s*password\s\+required\s\+pam_pwhistory.so/# password required pam_pwhistory.so/" ${COMMON_PWD_CONFIG_FILE}
      echo "password required pam_pwhistory.so remember=5" >> ${COMMON_PWD_CONFIG_FILE}
    fi
  fi
  # Ensure password hashing algorithm is SHA-512
  has_config "^\s*password\s+(\S+\s+)+pam_unix\.so\s+(\S+\s+)*sha512" ${COMMON_PWD_CONFIG_FILE}
  if [[ $? -eq 0 ]]; then
    echo "password [success=1 default=ignore] pam_unix.so sha512" >> ${COMMON_PWD_CONFIG_FILE}
  fi
}

function configure_accounts_envs() {
  CHECKLIST=(
    # Ensure password expiration is 365 days or less
    "PASS_MAX_DAYS|^\s*PASS_MAX_DAYS\s+180\s*$|PASS_MAX_DAYS 180"
    # Ensure minimum days between password changes is 7 or more
    "PASS_MIN_DAYS|^\s*PASS_MIN_DAYS\s+7\s*$|PASS_MIN_DAYS 7"
    # Ensure password expiration warning days is 7 or more
    "PASS_WARN_AGE|^\s*PASS_WARN_AGE\s+7\s*$|PASS_WARN_AGE 7"
  )
  harden "$CHECKLIST" "$LOGIN_CONFIG_FILE"
  ACCOUNTS=$(egrep "^[^:]+:[^\!*]" "/etc/shadow" | cut -d: -f1 )
  for USERNAME in ${ACCOUNTS}; do
    NUMBER=$(chage --list ${USERNAME} | egrep -i "^\s*Maximum\s+number\s+of\s+days" | awk '{print $NF}')
    if [[ "${NUMBER}" != "180" ]]; then
      chage --maxdays 180 ${USERNAME}
    fi
    NUMBER=$(chage --list ${USERNAME} | egrep -i "^\s*Minimum\s+number\s+of\s+days" | awk '{print $NF}')
    if [[ "${NUMBER}" != "7" ]]; then
      chage --mindays 7 ${USERNAME}
    fi
    NUMBER=$(chage --list ${USERNAME} | egrep -i "^\s*Number\s+of\s+days\s+of\s+warning" | awk '{print $NF}')
    if [[ "${NUMBER}" != "7" ]]; then
      chage --warndays 7 ${USERNAME}
    fi
  done
  # Ensure default group for the root account is GID 0
  GID=$(egrep "^root:" "/etc/passwd" | cut -f4 -d:)
  if [[ "${GID}" != "0" ]]; then
    usermod -g 0 root
  fi
}

function configure_logging() {
  # Ensure rsyslog Service is enabled
  STATUS=$(systemctl is-enabled rsyslog)
  if [[ "${STATUS}" != "enabled" ]]; then
    systemctl enable rsyslog
    echo "AAA"
  fi
  # Ensure permissions on all logfiles are configured
  chmod -R g-wx,o-rwx /var/log/*
}

print_banner
backup_files
configure_cron
configure_ssh
configure_pam
configure_accounts_envs
configure_logging
