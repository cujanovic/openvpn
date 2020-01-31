#!/bin/bash

# Build OpenVPN with specific OpenSSL version
# Tested on:
#   Ubuntu 16.04("xenial"), Ubuntu 18.04("bionic"), Ubuntu 19.04("disco")
#   Debian 8 ("jessie"), Debian 9 ("stretch"), Debian 10 ("buster")
#   CentOS 7, CentOS 8
#   Fedora 30, Fedora 31
#   OpenVPN version 2.4.x for clients
#   OpenSSL versions: 1.0.2x and 1.1.1x(preferred one) for clients

# args
OPENVPN_VESION="$1"
OPENSSL_VERSION="$2"

# default configs
TEMP_SOURCE_DIR="/usr/local/src/"
WGETOPT="-nc -q"
NB_PROC=2

#Build dependencies
DEBIAN_UBUNTU_BUILD_DEPENDENCIES="perl wget tar gcc make cmake gnupg gawk grep net-tools libpam0g-dev binutils findutils pkg-config systemd libsystemd-dev autoconf libtool"
CENTOS_RHEL_BUILD_DEPENDENCIES="perl-core wget tar gcc make cmake gpg gawk grep  net-tools pam-devel binutils findutils pkgconfig systemd systemd-devel autoconf libtool"

# OpenSSL installation default configs
OPENSSL_DOWNLOAD_URL="https://www.openssl.org/source/openssl-$OPENSSL_VERSION.tar.gz"
OPENSSL_SIG_KEY1="8657ABB260F056B1E5190839D9C4D26D0E604491"
OPENSSL_SIG_KEY2="7953AC1FBC3DC8B3B292393ED5E9E43F7DF9EE8C"
OPENSSL_PREFIX_DIR="/usr/local/openssl-$OPENSSL_VERSION"
OPENSSL_RPATH_DIR="/usr/local/openssl-$OPENSSL_VERSION/lib"
OPENSSL_CONFIGURE_PARAMS="no-comp no-ssl2 no-ssl3 no-tls1 no-tls1_1 enable-ec_nistp_64_gcc_128 --prefix=$OPENSSL_PREFIX_DIR"
OPENSSL_CFLAGS_PARAMS="-Wall -O2 -D_FORTIFY_SOURCE=2 -fexceptions -fPIC -pie -Wformat -Werror=format-security --param=ssp-buffer-size=4 -m64 -Wl,-z,relro,-z,now"

# OpenVPN installation default configs
OPENVPN_DOWNLOAD_URL="https://swupdate.openvpn.org/community/releases/openvpn-$OPENVPN_VESION.tar.gz"
OPENVPN_SIG_KEY="F554A3687412CFFEBDEFE0A312F5F7B42F2B01E7"
OPENVPN_PREFIX_DIR="/usr/local/openvpn-$OPENVPN_VESION"
OPENVPN_CONFIGURE_PARAMS="--disable-lzo --prefix=$OPENVPN_PREFIX_DIR --disable-debug --enable-strict --enable-systemd"
OPENVPN_CFLAGS_PARAMS="-Wall -std=c11 -O2 -D_FORTIFY_SOURCE=2 -fexceptions -fPIC -fPIE -pie -Wformat -Werror=format-security --param=ssp-buffer-size=4 -m64 -Wl,-z,relro,-z,now -I$OPENSSL_PREFIX_DIR/include -Wl,-rpath=$OPENSSL_RPATH_DIR -L$OPENSSL_RPATH_DIR"

#If terminal add collors
if [[ -t 1 ]]; then
	#Colors
	red='\e[0;31m'
	green='\e[0;32m'
	blue='\e[0;36m'
	yellow='\e[0;33m'
	errorredline='\e[0;41m'
	greenbgblacktext='\e[30;48;5;82m'
	NC='\e[0m'
else
	#NoColors
	red=''
	green=''
	blue=''
	yellow=''
	errorredline=''
	greenbgblacktext=''
	NC=''
fi

function CHECK_PREVIOUS_CMD () {
	if [ $? -ne 0 ]; then
		echo -e "${errorredline}Build error${NC}"
		echo -e "${red}$0 build error at script line: $1 ${NC}"
		echo -e "${yellow}View the last log above.${NC}"
		exit 1
	fi
}

function GET_CORE_NUMBERS () {
	if NB_PROC=$(grep -c ^processor /proc/cpuinfo 2>&1); then
		NB_PROC=$((NB_PROC*2))
	else
		NB_PROC=2
	fi
}

function CHECK_ROOT () {
	if [ "$(whoami)" != "root" ]; then
	echo -e "${errorredline}Error: This script needs to be run as root!${NC}"
	exit 1
	fi
}

function PRINT_INVALID_AND_CORRECT_USAGE_EXAMPLE () {
	echo -e "${errorredline}Invalid number of arguments. Example usage:${NC}"
	echo -e "${yellow}$0 OPENVPN-VERSION OPENSSL-VERSION"
	echo -e "${blue}$0 2.4.8 1.1.1d${NC}\n"
}

function PRINT_SCRIPT_HEADER () {
	echo -e "\n${greenbgblacktext}$0 - Build/Install OpenVPN with specific OpenSSL version${NC}\n"
	echo -e "# Tested on:"
	echo -e "#   Ubuntu 16.04(\"xenial\"), Ubuntu 18.04(\"bionic\"), Ubuntu 19.04(\"disco\")"
	echo -e "#   Debian 8 (\"jessie\"), Debian 9 (\"stretch\"), Debian 10 (\"buster\")"
	echo -e "#   CentOS 7, CentOS 8"
	echo -e "#   Fedora 30, Fedora 31\n"
}

function PRINT_SCRIPT_FOOTER {
	echo -e "\n${greenbgblacktext}All done.${NC}"
	echo -e "\n${blue}Place openvpn server config(${NC}server.conf${blue})in${NC} /etc/openvpn${blue} and run: ${NC}sudo systemctl start openvpn@server\n"
	echo -e "${greenbgblacktext}>>>>>${NC}${yellow} openvpn --version ${NC}${greenbgblacktext}<<<<<${NC}\n"
	openvpn --version
}

function CHECK_LOCAL_OPENVPN_AND_OPENSSL_VERSIONS () {
	if command -v openvpn &>/dev/null; then
		LOCAL_OPENVPN_VERSION=$(openvpn --version | head -n 1 | awk '{print $2}')
		CHECK_PREVIOUS_CMD $LINENO
		LOCAL_OPENSSL_VERSION=$(openvpn --version | head -n 2 | tail -n 1 | awk '{print $4}')
		CHECK_PREVIOUS_CMD $LINENO
		if [[ -z "${FORCE_OPENVPN_INSTALL}" ]]; then
		  FORCE_OPENVPN_INSTALL_VAR="no"
		elif [[ "${FORCE_OPENVPN_INSTALL}" -eq "yes" ]]; then
			FORCE_OPENVPN_INSTALL_VAR="yes"
		else
			FORCE_OPENVPN_INSTALL_VAR="no"
		fi
		if [[ "$LOCAL_OPENVPN_VERSION" == "$OPENVPN_VESION" ]] && [[ "$LOCAL_OPENSSL_VERSION" == "$OPENSSL_VERSION" ]] && [[ "$FORCE_OPENVPN_INSTALL_VAR" == "no" ]]; then
			echo -e "${yellow}Local versions of OpenVPN and OpenSSL versions are same as the provided ones:${NC}"
			echo -e "${blue}OpenVPN version:${NC} $OPENVPN_VESION"
			echo -e "${blue}OpenSSL version:${NC} $OPENSSL_VERSION"
			echo -e "${green}If you want to force the installation set a environment varialble FORCE_OPENVPN_INSTALL to yes:${NC} export FORCE_OPENVPN_INSTALL='yes' ${green}and run the ${NC}$0 ${green}script again.${NC}"
			echo -e "${greenbgblacktext}Exiting now.${NC}"
			exit
		fi
	fi
}

function INSTALL_DEPENDENCIES () {
	if [ -f /etc/debian_version ]; then
		echo -e "${blue}Debian/Ubuntu detected${NC}"
		echo -e "${blue}Updating list of available packages${NC}"
		apt-get -qq update
		CHECK_PREVIOUS_CMD $LINENO
		echo -e "${blue}Instaling dependencies:${NC} $DEBIAN_UBUNTU_BUILD_DEPENDENCIES"
		apt-get -qq install -y $DEBIAN_UBUNTU_BUILD_DEPENDENCIES
		CHECK_PREVIOUS_CMD $LINENO
	elif [ -f /etc/redhat-release ]; then
		echo -e "${blue}CentOS/RedHat detected${NC}"
		echo -e "${blue}Instaling dependencies:${NC} $CENTOS_RHEL_BUILD_DEPENDENCIES"
		yum -q install -y $CENTOS_RHEL_BUILD_DEPENDENCIES
		CHECK_PREVIOUS_CMD $LINENO
	fi
}

function SET_STACK_PROTECTION () {
	if gcc --help=common|grep -q 'fstack-protector-strong'; then
		OPENSSL_CFLAGS_PARAMS=$(echo "-fstack-protector-strong $OPENSSL_CFLAGS_PARAMS")
		OPENVPN_CFLAGS_PARAMS=$(echo "-fstack-protector-strong $OPENVPN_CFLAGS_PARAMS")
	else
		OPENSSL_CFLAGS_PARAMS=$(echo "-fstack-protector-all $OPENSSL_CFLAGS_PARAMS")
		OPENVPN_CFLAGS_PARAMS=$(echo "-fstack-protector-all $OPENVPN_CFLAGS_PARAMS")
	fi
}

function DOWNLOAD_BUILD_INSTALL_OPENSSL () {
	cd "$TEMP_SOURCE_DIR"
	CHECK_PREVIOUS_CMD $LINENO
	if [ -d "openssl-$OPENSSL_VERSION" ] || [ -f "openssl-$OPENSSL_VERSION.tar.gz" ] || [ -f "openssl-$OPENSSL_VERSION.tar.gz.asc" ]; then
		echo -e "${blue}Same version OpenSSL source code detected, deleting now:${NC} $TEMP_SOURCE_DIR/openssl-$OPENSSL_VERSION ${blue}and${NC} $TEMP_SOURCE_DIR/openssl-$OPENSSL_VERSION.tar.gz"
		rm -rf "openssl-$OPENSSL_VERSION"
		CHECK_PREVIOUS_CMD $LINENO
		rm -rf "openssl-$OPENSSL_VERSION.tar.gz"
		CHECK_PREVIOUS_CMD $LINENO
		rm -rf "openssl-$OPENSSL_VERSION.tar.gz.asc"
		CHECK_PREVIOUS_CMD $LINENO
	fi
	echo -e "${blue}Downloading OpenSSL version $OPENSSL_VERSION${NC}"
	wget $WGETOPT "$OPENSSL_DOWNLOAD_URL"
	CHECK_PREVIOUS_CMD $LINENO
	wget $WGETOPT "$OPENSSL_DOWNLOAD_URL.asc"
	CHECK_PREVIOUS_CMD $LINENO
	echo -e "${blue}Verifying downloaded OpenSSL version $OPENSSL_VERSION${NC}"
	gpg --trust-model always -q --keyserver pool.sks-keyservers.net --recv-keys "$OPENSSL_SIG_KEY1"
	CHECK_PREVIOUS_CMD $LINENO
	gpg --trust-model always -q --keyserver pool.sks-keyservers.net --recv-keys "$OPENSSL_SIG_KEY2"
	CHECK_PREVIOUS_CMD $LINENO
	gpg --trust-model always -q --verify "openssl-$OPENSSL_VERSION.tar.gz.asc" "openssl-$OPENSSL_VERSION.tar.gz"
	CHECK_PREVIOUS_CMD $LINENO
	echo -e "${blue}Extracting OpenSSL version $OPENSSL_VERSION${NC}"
	tar xzf "openssl-$OPENSSL_VERSION.tar.gz"
	CHECK_PREVIOUS_CMD $LINENO
	cd "openssl-$OPENSSL_VERSION"
	CHECK_PREVIOUS_CMD $LINENO
	echo -e "${blue}OpenSSL version: $OPENSSL_VERSION downloading, extracting and verifying done, building, testing and installing to: $OPENSSL_PREFIX_DIR now${NC}"
	CFLAGS=$(echo "$OPENSSL_CFLAGS_PARAMS") ./config $OPENSSL_CONFIGURE_PARAMS
	CHECK_PREVIOUS_CMD $LINENO
	make -s -j "$NB_PROC"
	CHECK_PREVIOUS_CMD $LINENO
	make -s test
	CHECK_PREVIOUS_CMD $LINENO
	make -s install_sw
	CHECK_PREVIOUS_CMD $LINENO
	echo -e "${green}OpenSSL installation to: $OPENSSL_PREFIX_DIR done.${NC}"
}

function DOWNLOAD_BUILD_INSTALL_OPENVPN () {
	cd "$TEMP_SOURCE_DIR"
	CHECK_PREVIOUS_CMD $LINENO
	if [ -d "openvpn-$OPENVPN_VESION" ] || [ -f "openvpn-$OPENVPN_VESION.tar.gz" ] || [ -f "openvpn-$OPENVPN_VESION.tar.gz.asc" ]; then
		echo -e "${blue}Same version OpenVPN source code detected, deleting now${NC}"
		rm -rf "openvpn-$OPENVPN_VESION"
		CHECK_PREVIOUS_CMD $LINENO
		rm -rf "openvpn-$OPENVPN_VESION.tar.gz"
		CHECK_PREVIOUS_CMD $LINENO
		rm -rf "openvpn-$OPENVPN_VESION.tar.gz.asc"
		CHECK_PREVIOUS_CMD $LINENO
	fi
	echo -e "${blue}Downloading OpenVPN version $OPENVPN_VESION${NC}"
	wget $WGETOPT "$OPENVPN_DOWNLOAD_URL"
	CHECK_PREVIOUS_CMD $LINENO
	wget $WGETOPT "$OPENVPN_DOWNLOAD_URL.asc"
	CHECK_PREVIOUS_CMD $LINENO
	echo -e "${blue}Verifying downloaded OpenVPN version $OPENVPN_VESION${NC}"
	gpg --trust-model always -q --keyserver pool.sks-keyservers.net --recv-keys "$OPENVPN_SIG_KEY"
	CHECK_PREVIOUS_CMD $LINENO
	gpg --trust-model always -q --verify "openvpn-$OPENVPN_VESION.tar.gz.asc" "openvpn-$OPENVPN_VESION.tar.gz"
	CHECK_PREVIOUS_CMD $LINENO
	echo -e "${blue}Extracting OpenVPN version $OPENVPN_VESION${NC}"
	tar xzf "openvpn-$OPENVPN_VESION.tar.gz"
	CHECK_PREVIOUS_CMD $LINENO
	cd "openvpn-$OPENVPN_VESION"
	CHECK_PREVIOUS_CMD $LINENO
	echo -e "${blue}OpenVPN version: $OPENVPN_VESION downloading, extracting and verifying done, building, testing and installing to: $OPENVPN_PREFIX_DIR now${NC}"
	CFLAGS=$(echo "$OPENVPN_CFLAGS_PARAMS") ./configure $OPENVPN_CONFIGURE_PARAMS
	CHECK_PREVIOUS_CMD $LINENO
	make -s -j "$NB_PROC"
	CHECK_PREVIOUS_CMD $LINENO
	make -s check
	CHECK_PREVIOUS_CMD $LINENO
	make -s install
	CHECK_PREVIOUS_CMD $LINENO
	echo -e "${green}OpenVPN installation to: $OPENVPN_PREFIX_DIR done.${NC}"
	echo -e "${blue}Linking OpenVPN installation to: /usr/local/sbin/openvpn${NC}"
	ln -sf "$OPENVPN_PREFIX_DIR/sbin/openvpn" /usr/local/sbin/openvpn
	CHECK_PREVIOUS_CMD $LINENO
	echo -e "${green}Linking OpenVPN installation to: /usr/local/sbin/openvpn done.${NC}"
	echo -e "${blue}Linking OpenVPN Plugin Auth installation to: /usr/local/lib/openvpn-plugin-auth-pam.so${NC}"
	ln -sf "$OPENVPN_PREFIX_DIR/lib/openvpn/plugins/openvpn-plugin-auth-pam.so" /usr/local/lib/openvpn-plugin-auth-pam.so
	CHECK_PREVIOUS_CMD $LINENO
	echo -e "${green}Linking OpenVPN Plugin Auth installation to: /usr/lib64/openvpn-plugin-auth-pam.so done.${NC}"
	echo -e "${blue}Linking/Enabling OpenVPN systemd service script to: /etc/systemd/system/openvpn@.service${NC}"
	systemctl -f enable "$OPENVPN_PREFIX_DIR/lib/systemd/system/openvpn-server@.service"
	CHECK_PREVIOUS_CMD $LINENO
	echo -e "${green}Linking/Enabling OpenVPN systemd service script to: /etc/systemd/system/openvpn@.service done.${NC}"
	if [ ! -d /etc/openvpn/server ]; then
		mkdir -p /etc/openvpn/server
		CHECK_PREVIOUS_CMD $LINENO
	fi
	echo -e "${green}Place your OpenVPN configuration in ${NC}${yellow}filename${NC}${green}: /etc/openvpn/server and run:${NC} ${blue}systemctl start openvpn-server@${NC} ${yellow}filename${NC}${blue}.service${NC}"
	}

function STRIP_UNNEEDED () {
	echo -e "${blue}Stripping unneeded from openssl and openvpn libs and executables${NC}"
	find "$OPENSSL_RPATH_DIR" -maxdepth 1 -type f | grep '.so' | awk '{system("strip --strip-unneeded "$1)}'
	CHECK_PREVIOUS_CMD $LINENO
	strip --strip-unneeded "$OPENSSL_PREFIX_DIR/bin/openssl"
	CHECK_PREVIOUS_CMD $LINENO
	find "$OPENVPN_PREFIX_DIR/lib/" -type f | grep '.so' | awk '{system("strip --strip-unneeded "$1)}'
	CHECK_PREVIOUS_CMD $LINENO
	strip --strip-unneeded "$OPENVPN_PREFIX_DIR/sbin/openvpn"
	CHECK_PREVIOUS_CMD $LINENO
	echo -e "${green}Stripping done.${NC}"
}

if [ $# -eq 0 ] || [ $# -gt 2 ] || [ $# -lt 2 ]; then
	PRINT_SCRIPT_HEADER
	PRINT_INVALID_AND_CORRECT_USAGE_EXAMPLE
	exit 1
else
	PRINT_SCRIPT_HEADER
	CHECK_ROOT
	CHECK_LOCAL_OPENVPN_AND_OPENSSL_VERSIONS
	INSTALL_DEPENDENCIES
	SET_STACK_PROTECTION
	GET_CORE_NUMBERS
	DOWNLOAD_BUILD_INSTALL_OPENSSL
	DOWNLOAD_BUILD_INSTALL_OPENVPN
	STRIP_UNNEEDED
	PRINT_SCRIPT_FOOTER
fi
