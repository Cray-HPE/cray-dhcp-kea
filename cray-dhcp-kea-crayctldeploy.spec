#
# RPM spec file for cray-uas-mgr deployment
# Copyright 2018 Cray Inc. All Rights Reserved.
#
%define crayctl_dir /opt/cray/crayctl
%define ansible_dir %{crayctl_dir}/ansible_framework
Name: cray-kea-crayctldeploy
License: Cray Software License Agreement
Summary: Cray DHCP Kea Config Update
Version: %(cat .version)
Release: %(echo ${BUILD_METADATA})
Source: %{name}-%{version}.tar.bz2
Vendor: Cray Inc.
Group: Networking
Requires: cray-crayctl
%description
KEA
%files
%dir %{crayctl_dir}
%{ansible_dir}
%prep
%setup -q
%build
%install
# Install ansible files
mkdir -p %{buildroot}%{crayctl_dir}
cp -R ansible_framework %{buildroot}%{ansible_dir}