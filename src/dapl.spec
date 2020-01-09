# Copyright (c) 2002-2005, Network Appliance, Inc. All rights reserved.
# Copyright (c) 2007, Intel Corporation. All rights reserved.
#
# This Software is licensed under one of the following licenses:
#
# 1) under the terms of the "Common Public License 1.0" a copy of which is
#    in the file LICENSE.txt in the root directory. The license is also
#    available from the Open Source Initiative, see
#    http://www.opensource.org/licenses/cpl.php.
#
# 2) under the terms of the "The BSD License" a copy of which is in the file
#    LICENSE2.txt in the root directory. The license is also available from
#    the Open Source Initiative, see
#    http://www.opensource.org/licenses/bsd-license.php.
#
# 3) under the terms of the "GNU General Public License (GPL) Version 2" a 
#    copy of which is in the file LICENSE3.txt in the root directory. The 
#    license is also available from the Open Source Initiative, see
#    http://www.opensource.org/licenses/gpl-license.php.
#
# Licensee has the right to choose one of the above licenses.
#
# Redistributions of source code must retain the above copyright
# notice and one of the license notices.
#
# Redistributions in binary form must reproduce both the above copyright
# notice, one of the license notices in the documentation
# and/or other materials provided with the distribution.
#
#
# uDAT and uDAPL 1.2 Registry RPM SPEC file
#
# $Id: $
Name: compat-dapl
Version: 1.2.15
Release: 1%{?dist}
Summary: A Library for userspace access to RDMA devices using OS Agnostic DAT API v1.2.

Group: System Environment/Libraries
License: Dual GPL/BSD/CPL
Url: http://openfabrics.org/
Source: http://www.openfabrics.org/downloads/%{name}/%{name}-%{version}.tar.gz
BuildRoot: %(mktemp -ud %{_tmppath}/%{name}-%{version}-%{release}-XXXXXX)
Requires(post): /sbin/ldconfig
Requires(postun): /sbin/ldconfig
Requires(post): sed
Requires(post): coreutils

%description
Along with the OpenFabrics kernel drivers, libdat and libdapl provides a userspace
RDMA API that supports DAT 1.2 specification and IB transport extensions for
atomic operations and rdma write with immediate data.

%package devel
Summary: Development files for the libdat and libdapl libraries
Group: System Environment/Libraries

%description devel
Header files for libdat and libdapl library.

%package devel-static
Summary: Static development files for libdat and libdapl library
Group: System Environment/Libraries
 
%description devel-static
Static libraries for libdat and libdapl library.

%package utils
Summary: Test suites for uDAPL library
Group: System Environment/Libraries
Requires: %{name} = %{version}-%{release}

%description utils
Useful test suites to validate uDAPL library API's.

%prep
%setup -q

%build
%configure 
make %{?_smp_mflags}

%install
rm -rf %{buildroot}
make DESTDIR=%{buildroot} install
# remove unpackaged files from the buildroot
rm -f %{buildroot}%{_libdir}/*.la
rm -f %{buildroot}%{_sysconfdir}/*.conf

%clean
rm -rf %{buildroot}

%post
/sbin/ldconfig
if [ -e %{_sysconfdir}/dat.conf ]; then
    sed -e '/OpenIB-.*/d' < %{_sysconfdir}/dat.conf > /tmp/$$ofadapl
    mv /tmp/$$ofadapl %{_sysconfdir}/dat.conf
fi
echo OpenIB-cma u1.2 nonthreadsafe default libdaplcma.so.1 dapl.1.2 '"ib0 0" ""'  >> %{_sysconfdir}/dat.conf
echo OpenIB-cma-1 u1.2 nonthreadsafe default libdaplcma.so.1 dapl.1.2 '"ib1 0" ""'  >> %{_sysconfdir}/dat.conf
echo OpenIB-mthca0-1 u1.2 nonthreadsafe default libdaplscm.so.1 dapl.1.2 '"mthca0 1" ""' >> %{_sysconfdir}/dat.conf
echo OpenIB-mthca0-2 u1.2 nonthreadsafe default libdaplscm.so.1 dapl.1.2 '"mthca0 2" ""' >> %{_sysconfdir}/dat.conf
echo OpenIB-mlx4_0-1 u1.2 nonthreadsafe default libdaplscm.so.1 dapl.1.2 '"mlx4_0 1" ""' >> %{_sysconfdir}/dat.conf
echo OpenIB-mlx4_0-2 u1.2 nonthreadsafe default libdaplscm.so.1 dapl.1.2 '"mlx4_0 2" ""' >> %{_sysconfdir}/dat.conf
echo OpenIB-ipath0-1 u1.2 nonthreadsafe default libdaplscm.so.1 dapl.1.2 '"ipath0 1" ""' >> %{_sysconfdir}/dat.conf
echo OpenIB-ipath0-2 u1.2 nonthreadsafe default libdaplscm.so.1 dapl.1.2 '"ipath0 2" ""' >> %{_sysconfdir}/dat.conf
echo OpenIB-ehca0-1 u1.2 nonthreadsafe default libdaplscm.so.1 dapl.1.2 '"ehca0 1" ""' >> %{_sysconfdir}/dat.conf
echo OpenIB-iwarp u1.2 nonthreadsafe default libdaplcma.so.1 dapl.1.2 '"eth2 0" ""'  >> %{_sysconfdir}/dat.conf

%postun
/sbin/ldconfig
if [ -e %{_sysconfdir}/dat.conf ]; then
    sed -e '/OpenIB-.* u1/d' < %{_sysconfdir}/dat.conf > /tmp/$$OpenIBdapl
    mv /tmp/$$OpenIBdapl %{_sysconfdir}/dat.conf
fi

%files
%defattr(-,root,root,-)
%{_libdir}/libda*.so.*
%doc AUTHORS README ChangeLog

%files devel
%defattr(-,root,root,-)
%{_libdir}/*.so
%dir %{_includedir}/dat
%{_includedir}/dat/*

%files devel-static
%defattr(-,root,root,-)
%{_libdir}/*.a

%files utils
%defattr(-,root,root,-)
%{_bindir}/*
%{_mandir}/man1/*.1*
%{_mandir}/man5/*.5*

%changelog
* Tue Nov 24 2009 Arlin Davis <ardavis@ichips.intel.com> - 1.2.15 
- DAT/DAPL Version 1.2.15 Release 1, OFED 1.5

* Tue Mar 31 2009 Arlin Davis <ardavis@ichips.intel.com> - 1.2.14 
- DAT/DAPL Version 1.2.14 Release 1, OFED 1.4.1 GA

* Mon Mar 16 2009 Arlin Davis <ardavis@ichips.intel.com> - 1.2.13 
- DAT/DAPL Version 1.2.13 Release 1, OFED 1.4.1  

* Fri Nov 07 2008 Arlin Davis <ardavis@ichips.intel.com> - 1.2.12 
- DAT/DAPL Version 1.2.12 Release 1, OFED 1.4 GA 

* Fri Oct 07 2008 Arlin Davis <ardavis@ichips.intel.com> - 1.2.11 
- DAT/DAPL Version 1.2.11 Release 1, OFED 1.4 rc3 

* Mon Sep 01 2008 Arlin Davis <ardavis@ichips.intel.com> - 1.2.10 
- DAT/DAPL Version 1.2.10 Release 1, OFED 1.4 rc1 

* Thu Aug 21 2008 Arlin Davis <ardavis@ichips.intel.com> - 1.2.9 
- DAT/DAPL Version 1.2.9 Release 1, OFED 1.4 RC 

* Tue Jun 23 2008 Arlin Davis <ardavis@ichips.intel.com> - 1.2.8 
- DAT/DAPL Version 1.2.8 Release 1, socket CM provider

* Tue May 20 2008 Arlin Davis <ardavis@ichips.intel.com> - 1.2.7
- DAT/DAPL Version 1.2.7 Release 1, OFED 1.3.1 GA

* Thu May 1 2008 Arlin Davis <ardavis@ichips.intel.com> - 1.2.6
- DAT/DAPL Version 1.2.6 Release 1, OFED 1.3.1 

* Thu Feb 14 2008 Arlin Davis <ardavis@ichips.intel.com> - 1.2.5
- DAT/DAPL Version 1.2.5 Release 1, OFED 1.3 GA 

* Mon Jan 28 2008 Arlin Davis <ardavis@ichips.intel.com> - 1.2.4
- DAT/DAPL Version 1.2.4 Release 1 

* Tue Oct 30 2007 Arlin Davis <ardavis@ichips.intel.com> - 1.2.3
- DAT/DAPL Version 1.2.3 Release 1 

* Wed Sep 26 2007 Arlin Davis <ardavis@ichips.intel.com> - 1.2.2-1
- OFED 1.3-alpha,   DAT/DAPL Version 1.2, Release 2

* Wed Jun 6 2007 Arlin Davis <ardavis@ichips.intel.com> - 1.2.1
- OFED 1.2,   DAT/DAPL Version 1.2, Release 1

* Fri Oct 20 2006 Arlin Davis <ardavis@ichips.intel.com> - 1.2.0
- OFED 1.1,

* Wed May 31 2006 Arlin Davis <ardavis@ichips.intel.com> - 1.2.0
- OFED 1.0
