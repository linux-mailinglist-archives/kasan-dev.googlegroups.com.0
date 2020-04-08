Return-Path: <kasan-dev+bncBCD3NZ4T2IKRBT7WXD2AKGQEKNVRDIA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13a.google.com (mail-il1-x13a.google.com [IPv6:2607:f8b0:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id 30B521A2ABA
	for <lists+kasan-dev@lfdr.de>; Wed,  8 Apr 2020 23:00:01 +0200 (CEST)
Received: by mail-il1-x13a.google.com with SMTP id f68sf8114949ilg.9
        for <lists+kasan-dev@lfdr.de>; Wed, 08 Apr 2020 14:00:01 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1586379599; cv=pass;
        d=google.com; s=arc-20160816;
        b=wmBOwKh5aaPYlahizBLJBqTaiTu74zlDECPYJoOwatR8UUC54N0Z5+c4R6Dzf9HCdh
         nB0zmENR+krRzjv0prG5ftfoC4DEwyGUS87WXxluNjoXmJ/9e/Tz1+AwGzQzO5XeyscM
         y0YjwiBAj8N9Bajq9v6r0RPQk967WBCxgaBNn81Sd0kpmr1AsT7CI0X7QS2l//hk75wd
         Rz3FZHmVm+4tZxD5tehSLDoIDJm2cCPH3V8F0M7pRd2c0QJM59yFAivBDbyh3o2Omnqo
         QEKs8UsBG0OPW8cwPDtxOPBpGGhV4S8XR8x6+BW8f5j2cJxRn/6QhTCwbqcgBeZk9vEv
         AwkQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:cc:date:message-id:subject
         :mime-version:content-transfer-encoding:from:sender:dkim-signature;
        bh=RsVPdUTl6H3Xl/wYch71evy3ktTe66vXzEtG3frZC34=;
        b=RHtX6kjGq2PCnMMQ6DJgIxyw/Ud0Acw8UIP5+tvfGn/5XQhbSavJs90TU3UgdyJ2hh
         X11Pl9jglEyYtDoeyy9/KGndx/c7J2A81wwltp2dp9kaXpZgBuiOtrY8SwNUMfAhiMH+
         ne5Bj/JTXN0Fp9hUxEKIIMc5j7+fXLr2MBnKJrdGaWNE2xSVsAQl6AjOhEZ+/ozcmRDW
         ZK2wW8ZpW/SZk5PsYwKXQOsjOSq4fVyMWPvJ2+pYmshe03PDCSTdlW1IUu4X3T28Nlk1
         Pm8zJQrgAEdk1NdtQWty3OEia+e25lbr2NYqISDeLIITtd38zjBrmgQcyWav+nVYsyLr
         /X6A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@lca.pw header.s=google header.b=S3jXt6pL;
       spf=pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::f2b as permitted sender) smtp.mailfrom=cai@lca.pw
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:content-transfer-encoding:mime-version:subject
         :message-id:date:cc:to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=RsVPdUTl6H3Xl/wYch71evy3ktTe66vXzEtG3frZC34=;
        b=OVfYFnyY/qG+JLDkEJjNh4GTVzZDTa7+jiQOS3sO7pqPNvjOHq8+xKaYKSlF9m4ANK
         yIz8aqxf4yt/G2o1uY8k7tMRIyG26jtci/OHUzDrWP3J9FVI0YZDluJnAlgZvGtq6ome
         fu9XBfyU1z3vBoAqZUWuquLC3f43//k2ODAqkPEBVUu0waWRk/eWDdjOHmtADoOFcq/b
         oEEPnNaYKEpEGcHwbnGzV2MfQjMfc0t99YaZ1CJYmjNha1nKKODXQU1vIDowjvRY0mt4
         e371qSGFqBzoEnNWssHRn07eIrM3xKyoJSM27RBsMwu2vLKr90HkpBwGwOumTope7ZIw
         l1cA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:content-transfer-encoding
         :mime-version:subject:message-id:date:cc:to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=RsVPdUTl6H3Xl/wYch71evy3ktTe66vXzEtG3frZC34=;
        b=GN6xr41qS/evZsHtjtVnzE3Eodw0NPQ8EEgU/Hex80IM44q1FI7A20rQXGiq31UFbK
         NsFKNp/apog+/VkU/gngVJg8xLc4LCX1vOFI2+TDqmMKgXikEuLUQgblN40C2BSkWQZK
         s+bpqHxHxcY12k0KdoF3CyXzan8zMa2uhf0shmxJ9I7LVUBQrEpjYNOyWcIlRcR5Fqaz
         RYJF3mw9XuxqNdy0AAOUq+oZ4VF6E1LCuvlabflDFAaujueSxVr/t7ohNf5XLDCo0gwv
         JX4FTzsWXYYs1CTAe+yoshAoWbEePYR5rvLLWA1NUG5yfDyxVWaxMf61yFwlciVGWgrn
         MJNA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AGi0PuYomAq1TJdq1Eg92DWds0oh5Vl0z0bOal4qagLOFMHoNe6e5/CG
	VeVfs8R70tzzJxf8uDXLp64=
X-Google-Smtp-Source: APiQypLeKKsoTtyFirsJkExrPbRSIxXuCPd3ol0qlau15ZQahns9smQU7oScrXWb5X5PUwWfeM5LEA==
X-Received: by 2002:a02:cd03:: with SMTP id g3mr8362998jaq.61.1586379599673;
        Wed, 08 Apr 2020 13:59:59 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:3945:: with SMTP id g66ls510564ila.0.gmail; Wed, 08 Apr
 2020 13:59:59 -0700 (PDT)
X-Received: by 2002:a92:48cb:: with SMTP id j72mr10014617ilg.162.1586379599269;
        Wed, 08 Apr 2020 13:59:59 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1586379599; cv=none;
        d=google.com; s=arc-20160816;
        b=qWwyebKjuSGJDellsks+n+Xz6fviXmJ+VxjpqDjCbt7xT6j7W7VDKlXQJaKRYvz1Ib
         bUCIkvulGdBVJkQDPPEZ2UhTjrAqj4TLhUDhoNHzuKe7MaJtdS8x3u4HWT7OJGMnueXE
         RsjvX0NzWuTT/cgG8nzzuxTikj1BcBxKpqDVxsNNWZ9m90XtfIUUqakDeeAQ+aLxgG8Q
         rS0F+9Ul7mZHot7XbS4whtqJyCvsyJGeez/T4kBZhAKzSiF7108swNRVlch+jQ67uNdJ
         GeRTY8kbm+a6KbNop5HpChmv9QqgNtF5DQabHv212N+gM+svKUvvBAOswInFhshICagx
         zM/A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:cc:date:message-id:subject:mime-version
         :content-transfer-encoding:from:dkim-signature;
        bh=dYstEsSqQX7IaGveGd4y7V+/6JpFwxf+9/QIg+c9QOM=;
        b=R77gpFO3nfDsqBECF0NRlpS2UR7OdIQ7bRgpqky3VPKOjiQCS50HS4ByfKxuGtM413
         u4uYozlDfPnvIIFxfpo1TDu7hH/ihR4zQaSa+syTjh945qJtb/lD2ZlJeItni2ZKNAyX
         NCxyHexZOy6CtTLGjvEy1SA+XjHLLT+x7FO4+LVYcuMw78viE5dbAo/ac3axqqM3qXwf
         d5qtTFYmY46+0b24I6y/HWOeed8L1fllmvRAPfseaxQtMwuPMtdRVUICGF6WDfrVxLW/
         8sNUdIlsWEWC66rGv03quADFYyGyd8/s2SYQQrJwuQOwqh9n12uLWROmG/c5O2QmBO14
         FyXw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@lca.pw header.s=google header.b=S3jXt6pL;
       spf=pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::f2b as permitted sender) smtp.mailfrom=cai@lca.pw
Received: from mail-qv1-xf2b.google.com (mail-qv1-xf2b.google.com. [2607:f8b0:4864:20::f2b])
        by gmr-mx.google.com with ESMTPS id u6si659452ili.3.2020.04.08.13.59.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 08 Apr 2020 13:59:59 -0700 (PDT)
Received-SPF: pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::f2b as permitted sender) client-ip=2607:f8b0:4864:20::f2b;
Received: by mail-qv1-xf2b.google.com with SMTP id s18so4476833qvn.1
        for <kasan-dev@googlegroups.com>; Wed, 08 Apr 2020 13:59:59 -0700 (PDT)
X-Received: by 2002:a0c:9e68:: with SMTP id z40mr9255056qve.242.1586379598529;
        Wed, 08 Apr 2020 13:59:58 -0700 (PDT)
Received: from [192.168.1.153] (pool-71-184-117-43.bstnma.fios.verizon.net. [71.184.117.43])
        by smtp.gmail.com with ESMTPSA id w30sm21219394qtw.21.2020.04.08.13.59.57
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 08 Apr 2020 13:59:57 -0700 (PDT)
From: Qian Cai <cai@lca.pw>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
Mime-Version: 1.0 (Mac OS X Mail 13.4 \(3608.80.23.2.2\))
Subject: KCSAN + KVM = host reset
Message-Id: <E180B225-BF1E-4153-B399-1DBF8C577A82@lca.pw>
Date: Wed, 8 Apr 2020 16:59:56 -0400
Cc: "paul E. McKenney" <paulmck@kernel.org>,
 Paolo Bonzini <pbonzini@redhat.com>,
 kasan-dev <kasan-dev@googlegroups.com>,
 LKML <linux-kernel@vger.kernel.org>,
 kvm@vger.kernel.org
To: Elver Marco <elver@google.com>
X-Mailer: Apple Mail (2.3608.80.23.2.2)
X-Original-Sender: cai@lca.pw
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@lca.pw header.s=google header.b=S3jXt6pL;       spf=pass
 (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::f2b as
 permitted sender) smtp.mailfrom=cai@lca.pw
Precedence: list
Mailing-list: list kasan-dev@googlegroups.com; contact kasan-dev+owners@googlegroups.com
List-ID: <kasan-dev.googlegroups.com>
X-Spam-Checked-In-Group: kasan-dev@googlegroups.com
X-Google-Group-Id: 358814495539
List-Post: <https://groups.google.com/group/kasan-dev/post>, <mailto:kasan-dev@googlegroups.com>
List-Help: <https://groups.google.com/support/>, <mailto:kasan-dev+help@googlegroups.com>
List-Archive: <https://groups.google.com/group/kasan-dev
List-Subscribe: <https://groups.google.com/group/kasan-dev/subscribe>, <mailto:kasan-dev+subscribe@googlegroups.com>
List-Unsubscribe: <mailto:googlegroups-manage+358814495539+unsubscribe@googlegroups.com>,
 <https://groups.google.com/group/kasan-dev/subscribe>

Running a simple thing on this AMD host would trigger a reset right away.
Unselect KCSAN kconfig makes everything work fine (the host would also
reset If only "echo off > /sys/kernel/debug/kcsan=E2=80=9D before running q=
emu-kvm).

/usr/libexec/qemu-kvm -name ubuntu-18.04-server-cloudimg -cpu host -smp 2 -=
m 2G -hda ubuntu-18.04-server-cloudimg.qcow2 -cdrom ubuntu-18.04-server-clo=
udimg.iso -nic user,hostfwd=3Dtcp::2222-:22 -serial mon:stdio -nographic

With this config on today=E2=80=99s linux-next,

https://raw.githubusercontent.com/cailca/linux-mm/master/kcsan.config

Cherry-picked a few commits from -rcu (in case if it ever matters)

48b1fc1 kcsan: Add option to allow watcher interruptions
2402d0e kcsan: Add option for verbose reporting
43f7646 x86/mm/pat: Mark an intentional data race

=3D=3D=3D console output =3D=3D=3D
Kernel 5.6.0-next-20200408+ on an x86_64

hp-dl385g10-05 login:=20

<...host reset...>

=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
HPE ProLiant System BIOS A40 v1.20 (03/09/2018)
(C) Copyright 1982-2018 Hewlett Packard Enterprise Development LP
Early system initialization, please wait...=20


iLO 5 IPv4: 10.73.196.44
iLO 5 IPv6: FE80::D6C9:EFFF:FECE:717E

  2%: Early Processor Initialization
  4%: Processor Root Ports Initialization
  8%: SMBIOS Table Initialization
 12%: HPE SmartMemory Initialization
 17%: iLO Embedded Health Initialization
 21%: ACPI Table Initialization
 25%: System Security Initialization
 30%: BIOS Configuration Initialization
 39%: Early PCI Initialization - Start
 47%: Early PCI Initialization - Complete
 60%: Switching console output to Primary Video. Please wait=E2=80=A6
=3D=3D=3D=3D=3D=3D=3D=3D

# lscpu
Architecture:        x86_64
CPU op-mode(s):      32-bit, 64-bit
Byte Order:          Little Endian
CPU(s):              32
On-line CPU(s) list: 0-31
Thread(s) per core:  2
Core(s) per socket:  8
Socket(s):           2
NUMA node(s):        8
Vendor ID:           AuthenticAMD
CPU family:          23
Model:               1
Model name:          AMD EPYC 7251 8-Core Processor
Stepping:            2
CPU MHz:             2830.383
CPU max MHz:         2100.0000
CPU min MHz:         1200.0000
BogoMIPS:            4191.58
Virtualization:      AMD-V
L1d cache:           32K
L1i cache:           64K
L2 cache:            512K
L3 cache:            4096K
NUMA node0 CPU(s):   0,1,16,17
NUMA node1 CPU(s):   2,3,18,19
NUMA node2 CPU(s):   4,5,20,21
NUMA node3 CPU(s):   6,7,22,23
NUMA node4 CPU(s):   8,9,24,25
NUMA node5 CPU(s):   10,11,26,27
NUMA node6 CPU(s):   12,13,28,29
NUMA node7 CPU(s):   14,15,30,31
Flags:               fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge m=
ca cmov pat pse36 clflush mmx fxsr sse sse2 ht syscall nx mmxext fxsr_opt p=
dpe1gb rdtscp lm constant_tsc rep_good nopl nonstop_tsc cpuid extd_apicid a=
md_dcm aperfmperf pni pclmulqdq monitor ssse3 fma cx16 sse4_1 sse4_2 movbe =
popcnt aes xsave avx f16c rdrand lahf_lm cmp_legacy svm extapic cr8_legacy =
abm sse4a misalignsse 3dnowprefetch osvw skinit wdt tce topoext perfctr_cor=
e perfctr_nb bpext perfctr_llc mwaitx cpb hw_pstate ssbd ibpb vmmcall fsgsb=
ase bmi1 avx2 smep bmi2 rdseed adx smap clflushopt sha_ni xsaveopt xsavec x=
getbv1 xsaves clzero irperf xsaveerptr arat npt lbrv svm_lock nrip_save tsc=
_scale vmcb_clean flushbyasid decodeassists pausefilter pfthreshold avic v_=
vmsave_vmload vgif overflow_recov succor smca

# cat /sys/kernel/debug/kcsan=20
enabled: 1
used_watchpoints: 0
setup_watchpoints: 13777602
data_races: 47
assert_failures: 0
no_capacity: 598865
report_races: 0
races_unknown_origin: 226
unencodable_accesses: 0
encoding_false_positives: 0

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/E180B225-BF1E-4153-B399-1DBF8C577A82%40lca.pw.
