Return-Path: <kasan-dev+bncBCD3NZ4T2IKRBDOSQH2QKGQEKQYIJBI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd39.google.com (mail-io1-xd39.google.com [IPv6:2607:f8b0:4864:20::d39])
	by mail.lfdr.de (Postfix) with ESMTPS id 6FB911B4939
	for <lists+kasan-dev@lfdr.de>; Wed, 22 Apr 2020 17:55:59 +0200 (CEST)
Received: by mail-io1-xd39.google.com with SMTP id a12sf2574442ioe.17
        for <lists+kasan-dev@lfdr.de>; Wed, 22 Apr 2020 08:55:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1587570958; cv=pass;
        d=google.com; s=arc-20160816;
        b=lj4M/a0B7J0CqXzJv9AhsG0pzgvjzw3kznR5H12Z8xZhPI8PELGaztbSteSBtagce9
         nNa/r21tgzHOoKgfW/vJHMxqV8PUOyFiQsu53NkN+eVhX4DSwGSqAWbYdDK57AR3fohx
         u5hV5rewndR7sNc1AOH+MqQ/3yh4V/K8OHzOlJovHeEk3vpH4sFzG8SvujwkMmN7yfPW
         OieQE26uHc1RaDHXmYSTQ0a5yFA6qjjyulRxdymCJZ071elfb/kBfPACSY3YLEkVMZBg
         7LakzGgnIWq/Y1tkV+i8OvMyUGK1ymbQgZkVER3i3kyEolmKufASO81ZzKJiK7o18k2x
         EPsg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:cc:date:message-id:subject
         :mime-version:content-transfer-encoding:from:sender:dkim-signature;
        bh=V1/dtwG8s1mZCyua3Z7KbcENW4w6dXW5nYeY+uRvnCw=;
        b=uAnRF7tmUaO070lJBRf0vsm6j7FNu9v8TtT7u7gfmFfaZok4pIatlrIasqjGDym/Qn
         iFQM1EgP3sT3kxssLE2p32YYU8apNQKPvnFSCwfVWR60lJ0rWR9OLK4RolJ2UQJd5MB2
         cE9kCrmobXViriKHECDS/dkCgmdpFULb41+gsqlQeyV2IuWjp55yHlT7f4RzHIp1FRde
         mB6UvYYhQHxSudAnfNU3z4RRl25dHZzUEa9L4tikjf5SVWI0RfDw91mifmqJSqYaMfGL
         vQFBcH2/lJPyh/d12eb0/IFLfr7vw4gbCaEm/42ms1jO7BcN9ntN8/5SwwhcPc7k+VZJ
         oGbg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@lca.pw header.s=google header.b=c6WioayN;
       spf=pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::830 as permitted sender) smtp.mailfrom=cai@lca.pw
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:content-transfer-encoding:mime-version:subject
         :message-id:date:cc:to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=V1/dtwG8s1mZCyua3Z7KbcENW4w6dXW5nYeY+uRvnCw=;
        b=KYbO0MMhWJVVXZiC2a61RCFqMAe8XG0NC/6a8SCEfWhfHxNtf9CytIE/OuNjKUqVy3
         XdnWomLzXcnwW1pXkatOISda993dRlmsfZm2gCnWUJp/ZulHbR3W61XQDXdMIIJ74Mtw
         CAP05Xv+CQhX/W7NjxbemcN4C6nP8CcrZDfnhSJwt0roPPvD9xjFICGIjbTERdE6KTnu
         yE5ss91KiKg6g8uR9VNEZNdRxRa8j+aKaaFGWDFcYC+HZDUZjAFKI9xpYsEr9OxoGP1Q
         fIKGK2axyww8xoirEn+uwx/ARpNfhPuMv8XSXq+QFgES/gSdMElW6erh9E5fH2wjXjKg
         6USA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:content-transfer-encoding
         :mime-version:subject:message-id:date:cc:to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=V1/dtwG8s1mZCyua3Z7KbcENW4w6dXW5nYeY+uRvnCw=;
        b=A3rbsEWnFdxbRtDMyiOkdm9uk41czloAVHDANADs/eoMFexrSNKilR+dQfcEhYidLG
         sN/RNt9KOmEvPwGKxlYS1PUGYdbbt01RMMWnXfDSe9Cj4NLAe5PYEdE0EPeNgQ0X4ga9
         ZcAbXlbEQr/5VoVRkmI8ldIyHJoA3FtdI670OhUn2rTiDJXqrUYGs+xWQbuSXRbVIIDM
         Z++jsSmF/IHPxi6a38uwkNSpOoKGmuzKxvHNw6yQKXEPACMRegBZ26V9CaCSIEyn+Qal
         Gs8Prz4AWSxbrZocgXOQALAZLHip9o7fY2zidVoQ1jKVko712R8gsA9mm7wCvy/CB5zU
         HuZQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AGi0Puaic3MkpTO0dYp2VOeN1TdSTotvwNx5JuwVriDE78xcGMsAWlq9
	4Q2ZrbvcgtKR/EGdMEwcX54=
X-Google-Smtp-Source: APiQypKkhZVR5AKUJa2704GZfinQc8m/AbNOy4UqePQc5tzdmolm4XkZ5PPKnx08HAZHCjaouY9hJg==
X-Received: by 2002:a05:6e02:790:: with SMTP id q16mr25090144ils.60.1587570958032;
        Wed, 22 Apr 2020 08:55:58 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a6b:610a:: with SMTP id v10ls658002iob.9.gmail; Wed, 22 Apr
 2020 08:55:57 -0700 (PDT)
X-Received: by 2002:a5e:c804:: with SMTP id y4mr26440004iol.58.1587570957349;
        Wed, 22 Apr 2020 08:55:57 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1587570957; cv=none;
        d=google.com; s=arc-20160816;
        b=lk51/qXmxd1e30cLDL50kjUenAqu6O5JWGcsdzh3wo+3zHmB3gPMoxvZOiVplORgOE
         /2Hc+LQc1lZOUr2HEoitUhRaLLpFj8Am1iEdNp9Nzf8vEzhApT/Hz1ctVuCaNd2YQDbI
         YUjeJ1W9+Yi08txi6UyxeSs7ySvG7wQi8We5MZGQDhDiKd0CguJppV0+b7eqTqT0jHZR
         DGY1rQelt79PMYqDT5BT8p59QQVVALoZxUwniHDBzvlLZuLV2jZbBUHymnypOx0XgXKS
         qMR145N+vz4Bn/KHA4yfe38YP4gZ4sW0vMSmKmN38K7k9LWkDihKdRmUo4QzXPWe2t5p
         3awg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:cc:date:message-id:subject:mime-version
         :content-transfer-encoding:from:dkim-signature;
        bh=lYFc3VEojR2qbu+rsSnzrVBUC5UN+0hnVvXP8dVpMPI=;
        b=q1pHrf+18reA2bkHEgqSWocz33Z4qRHT2fUeK+DcygIBtUkJYhsGMB8TFkAT9XAeYK
         e+IGGSl/vO0c5UPZ/v4Y2pCv1zNh/URUS8ZJmo/mXutqF0cELEgVaULmReaHyT034oe8
         kwdrDXOkk7RwfBlpMCP8+ADXotcKaNUIXvLFp6OfLvHatz+wxcV4Jx+mEJ7Emlwg3P75
         19oV63E08XMYR7GhF10BJDt6+A6ItKW39Y0tZ8A6IFz9R6kiMFLRcLTVurQyyeoYZpAe
         C5sY0Dv2jRATfM5Gi8+zySypckDIj/K4tn4dyX/sN9isRg+waCnuMoj4WIh51eT5btW8
         HBCQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@lca.pw header.s=google header.b=c6WioayN;
       spf=pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::830 as permitted sender) smtp.mailfrom=cai@lca.pw
Received: from mail-qt1-x830.google.com (mail-qt1-x830.google.com. [2607:f8b0:4864:20::830])
        by gmr-mx.google.com with ESMTPS id j21si125210iow.4.2020.04.22.08.55.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 22 Apr 2020 08:55:57 -0700 (PDT)
Received-SPF: pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::830 as permitted sender) client-ip=2607:f8b0:4864:20::830;
Received: by mail-qt1-x830.google.com with SMTP id l13so2034689qtr.7
        for <kasan-dev@googlegroups.com>; Wed, 22 Apr 2020 08:55:57 -0700 (PDT)
X-Received: by 2002:ac8:514d:: with SMTP id h13mr27475497qtn.226.1587570956541;
        Wed, 22 Apr 2020 08:55:56 -0700 (PDT)
Received: from [192.168.1.153] (pool-71-184-117-43.bstnma.fios.verizon.net. [71.184.117.43])
        by smtp.gmail.com with ESMTPSA id p22sm4384866qte.2.2020.04.22.08.55.55
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 22 Apr 2020 08:55:56 -0700 (PDT)
From: Qian Cai <cai@lca.pw>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
Mime-Version: 1.0 (Mac OS X Mail 13.4 \(3608.80.23.2.2\))
Subject: AMD boot woe due to "x86/mm: Cleanup pgprot_4k_2_large() and
 pgprot_large_2_4k()"
Message-Id: <1ED37D02-125F-4919-861A-371981581D9E@lca.pw>
Date: Wed, 22 Apr 2020 11:55:54 -0400
Cc: Borislav Petkov <bp@suse.de>,
 "Peter Zijlstra (Intel)" <peterz@infradead.org>,
 x86 <x86@kernel.org>,
 LKML <linux-kernel@vger.kernel.org>,
 kasan-dev <kasan-dev@googlegroups.com>
To: Christoph Hellwig <hch@lst.de>
X-Mailer: Apple Mail (2.3608.80.23.2.2)
X-Original-Sender: cai@lca.pw
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@lca.pw header.s=google header.b=c6WioayN;       spf=pass
 (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::830 as
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

Reverted the linux-next commit and its dependency,

a85573f7e741 ("x86/mm: Unexport __cachemode2pte_tbl=E2=80=9D)
9e294786c89a (=E2=80=9Cx86/mm: Cleanup pgprot_4k_2_large() and pgprot_large=
_2_4k()=E2=80=9D)

fixed crashes or hard reset on AMD machines during boot that have been flag=
ged by
KASAN in different forms indicating some sort of memory corruption with thi=
s config,

https://raw.githubusercontent.com/cailca/linux-mm/master/x86.config

[    0.000000] ACPI: LAPIC_NMI (acpi_id[0x71] high level lint[0x1])
[    0.000000] ACPI: LAPIC_NMI (acpi_id[0x78] high level lint[0x1])
[    0.000000] ACPI: LAPIC_NMI (acpi_id[0x79] high level lint[0x1])
[    0.000000] BUG: unable to handle page fault for address: ffffed107c782f=
ff
[    0.000000] #PF: supervisor read access in kernel mode
[    0.000000] #PF: error_code(0x0000) - not-present page
[    0.000000] =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
[    0.000000] BUG: KASAN: stack-out-of-bounds in cmp_ex_search+0x1e/0x40
ex_to_insn at lib/extable.c:20
(inlined by) cmp_ex_search at lib/extable.c:101
[    0.000000] Read of size 4 at addr ffffffffae27cae4 by task swapper/0[  =
  0.000000] CPU: 0 PID: 0 Comm: swapper Not tainted 5.7.0-rc2-next-20200422=
+ #4
[    0.000000]
[    0.000000] Hardware name: HPE ProLiant DL385 Gen10/ProLiant DL385 Gen10=
, BIOS A40 03/09/2018
[    0.000000] Call Trace:
[    0.000000]=20
[    0.000000] The buggy address belongs to the variable:
[    0.000000]  __start___ex_table+0x1cd4/0x2670
[    0.000000]=20
[    0.000000] Memory state around the buggy address:
[    0.000000]  ffffffffae27c980: 00 00 00 00 00 00 00 00 00 00 00 00 00 00=
 00 00
[    0.000000]  ffffffffae27ca00: 00 00 00 00 00 00 00 00 00 00 00 00 00 00=
 00 00
[    0.000000] >ffffffffae27ca80: 00 00 00 00 00 f1 f1 f1 f1 00 f2 f2 f2 00=
 00 00
[    0.000000]                                                        ^
[    0.000000]  ffffffffae27cb00: 00 00 00 00 00 00 00 00 00 00 00 00 00 00=
 00 00
[    0.000000]  ffffffffae27cb80: 00 00 00 00 00 f1 f1 f1 f1 02 f2 f2 f2 f2=
 f2 f2
[    0.000000] =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D


[    5.125583][    T0] BUG: KASAN: null-ptr-deref in __check_object_size+0x=
12c/0x503
__read_once_size at include/linux/compiler.h:199
(inlined by) compound_head at include/linux/page-flags.h:182
(inlined by) PageSlab at include/linux/page-flags.h:333
(inlined by) check_heap_object at mm/usercopy.c:238
(inlined by) __check_object_size at mm/usercopy.c:286
(inlined by) __check_object_size at mm/usercopy.c:256
[    5.133083][    T0] Read of size 8 at addr 0000000000000006 by task swap=
per/0
[    5.140244][    T0]=20
[    5.142434][    T0] CPU: 0 PID: 0 Comm: swapper Not tainted 5.7.0-rc2+ #=
8
[    5.149241][    T0] Hardware name: HPE ProLiant DL385 Gen10/ProLiant DL3=
85 Gen10, BIOS A40 07/10/2019
[    5.158502][    T0] Call Trace:
[    5.161654][    T0]  ? do_raw_spin_lock+0x11e/0x1e0
[    5.166542][    T0]  ? rwlock_bug.part.0+0x60/0x60
[    5.171348][    T0]  ? bad_area_nosemaphore+0x16/0x20
[    5.176409][    T0]  ? do_page_fault+0x44b/0x9d7
[    5.181043][    T0]  ? trace_hardirqs_off_thunk+0x1a/0x1c
[    5.186459][    T0]  ? page_fault+0x34/0x40
[    5.190649][    T0]  ? dump_pagetable+0xf3/0x3b0
[    5.195280][    T0]  ? __asan_load8+0x40/0xb0
[    5.199645][    T0]  ? dump_pagetable+0xf3/0x3b0
[    5.204274][    T0]  ? vmalloc_fault+0x450/0x450
[    5.208906][    T0]  ? search_exception_tables+0x4c/0x50
[    5.214231][    T0]  ? fixup_exception+0x38/0x92
[    5.218861][    T0]  ? no_context.cold.21+0x160/0x2e0
[    5.223928][    T0]  ? pgtable_bad+0x80/0x80
[    5.228209][    T0]  ? register_lock_class+0xb40/0xb40
[    5.233362][    T0]  ? register_lock_class+0xb40/0xb40
[    5.238519][    T0]  ? snprintf+0xc0/0xc0
[    5.242538][    T0]  ? debug_lockdep_rcu_enabled+0x11/0x60
[    5.248039][    T0]  ? debug_lockdep_rcu_enabled+0x11/0x60
[    5.253538][    T0]  ? console_unlock+0x3e5/0x740
[    5.258257][    T0]  ? console_unlock+0x3ff/0x740
[    5.262975][    T0]  ? __bad_area_nosemaphore+0x66/0x230
[    5.268303][    T0]  ? do_raw_spin_lock+0x11e/0x1e0
[    5.273193][    T0]  ? rwlock_bug.part.0+0x60/0x60
[    5.277998][    T0]  ? bad_area_nosemaphore+0x16/0x20
[    5.283064][    T0]  ? do_page_fault+0x44b/0x9d7
[    5.287694][    T0]  ? trace_hardirqs_off_thunk+0x1a/0x1c
[    5.293111][    T0]  ? page_fault+0x34/0x40
[    5.297303][    T0]  ? dump_pagetable+0xf3/0x3b0
[    5.301933][    T0]  ? __asan_load8+0x40/0xb0
[    5.306300][    T0]  ? dump_pagetable+0xf3/0x3b0
[    5.310929][    T0]  ? vmalloc_fault+0x450/0x450
[    5.315560][    T0]  ? search_exception_tables+0x4c/0x50
[    5.320886][    T0]  ? fixup_exception+0x38/0x92
[    5.325518][    T0]  ? no_context.cold.21+0x160/0x2e0
[    5.330582][    T0]  ? pgtable_bad+0x80/0x80
[    5.334863][    T0]  ? register_lock_class+0xb40/0xb40
[    5.340018][    T0]  ? register_lock_class+0xb40/0xb40
[    5.345171][    T0]  ? snprintf+0xc0/0xc0
[    5.349190][    T0]  ? debug_lockdep_rcu_enabled+0x11/0x60
[    5.354694][    T0]  ? debug_lockdep_rcu_enabled+0x11/0x60
[    5.360521][    T0]  ? console_unlock+0x3e5/0x740
[    5.365235][    T0]  ? console_unlock+0x3ff/0x740
[    5.369954][    T0]  ? __bad_area_nosemaphore+0x66/0x230
[    5.375282][    T0]  ? do_raw_spin_lock+0x11e/0x1e0
[    5.380174][    T0]  ? rwlock_bug.part.0+0x60/0x60
[    5.384977][    T0]  ? bad_area_nosemaphore+0x16/0x20
[    5.390044][    T0]  ? do_page_fault+0x44b/0x9d7
[    5.394674][    T0]  ? trace_hardirqs_off_thunk+0x1a/0x1c
[    5.400090][    T0]  ? page_fault+0x34/0x40
[    5.404282][    T0]  ? dump_pagetable+0xf3/0x3b0
[    5.408912][    T0]  ? __asan_load8+0x40/0xb0
[    5.413279][    T0]  ? dump_pagetable+0xf3/0x3b0
[    5.417908][    T0]  ? vmalloc_fault+0x450/0x450
[    5.422538][    T0]  ? search_exception_tables+0x4c/0x50
[    5.427868][    T0]  ? fixup_exception+0x38/0x92
[    5.432496][    T0]  ? no_context.cold.21+0x160/0x2e0
[    5.437562][    T0]  ? pgtable_bad+0x80/0x80
[    5.441843][    T0]  ? register_lock_class+0xb40/0xb40
[    5.446996][    T0]  ? register_lock_class+0xb40/0xb40
[    5.452152][    T0]  ? snprintf+0xc0/0xc0
[    5.456170][    T0]  ? debug_lockdep_rcu_enabled+0x11/0x60
[    5.461674][    T0]  ? debug_lockdep_rcu_enabled+0x11/0x60
[    5.467173][    T0]  ? console_unlock+0x3e5/0x740
[    5.471891][    T0]  ? console_unlock+0x3ff/0x740
[    5.476609][    T0]  ? __bad_area_nosemaphore+0x66/0x230
[    5.481937][    T0]  ? do_raw_spin_lock+0x11e/0x1e0
[    5.486829][    T0]  ? rwlock_bug.part.0+0x60/0x60
[    5.491632][    T0]  ? bad_area_nosemaphore+0x16/0x20
[    5.496699][    T0]  ? do_page_fault+0x44b/0x9d7
[    5.501329][    T0]  ? trace_hardirqs_off_thunk+0x1a/0x1c
[    5.506746][    T0]  ? page_fault+0x34/0x40
[    5.510938][    T0]  ? dump_pagetable+0xf3/0x3b0
[    5.515568][    T0]  ? __asan_load8+0x40/0xb0
[    5.519935][    T0]  ? dump_pagetable+0xf3/0x3b0
[    5.524564][    T0]  ? vmalloc_fault+0x450/0x450
[    5.529194][    T0]  ? search_exception_tables+0x4c/0x50
[    5.534521][    T0]  ? fixup_exception+0x38/0x92
[    5.539153][    T0]  ? no_context.cold.21+0x160/0x2e0
[    5.544218][    T0]  ? pgtable_bad+0x80/0x80
[    5.548499][    T0]  ? register_lock_class+0xb40/0xb40
[    5.553652][    T0]  ? register_lock_class+0xb40/0xb40
[    5.558805][    T0]  ? snprintf+0xc0/0xc0
[    5.562826][    T0]  ? debug_lockdep_rcu_enabled+0x11/0x60
[    5.568327][    T0]  ? debug_lockdep_rcu_enabled+0x11/0x60
[    5.573829][    T0]  ? console_unlock+0x3e5/0x740
[    5.578546][    T0]  ? console_unlock+0x3ff/0x740
[    5.583265][    T0]  ? __bad_area_nosemaphore+0x66/0x230
[    5.588592][    T0]  ? do_raw_spin_lock+0x11e/0x1e0
[    5.593485][    T0]  ? rwlock_bug.part.0+0x60/0x60
[    5.598290][    T0]  ? bad_area_nosemaphore+0x16/0x20
[    5.603354][    T0]  ? do_page_fault+0x44b/0x9d7
[    5.607985][    T0]  ? trace_hardirqs_off_thunk+0x1a/0x1c
[    5.613401][    T0]  ? page_fault+0x34/0x40
[    5.617594][    T0]  ? dump_pagetable+0xf3/0x3b0
[    5.622224][    T0]  ? __asan_load8+0x40/0xb0
[    5.626590][    T0]  ? dump_pagetable+0xf3/0x3b0
[    5.631219][    T0]  ? vmalloc_fault+0x450/0x450
[    5.635849][    T0]  ? search_exception_tables+0x4c/0x50
[    5.641176][    T0]  ? fixup_exception+0x38/0x92
[    5.645809][    T0]  ? no_context.cold.21+0x160/0x2e0
[    5.650874][    T0]  ? pgtable_bad+0x80/0x80
[    5.655154][    T0]  ? register_lock_class+0xb40/0xb40
[    5.660307][    T0]  ? register_lock_class+0xb40/0xb40
[    5.665461][    T0]  ? snprintf+0xc0/0xc0
[    5.669480][    T0]  ? debug_lockdep_rcu_enabled+0x11/0x60
[    5.674983][    T0]  ? debug_lockdep_rcu_enabled+0x11/0x60
[    5.680485][    T0]  ? console_unlock+0x3e5/0x740
[    5.685202][    T0]  ? console_unlock+0x3ff/0x740
[    5.689921][    T0]  ? __bad_area_nosemaphore+0x66/0x230
[    5.695248][    T0]  ? do_raw_spin_lock+0x11e/0x1e0
[    5.700141][    T0]  ? rwlock_bug.part.0+0x60/0x60
[    5.704945][    T0]  ? bad_area_nosemaphore+0x16/0x20
[    5.710010][    T0]  ? do_page_fault+0x44b/0x9d7
[    5.714639][    T0]  ? trace_hardirqs_off_thunk+0x1a/0x1c
[    5.720056][    T0]  ? page_fault+0x34/0x40
[    5.724249][    T0]  ? dump_pagetable+0xf3/0x3b0
[    5.728878][    T0]  ? __asan_load8+0x40/0xb0
[    5.733246][    T0]  ? dump_pagetable+0xf3/0x3b0
[    5.737875][    T0]  ? vmalloc_fault+0x450/0x450
[    5.742505][    T0]  ? search_exception_tables+0x4c/0x50
[    5.747832][    T0]  ? fixup_exception+0x38/0x92
[    5.752462][    T0]  ? no_context.cold.21+0x160/0x2e0
[    5.757529][    T0]  ? pgtable_bad+0x80/0x80
[    5.761809][    T0]  ? register_lock_class+0xb40/0xb40
[    5.766962][    T0]  ? register_lock_class+0xb40/0xb40
[    5.772118][    T0]  ? snprintf+0xc0/0xc0
[    5.776137][    T0]  ? debug_lockdep_rcu_enabled+0x11/0x60
[    5.781639][    T0]  ? debug_lockdep_rcu_enabled+0x11/0x60
[    5.787144][    T0]  ? console_unlock+0x3e5/0x740
[    5.791857][    T0]  ? console_unlock+0x3ff/0x740
[    5.796576][    T0]  ? __bad_area_nosemaphore+0x66/0x230
[    5.801903][    T0]  ? do_raw_spin_lock+0x11e/0x1e0
[    5.806796][    T0]  ? rwlock_bug.part.0+0x60/0x60
[    5.811601][    T0]  ? bad_area_nosemaphore+0x16/0x20
[    5.816665][    T0]  ? do_page_fault+0x44b/0x9d7
[    5.821295][    T0]  ? trace_hardirqs_off_thunk+0x1a/0x1c
[    5.826711][    T0]  ? page_fault+0x34/0x40
[    5.830904][    T0]  ? dump_pagetable+0xf3/0x3b0
[    5.835534][    T0]  ? __asan_load8+0x40/0xb0
[    5.839901][    T0]  ? dump_pagetable+0xf3/0x3b0
[    5.844530][    T0]  ? vmalloc_fault+0x450/0x450
[    5.849160][    T0]  ? search_exception_tables+0x4c/0x50
[    5.854487][    T0]  ? fixup_exception+0x38/0x92
[    5.859120][    T0]  ? no_context.cold.21+0x160/0x2e0
[    5.864185][    T0]  ? pgtable_bad+0x80/0x80
[    5.868465][    T0]  ? register_lock_class+0xb40/0xb40
[    5.873618][    T0]  ? register_lock_class+0xb40/0xb40
[    5.878773][   6.262157][    T0]  ? __asan_load8+0x40/0xb0
[    6.266523][    T0]  ? dump_pagetable+0xf3/0x3b0
[    6.271152][    T0]  ? vmalloc_fault+0x450/0x450
[    6.275782][    T0]  ? search_exception_tables+0x4c/0x50
[    6.281109][    T0]  ? fixup_exception+0x38/0x92
[    6.285739][    T0]  ? no_context.cold.21+0x160/0x2e0
[    6.290807][    T0]  ? pgtable_bad+0x80/0x80
[    6.295087][    T0]  ? register_lock_class+0xb40/0xb40
[    6.300240][    T0]  ? register_lock_class+0xb40/0xb40
[    6.305394][    T0]  ? snprintf+0xc0/0xc0
[    6.309413][    T0]  ? debug_lockdep_rcu_enabled+0x11/0x60
[    6.314917][    T0]  ? debug_lockdep_rcu_enabled+0x11/0x60
[    6.320419][    T0]  ? console_unlock+0x3e5/0x740
[    6.325134][    T0]  ? console_unlock+0x3ff/0x740
[    6.329852][    T0]  ? __bad_area_nosemaphore+0x66/0x230
[    6.335180][    T0]  ? do_raw_spin_lock+0x11e/0x1e0
[    6.340072][    T0]  ? rwlock_bug.part.0+0x60/0x60
[    6.344877][    T0]  ? bad_area_nosemaphore+0x16/0x20
[    6.349944][    T0]  ? do_page_fault+0x44b/0x9d7x11/0x60
[    6.741538][    T0]  ? debug_lockdep_rcu_enabled+0x11/0x60
[    6.747040][    T0]  ? console_unlock+0x3e5/0x740
[    6.751757][    T0]  ? console_unlock+0x3ff/0x740
[    6.756476][    T0]  ? __bad_area_nosemaphore+0x66/0x230
[    6.761803][    T0]  ? do_raw_spin_lock+0x11e/0x1e0
[    6.766694][    T0]  ? rwlock_bug.part.0+0x60/0x60
[    6.771500][    T0]  ? bad_area_nosemaphore+0x16/0x20
[    6.776565][    T0]  ? do_page_fault+0x44b/0x9d7
[    6.781196][    T0]  ? trace_hardirqs_off_thunk+0x1a/0x1c
[    6.786610][    T0]  ? page_fault+0x34/0x40
[    6.790805][    T0]  ? dump_pagetable+0xf3/0x3b0
[    6.795432][    T0]  ? __asan_load8+0x40/0xb0
[    6.799801][    T0]  ? dump_pagetable+0xf3/0x3b0
[    6.804430][    T0]  ? vmalloc_fault+0x450/0x450
[    6.809060][    T0]  ? search_exception_tables+0x4c/0x50
[    6.814387][    T0]  ? fixup_exception+0x38/0x92
[    6.819017][    T0]  ? no_context.cold.21+0x160/0x2e0
[    6.824084][    T0]  ? pgtable_bad+0x80/0x80
[    6.828363][    T0]  ? register_lock_class+0xb40/0xb40
[    6.833 T0]  ? dump_pagetable+0xf3/0x3b0
[    7.222054][    T0]  ? __asan_load8+0x40/0xb0
[    7.226423][    T0]  ? dump_pagetable+0xf3/0x3b0
[    7.231052][    T0]  ? vmalloc_fault+0x450/0x450
[    7.235682][    T0]  ? search_exception_tables+0x4c/0x50
[    7.241009][    T0]  ? fixup_exception+0x38/0x92
[    7.245640][    T0]  ? no_context.cold.21+0x160/0x2e0
[    7.250704][    T0]  ? pgtable_bad+0x80/0x80
[    7.254985][    T0]  ? register_lock_class+0xb40/0xb40
[    7.260140][    T0]  ? register_lock_class+0xb40/0xb40
[    7.265293][    T0]  ? snprintf+0xc0/0xc0
[    7.269312][    T0]  ? debug_lockdep_rcu_enabled+0x11/0x60
[    7.274816][    T0]  ? debug_lockdep_rcu_enabled+0x11/0x60
[    7.280317][    T0]  ? console_unlock+0x3e5/0x740
[    7.285035][    T0]  ? console_unlock+0x3ff/0x740
[    7.289751][    T0]  ? __bad_area_nosemaphore+0x66/0x230
[    7.295080][    T0]  ? do_raw_spin_lock+0x11e/0x1e0
[    7.299970][    T0]  ? rwlock_bug.part.0+0x60pgtable_bad+0x80/0x80
[    7.788263][    T0]  ? register_lock_class+0xb40/0xb40
[    7.793415][    T0]  ? register_lock_class+0xb40/0xb40
[    7.798571][    T0]  ? snprintf+0xc0/0xc0
[    7.802590][    T0]  ? debug_lockdep_rcu_enabled+0x11/0x60
[    7.808094][    T0]  ? debug_lockdep_rcu_enabled+0x11/0x60
[    7.813595][    T0]  ? console_unlock+0x3e5/0x740
[    7.818312][    T0]  ? console_unlock+0x3ff/0x740
[    7.823030][    T0]  ? __bad_area_nosemaphore+0x66/0x230
[    7.828357][    T0]  ? do_raw_spin_lock+0x11e/0x1e0
[    7.833250][    T0]  ? rwlock_bug.part.0+0x60/0x60
[    7.838054][    T0]  ? bad_area_nosemaphore+0x16/0x20
[    7.843118][    T0]  ? do_page_fault+0x44b/0x9d7
[    7.847751][    T0]  ? trace_hardirqs_off_thunk+0x1a/0x1c
[    7.853165][    T0]  ? page_fault+0x34/0x40
[    7.857357][    T0]  ? dump_pagetable+0xf3/0x3b0
[    7.861987][    T0]  ? __asan_load8+0x40/0xb0
[    7.866356][    T0]  ? dump_pagetable+0xf3/0x3b0
[    7.870985][    T0]  ? vmalloc_fault+0x450/0x450
[    7.875613][    T0]  ? search_exception_tables    8.264676][    T0]  ? b=
ad_area_nosemaphore+0x16/0x20
[    8.269740][    T0]  ? do_page_fault+0x44b/0x9d7
[    8.274372][    T0]  ? trace_hardirqs_off_thunk+0x1a/0x1c
[    8.279787][    T0]  ? page_fault+0x34/0x40
[    8.283980][    T0]  ? dump_pagetable+0xf3/0x3b0
[    8.288611][    T0]  ? __asan_load8+0x40/0xb0
[    8.292975][    T0]  ? dump_pagetable+0xf3/0x3b0
[    8.297607][    T0]  ? vmalloc_fault+0x450/0x450
[    8.302237][    T0]  ? __kasan_check_write+0x14/0x20
[    8.307220][    T0]  ? debug_locks_off+0x44/0x70
[    8.311845][    T0]  ? no_context.cold.21+0x160/0x2e0
[    8.316910][    T0]  ? __kasan_check_read+0x11/0x20
[    8.321802][    T0]  ? pgtable_bad+0x80/0x80

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/1ED37D02-125F-4919-861A-371981581D9E%40lca.pw.
