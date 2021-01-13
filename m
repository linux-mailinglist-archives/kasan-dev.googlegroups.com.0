Return-Path: <kasan-dev+bncBAABBXVV7H7QKGQEZ2TQ2QI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x937.google.com (mail-ua1-x937.google.com [IPv6:2607:f8b0:4864:20::937])
	by mail.lfdr.de (Postfix) with ESMTPS id C95F72F41C0
	for <lists+kasan-dev@lfdr.de>; Wed, 13 Jan 2021 03:28:47 +0100 (CET)
Received: by mail-ua1-x937.google.com with SMTP id j22sf35487uak.6
        for <lists+kasan-dev@lfdr.de>; Tue, 12 Jan 2021 18:28:47 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610504926; cv=pass;
        d=google.com; s=arc-20160816;
        b=T4YDEymOrpuM4YS/7a8mHiAnLEtBy0XyRYEAAcwyld+y68YlX99/8bubW9xCU8NXpO
         3BDQeqYL/f/KnahMFBUFz4NXw1BYhoUjxLDWP3ujPZwMB7Tf86ieAKm4KUwIKqvs7PGe
         A70CoHLI8nMge/4Yf+Ej5cQLcdqcgxp2Ldypdam3ZSBqA5WBCWYfpa1ao51cZGjW4BgH
         rL3e4yqbXTFa/6AVO0HIpD2or7viP8stKjB25KulVBbrVkOfgOZ965LkTueza2JUpQc4
         KcWPiFtqXjZe8Nwdfp76PcOVkcyCEeWt/U9u/cIk/ZLLIi/E908EyIZu23dZxAVn950M
         j1Hw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=wrRtVDJ3N8StrcjpKMaqB+QXSin7079kfF/Ri110vDk=;
        b=iZifqbLZOkvvIETqnlyXFmabcKtuXjdNEEql9W3skQ6m1wadM0BQG5JNtZDGM+yq8d
         TB9khAU9ZyuyIl6GFulNRa2XeXU3OQvkabBSNtuo8/d5bS2LL4BP6J13a/jwDyMdA1Uu
         jlYf9rk3I24JN/dnXiaSW9jLN0EbLUnj77Z9lqe/UTnKIErVGkDSTIgTrHovsVYuUl6W
         bkvznKiJprDrPjCCLuDuZZvKdjsFAEln76GRyOzllMM4XSD6ylH12KYtSAbsYS98O+L+
         LJBiqiv1Jb4NQi13MC8zLy3zmIZ93otmhsv5CaN3LushIJID/RjGj+eSQ33RPK/G2Iw6
         S91g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of nylon7@andestech.com designates 60.248.187.195 as permitted sender) smtp.mailfrom=nylon7@andestech.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=wrRtVDJ3N8StrcjpKMaqB+QXSin7079kfF/Ri110vDk=;
        b=WKyaEHjosn82K3JNn1VnWblJFig5KHWFOLivshwqAT2uptN7+509ZL+ylCoJ8cbKlJ
         BJzQGLDVlc0p9w20w0sJCP+gH7smbyW0C96GSkmqU10aD4yWm8DbTLmics7QsuXWpIYC
         BNrx1EdNkFC8BVikkGDOxrhUdVtb++18HSNDZKYWxh6f02CeAM4yrF1Uq2tfklnqHVyj
         z7yyKVR5VXqrIR2gI1t1MfLgAVApHAicGtd7KajeEsl8oHphFneoT/GtKixZM3KjwPdD
         JOTmkeIFT4JScwU4AfoDDnP4zFDdJ3baOfKXjToIkP7WC6O6VUlwN8XQMJXdiD/t6sVy
         eeAw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=wrRtVDJ3N8StrcjpKMaqB+QXSin7079kfF/Ri110vDk=;
        b=XZvbYjz0Kkc/ma6bZqiiwMvk5KLrnNKqJbXFOmDjZ+EsQ9nmECb4n0/j6OH1R+77WD
         MbDq9c/JxS9WlfuTyLCjVPminzA4y73m2ixzcU/TO3HCinf6/F/SqnTmfOkNPS0uPUY6
         2BF67hDVIEnEyppknvKsEMLyeZ6ElmBrshguT98hu0bAePX2NVzYKFOBDhplIAMWwBM/
         IwH7ub9u1UhGfB2d9CsQ7Lwag2bqhP1pAlFxwUne+RMjxstf1TrG5wvnKyJNhy3O9RII
         Hn/4Ocev/NkqhGS5FaQb5KQTOiyqXiku4Uoyjw2uauypwK6IpH/a1AL5j/ZIqQZy1AEz
         m7LA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533V9AX6x3U0AgnhJM/uicWWskblKnGCwuAGT9tjmBOjTt68cOij
	aQR6AJmNZ6GaQGHr7JI7tzY=
X-Google-Smtp-Source: ABdhPJzVFqY02GLm0sn6lYdzVPy1xQVq/vqVq/FOc77jOQUs4QiLPv157wWsxoVfaYhiQ+grXF9YDA==
X-Received: by 2002:a1f:3fc9:: with SMTP id m192mr2213526vka.17.1610504926661;
        Tue, 12 Jan 2021 18:28:46 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ab0:e4:: with SMTP id 91ls36246uaj.3.gmail; Tue, 12 Jan 2021
 18:28:46 -0800 (PST)
X-Received: by 2002:a9f:2626:: with SMTP id 35mr68303uag.80.1610504926020;
        Tue, 12 Jan 2021 18:28:46 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610504926; cv=none;
        d=google.com; s=arc-20160816;
        b=ECMGgp3+9rKZK1SFkrLFJp6/vcH8cVe1cMCuZXA42BEWKeXkpXi2RYL5UGHbwvpYnL
         Cv3C2/HORTtiJob/BF2VBwz6GDwJMsERmq6RW1b6HGB3z9bBvxEWKk2PSqiBWHFHByYQ
         IL01CWaCRKirR5RVYLFliVca9i+T5X69YKzIHkZw/lL5dNnj/u8NCPBlKx7fslSK+r8d
         QqZqDy4/iadk0zHr/UMV9doO8raVv2hE9FNPUjYRar2MixqPR2QvGde8rhy/WMxscqKQ
         rffnbC7Y7KsZeEtjsr1e1xrnTM/Qnvymqp9VPqkHzXEXvFGB80KFA1GpGeUyTtU8KGMa
         0nFw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:subject:cc:to:from;
        bh=4g8bpWRFFbze0eKjyeoZv0D3z0R2ISPPfm/xh72URvs=;
        b=cKAqsOKbNOnfuOiDGDiaRwci1hKP6ZHTtX1WLEzibZMpgoMcJ7BEirGQKKgI6W8EzS
         1oLe1j01xufOnQhc/C5pUJTuGWyD8PoUTBPecH6oIyoLU6qcv7wdlIk8ZGAP8C6RoLMH
         nqs7OfNTSaOcUkgDD1Wx6ypCBf+kK5vppWY+tJoShhqdNulakBGOIHlTwlxUOAQdAsj/
         NgSpn3yftORD7QhU3WhpmrPtLE5spYd3RUgEvLaG2BGlevIsFP59EzXdNZ9kYf4E+gps
         GYY4LkVOucKL8CUKcUmEc+sMfSYKH+qQlAYcctDC3jTad3mU5TR5pg9eZrutJOgrmYD+
         dHpw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of nylon7@andestech.com designates 60.248.187.195 as permitted sender) smtp.mailfrom=nylon7@andestech.com
Received: from ATCSQR.andestech.com (exmail.andestech.com. [60.248.187.195])
        by gmr-mx.google.com with ESMTPS id e11si24533vkp.4.2021.01.12.18.28.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 12 Jan 2021 18:28:45 -0800 (PST)
Received-SPF: pass (google.com: domain of nylon7@andestech.com designates 60.248.187.195 as permitted sender) client-ip=60.248.187.195;
Received: from mail.andestech.com (atcpcs16.andestech.com [10.0.1.222])
	by ATCSQR.andestech.com with ESMTP id 10D2Pffl039664;
	Wed, 13 Jan 2021 10:25:41 +0800 (GMT-8)
	(envelope-from nylon7@andestech.com)
Received: from atcfdc88.andestech.com (10.0.15.120) by ATCPCS16.andestech.com
 (10.0.1.222) with Microsoft SMTP Server id 14.3.487.0; Wed, 13 Jan 2021
 10:28:24 +0800
From: Nylon Chen <nylon7@andestech.com>
To: <linux-riscv@lists.infradead.org>, <linux-kernel@vger.kernel.org>
CC: <kasan-dev@googlegroups.com>, <aou@eecs.berkeley.edu>,
        <palmer@dabbelt.com>, <paul.walmsley@sifive.com>, <dvyukov@google.com>,
        <glider@google.com>, <aryabinin@virtuozzo.com>,
        <alankao@andestech.com>, <nickhu@andestech.com>,
        <nylon7@andestech.com>, <nylon7717@gmail.com>
Subject: [PATCH 0/1] kasan: support backing vmalloc space for riscv
Date: Wed, 13 Jan 2021 10:28:21 +0800
Message-ID: <20210113022822.9230-1-nylon7@andestech.com>
X-Mailer: git-send-email 2.17.1
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Originating-IP: [10.0.15.120]
X-DNSRBL: 
X-MAIL: ATCSQR.andestech.com 10D2Pffl039664
X-Original-Sender: nylon7@andestech.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of nylon7@andestech.com designates 60.248.187.195 as
 permitted sender) smtp.mailfrom=nylon7@andestech.com
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

This patchset is support KASAN_VMALLOC in riscv.

We reference x86/s390 mailing list discussion for our implement.
https://lwn.net/Articles/797950/

It's also pass `vmalloc-out-of-bounds` of test_kasan.ko

log:
[  235.834318]     # Subtest: kasan
[  235.835190]     1..37
[  235.845238]
==================================================================
[  235.847818] BUG: KASAN: slab-out-of-bounds in
kmalloc_oob_right+0xe2/0x192 [test_kasan]
[  235.850688] Write of size 1 at addr ffffffe0075d5a7b by task
kunit_try_catch/125
[  235.852630]
[  235.853212] CPU: 0 PID: 125 Comm: kunit_try_catch Tainted: G    B
5.11.0-rc3-13940-gb0bb4cd86282-dirty #1
...
[  241.835850]
==================================================================
[1154/67143]
[  241.840884]     ok 36 - kmalloc_double_kzfree
[  241.852642]
==================================================================
[  241.857261] BUG: KASAN: vmalloc-out-of-bounds in
vmalloc_oob+0xcc/0x17c [test_kasan]
[  241.861327] Read of size 1 at addr ffffffd00407ec1c by task
kunit_try_catch/161
[  241.864525]
[  241.865200] CPU: 0 PID: 161 Comm: kunit_try_catch Tainted: G    B
5.11.0-rc3-13940-gb0bb4cd86282-dirty #1
[  241.869887] Call Trace:
[  241.870972] [<ffffffe0000052d2>] walk_stackframe+0x0/0x128
[  241.873353] [<ffffffe000abcff0>] show_stack+0x32/0x3e
[  241.875457] [<ffffffe000ac0d46>] dump_stack+0x84/0xa0
[  241.877806] [<ffffffe000188926>]
print_address_description.constprop.0+0x88/0x362
[  241.881150] [<ffffffe000188e4a>] kasan_report+0x176/0x194
[  241.883604] [<ffffffe000189390>] __asan_load1+0x42/0x4a
[  241.885897] [<ffffffdf81f9f2f4>] vmalloc_oob+0xcc/0x17c [test_kasan]
[  241.889458] [<ffffffdf81f91e8e>] kunit_try_run_case+0x80/0x11a
[kunit]
[  241.892665] [<ffffffdf81f92e16>]
kunit_generic_run_threadfn_adapter+0x2c/0x4e [kunit]
[  241.896568] [<ffffffe000034ac4>] kthread+0x206/0x222
[  241.899219] [<ffffffe00000361a>] ret_from_exception+0x0/0xc
[  241.901700]
[  241.902497]
[  241.903257] Memory state around the buggy address:
[  241.905430]  ffffffd00407eb00: 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00
[  241.908661]  ffffffd00407eb80: 00 00 00 00 00 00 00 f8 f8 f8 f8 f8 f8
f8 f8 f8
[  241.911841] >ffffffd00407ec00: f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8
f8 f8 f8
[  241.915037]                             ^
[  241.916053]  ffffffd00407ec80: f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8
f8 f8 f8
[  241.919272]  ffffffd00407ed00: f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8
f8 f8 f8
[  241.922417]
==================================================================
[  242.073698]     ok 37 - vmalloc_oob


Nylon Chen (1):
  riscv/kasan: add KASAN_VMALLOC support

 arch/riscv/Kconfig         |  1 +
 arch/riscv/mm/kasan_init.c | 66 +++++++++++++++++++++++++++++++++++++-
 2 files changed, 66 insertions(+), 1 deletion(-)

-- 
2.17.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210113022822.9230-1-nylon7%40andestech.com.
