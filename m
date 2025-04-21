Return-Path: <kasan-dev+bncBCO7L6ME2ELBBH5QTDAAMGQEFQHJTNI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33c.google.com (mail-wm1-x33c.google.com [IPv6:2a00:1450:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id C34B9A94F20
	for <lists+kasan-dev@lfdr.de>; Mon, 21 Apr 2025 12:04:34 +0200 (CEST)
Received: by mail-wm1-x33c.google.com with SMTP id 5b1f17b1804b1-44059976a1fsf14318845e9.1
        for <lists+kasan-dev@lfdr.de>; Mon, 21 Apr 2025 03:04:34 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1745229857; cv=pass;
        d=google.com; s=arc-20240605;
        b=PBGRfeQcdcWyy3m860IWAzL+lFN/bAqYATJFa0E/7f/SHOSpUn7gJnWGOME77jmJvr
         35Ktb3YqR+5qll8HFxIAaiV11rLIxABbfzWydwHLqaZ65QBHJ5FwA5AY5F9t0Hv0zedb
         gG7260wSeVEow0LJ8cGmAlZOKk45wQO29trff1b/qWZ7We/bsZPE8IZcP5kLKbg7wNyk
         tSPYOa9Zvho5C9cyNP10OblGRrXf1wGhz2dbQsHPOcsq35JISXYEN03KM68zg4GKZDd2
         DJHhbF028NAvbuOZx8Mrg5rzlkPoFnhrO6VqfDa32nSQgD6sCAm6YudagDS4yZvGBYUT
         AznQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:subject:cc:to:from:date:dkim-signature;
        bh=uiZp0DyA8rtMq5g+GauCqyBAxDyMDUKxbFs0cSga81o=;
        fh=lx3C3CttiRnTzWw53D4PkCjSVLN+ifoOFV1JX4FLabU=;
        b=Q3UTYceJMUGCeTev8ckqQ9gataLz33OlUn03MCcUnmqYgssP1Y+03+XVuJD+vL7RyZ
         Qi8PlyfIXMS6vYj755JLGhEvaA/IHnlaqhYbSxRXLsaq8bZZGctXxOxjtnixZZqk0jxx
         qspyBrqXALL2gmFHbJl0awBTZVPWsOgMlefg+JnqZmx4fuoyFGEo3O9Gsde/Fe1rN6WZ
         PUZb+3CGxVmaQ+xC1SdB5Qn5v/B/KKNmOvnRtFWgS+J1LbY/p8CQYdFDBtNsfihCV3Ax
         xUBdKqKnC7ABGKZr70PPj+wdfCL6LPC9oa4YPT0s65tL+hT6sp9wjO41BruY+H38+tSp
         hZTw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mailbox.org header.s=mail20150812 header.b=kccPDBOQ;
       spf=pass (google.com: domain of erhard_f@mailbox.org designates 2001:67c:2050:0:465::101 as permitted sender) smtp.mailfrom=erhard_f@mailbox.org;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=mailbox.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1745229857; x=1745834657; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:subject:cc:to:from:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=uiZp0DyA8rtMq5g+GauCqyBAxDyMDUKxbFs0cSga81o=;
        b=Alibg41ReouIujVjMzBs7UX6BroJ08pF2b2BwwLvnRzWuyFJWa09iRfyJKfmYXfKe1
         04yJf0SIJxNOkl0s5D5U6gB+H5p1/yIora6aEwo2+t/1xEiF9VMmQCa/9T2Aqbt59n9w
         rIZbv2L7/4LEnQ9PRcxoZxPlJaeCtD1Q7K48Gf7We7IWLimxoJXyX6XZcw+3T6qz9f3T
         kPyZowFoLwk7861NuXvUndz7SJHfCXwymwMYPR24sPPDXbMx5LsmBcosGWovKWTyHjLg
         DDTvcIJpEfuTjZUG2juRS/NiSRWG+3IpcLs1Xu/CF7p/zVUnm6HW5X/wdRaXA5urgCtq
         3XRQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1745229857; x=1745834657;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:subject:cc:to:from:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=uiZp0DyA8rtMq5g+GauCqyBAxDyMDUKxbFs0cSga81o=;
        b=wvmpkaPYd3HpX87JdUAgMuYXgj0bvVxsOSdTGf7TeZCO2XICR47SX4P0+98s1iGxqc
         45XU/STTKLwFPcNMBrmvwMWQPaYiC3A4+TylMj1SgGZgywSm66IYcbwcUkO5rd/lWaBz
         QECgPrWf/ZuZvpHWpUpFIq/1nn/PooMicaiC4ugLPeX0y9f/wVhegM/y1cqnzLB2uRxn
         Zbu5U/vGacHREj4Ijm/8LKnrn6lya697cS755DxkuEAbG76k6mwT9dnTkHBFpRM2Ydzv
         psK+ZbRrpKSsSwescS3/NPy1buWpcEU9slxa3NJzQRpIHHDrEXrK//40GdHQ5vcOXVxn
         AeUw==
X-Forwarded-Encrypted: i=2; AJvYcCXzkS45RpmY9qnKzZFQFtcOlUr23cjCUhwi1otZH/3vaJc2EIlp2xzb3Cs2OnfGmg7s2LkuzQ==@lfdr.de
X-Gm-Message-State: AOJu0YzJ/Yc2dOrN+PxnKSxYyZ7ZyoQK3V2IZAYQBXKjIy1nGP207gf8
	iwn47LqNiixsQYTTA6JYYu0m+b/elrS4FhZOWhAmMzkrYGwOJaEb
X-Google-Smtp-Source: AGHT+IGlhl2hkU5uqPEQwfGz3gek8nkIRwBGEXDdPZOBev0q2JAXLwAk2HLKLm4HsdIfvip6H2ra8A==
X-Received: by 2002:a05:600c:1e18:b0:43b:cb12:ba6d with SMTP id 5b1f17b1804b1-4406ab7ab1emr108339795e9.3.1745229856377;
        Mon, 21 Apr 2025 03:04:16 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARLLPALCgSIAK4xJzWXmN6BYOqoGm7knCQW5G4Kyyvy41+VRjg==
Received: by 2002:a05:600c:6550:b0:43d:40b0:33 with SMTP id
 5b1f17b1804b1-4406227b2cbls12402975e9.0.-pod-prod-01-eu; Mon, 21 Apr 2025
 03:04:14 -0700 (PDT)
X-Received: by 2002:a05:6000:420a:b0:39f:e50:af8 with SMTP id ffacd0b85a97d-39f0e500b83mr582920f8f.18.1745229853672;
        Mon, 21 Apr 2025 03:04:13 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1745229853; cv=none;
        d=google.com; s=arc-20240605;
        b=BKtaiNdaR58GVNYvAPlvLqlqOI/fFde7Z1WS8IcsESzfEgbtDsPyGG2NF2AeM/VucX
         ono1xMdxUHeHC2PwNLCUGNEj/EJxaJEq1oMq1rhWxIz+1k93sMWi8sWW5CJ+G7CIy8ud
         nws258M778K/uLXa3TEr4D+mNUiJ53urj9EsS4c5EKmvsuUvLqspX9yK2NufRG8R3GJI
         +3G4ajcQfu914phzH2VnHKGggMQgFhRD6WB5ZUgHGC3dJ8juL+4SCSEh9yPd+K4vezy3
         qmsBWvm6FxX2tI/YbcJ6ghhPStqpOLunogEMY99AVyl79eEa7HfKT7Z5CZD3W5l32zdY
         T4XQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=XfvxI0+i7Z1YuQZARp14sno/p3pBL2EyWOlCeZKZQL4=;
        fh=orNCne014tYc2nfIT6bvkMC36UfUk3P2HxOTOSn9Es4=;
        b=Ad5SYCYgXwJkBLcPc3+lkCzkfwgBwdXWEKyy2FTZ9oCJCG3kv/8P+GjLEECMIHvL45
         xY6DuLqNDjHYqa0bEHAVKbaZm/QCXF1PPrPW6cEXcb1wluzCb6CdHp4LqxmpktEaC3s+
         Xcwe86SBvY4xL6Vc5jWAOGrRSHPQQHuweXeW6zZ0+xjUFf8ykZbxEDgWw9vkNigZ6en/
         l4VVppQVeH3CKZCsrE8AdSt7pu4Cmax9j/s+gEUJ3aaDOccrApktZFoy9kC2dUhAQo/C
         +gzJaMu/tZRfBt7iMOrEk+R+VUxPtGYCVSwXjxfFtGbJTMvIaRGdngVb6TLXxIm4wvD6
         jspQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mailbox.org header.s=mail20150812 header.b=kccPDBOQ;
       spf=pass (google.com: domain of erhard_f@mailbox.org designates 2001:67c:2050:0:465::101 as permitted sender) smtp.mailfrom=erhard_f@mailbox.org;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=mailbox.org
Received: from mout-p-101.mailbox.org (mout-p-101.mailbox.org. [2001:67c:2050:0:465::101])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-4404352aa2csi7021025e9.1.2025.04.21.03.04.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 21 Apr 2025 03:04:13 -0700 (PDT)
Received-SPF: pass (google.com: domain of erhard_f@mailbox.org designates 2001:67c:2050:0:465::101 as permitted sender) client-ip=2001:67c:2050:0:465::101;
Received: from smtp2.mailbox.org (smtp2.mailbox.org [IPv6:2001:67c:2050:b231:465::2])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by mout-p-101.mailbox.org (Postfix) with ESMTPS id 4Zh1DV52H2z9sFn;
	Mon, 21 Apr 2025 12:04:10 +0200 (CEST)
Date: Mon, 21 Apr 2025 12:04:08 +0200
From: "'Erhard Furtner' via kasan-dev" <kasan-dev@googlegroups.com>
To: linux-mm@kvack.org
Cc: kasan-dev@googlegroups.com, kees@kernel.org
Subject: Re: BUG: KASAN: vmalloc-out-of-bounds in
 vrealloc_noprof+0x195/0x220 at running fortify_kunit (v6.15-rc1, x86_64)
Message-ID: <20250421120408.04d7abdf@outsider.home>
In-Reply-To: <20250408192503.6149a816@outsider.home>
References: <20250408192503.6149a816@outsider.home>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-MBO-RS-META: zxwokzf37mfzxf5g5g1rwfuugfp7cjje
X-MBO-RS-ID: fc43cb995263aa00757
X-Original-Sender: erhard_f@mailbox.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mailbox.org header.s=mail20150812 header.b=kccPDBOQ;       spf=pass
 (google.com: domain of erhard_f@mailbox.org designates 2001:67c:2050:0:465::101
 as permitted sender) smtp.mailfrom=erhard_f@mailbox.org;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=mailbox.org
X-Original-From: Erhard Furtner <erhard_f@mailbox.org>
Reply-To: Erhard Furtner <erhard_f@mailbox.org>
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

Greetings!

fortify_test_alloc_size_kvmalloc_const test failure still in v6.15-rc3, also with a 'GCC14 -O2'-built kernel:

==================================================================
BUG: KASAN: vmalloc-out-of-bounds in vrealloc_noprof+0x2a2/0x370
Read of size 6291456 at addr ffffc9000e200000 by task kunit_try_catch/4317

CPU: 21 UID: 0 PID: 4317 Comm: kunit_try_catch Tainted: G                 N  6.15.0-rc3-Zen3 #11 PREEMPT 
Tainted: [N]=TEST
Hardware name: To Be Filled By O.E.M. B550M Pro4/B550M Pro4, BIOS L3.46 08/20/2024
Call Trace:
 <TASK>
 dump_stack_lvl+0x4a/0x70
 print_report+0x132/0x4e0
 ? __rwlock_init+0x120/0x120
 ? vrealloc_noprof+0x2a2/0x370
 kasan_report+0xd9/0x110
 ? vrealloc_noprof+0x2a2/0x370
 ? fortify_test_alloc_size_kvmalloc_const+0x4892/0xa3d0 [fortify_kunit]
 kasan_check_range+0x113/0x210
 __asan_memcpy+0x1f/0x70
 vrealloc_noprof+0x2a2/0x370
 ? srso_alias_return_thunk+0x5/0xfbef5
 fortify_test_alloc_size_kvmalloc_const+0x4892/0xa3d0 [fortify_kunit]
 ? fortify_test_alloc_size_vmalloc_const+0x2a30/0x2a30 [fortify_kunit]
 ? srso_alias_return_thunk+0x5/0xfbef5
 ? srso_alias_return_thunk+0x5/0xfbef5
 ? ktime_get_ts64+0x7a/0x220
 ? fortify_test_init+0x2be/0x460 [fortify_kunit]
 kunit_try_run_case+0x199/0x2b0 [kunit]
 ? kunit_try_run_case_cleanup+0xe0/0xe0 [kunit]
 ? srso_alias_return_thunk+0x5/0xfbef5
 ? do_raw_spin_unlock+0x4f/0x220
 ? kunit_try_run_case_cleanup+0xe0/0xe0 [kunit]
 ? kunit_mem_assert_format+0x460/0x460 [kunit]
 kunit_generic_run_threadfn_adapter+0x7b/0xe0 [kunit]
 kthread+0x349/0x6c0
 ? kthread_is_per_cpu+0xd0/0xd0
 ? kthread_is_per_cpu+0xd0/0xd0
 ? kthread_is_per_cpu+0xd0/0xd0
 ret_from_fork+0x2b/0x70
 ? kthread_is_per_cpu+0xd0/0xd0
 ret_from_fork_asm+0x11/0x20
 </TASK>

The buggy address belongs to the virtual mapping at
 [ffffc9000e200000, ffffc9000e801000) created by:
 fortify_test_alloc_size_kvmalloc_const+0x4788/0xa3d0 [fortify_kunit]

The buggy address belongs to the physical page:
page: refcount:1 mapcount:0 mapping:0000000000000000 index:0x7fab41f0a pfn:0x128000
flags: 0x4000000000000000(zone=1)
raw: 4000000000000000 0000000000000000 dead000000000122 0000000000000000
raw: 00000007fab41f0a 0000000000000000 00000001ffffffff 0000000000000000
page dumped because: kasan: bad access detected

Memory state around the buggy address:
 ffffc9000e600f00: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
 ffffc9000e600f80: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
>ffffc9000e601000: f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8
                   ^
 ffffc9000e601080: f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8
 ffffc9000e601100: f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8
==================================================================
Disabling lock debugging due to kernel taint
    not ok 7 fortify_test_alloc_size_kvmalloc_const
[...]

Regards,
Erhard


On Tue, 8 Apr 2025 19:25:03 +0200
Erhard Furtner <erhard_f@mailbox.org> wrote:

> Greetings!
> 
> I gave v6.15-rc1 a test ride on my Ryzen 5950 system with some debugging options turned on, getting a KASAN vmalloc-out-of-bounds hit at running fortify_kunit test:
> 
> [...]
> TAP version 1
> 1..1
>     KTAP version 1
>     # Subtest: fortify
>     # module: fortify_kunit
>     1..26
>     ok 1 fortify_test_known_sizes
>     ok 2 fortify_test_control_flow_split
>     ok 3 fortify_test_alloc_size_kmalloc_const
>     ok 4 fortify_test_alloc_size_kmalloc_dynamic
>     ok 5 fortify_test_alloc_size_vmalloc_const
>     ok 6 fortify_test_alloc_size_vmalloc_dynamic
> ==================================================================
> BUG: KASAN: vmalloc-out-of-bounds in vrealloc_noprof+0x195/0x220
> Read of size 6291456 at addr ffffc90015c00000 by task kunit_try_catch/4334
> 
> CPU: 15 UID: 0 PID: 4334 Comm: kunit_try_catch Tainted: G                 N  6.15.0-rc1-Zen3 #6 PREEMPT 
> Tainted: [N]=TEST
> Hardware name: To Be Filled By O.E.M. B550M Pro4/B550M Pro4, BIOS L3.46 08/20/2024
> Call Trace:
>  <TASK>
>  dump_stack_lvl+0x2a/0x90
>  print_report+0x17a/0x520
>  ? srso_alias_return_thunk+0x5/0xfbef5
>  ? vrealloc_noprof+0x195/0x220
>  kasan_report+0xb9/0x100
>  ? vrealloc_noprof+0x195/0x220
>  kasan_check_range+0x184/0x190
>  ? vrealloc_noprof+0x195/0x220
>  __asan_memcpy+0x25/0x70
>  vrealloc_noprof+0x195/0x220
>  ? fortify_test_alloc_size_kvmalloc_const+0x2eae/0x7170 [fortify_kunit]
>  fortify_test_alloc_size_kvmalloc_const+0x2eae/0x7170 [fortify_kunit]
>  kunit_try_run_case+0x119/0x340 [kunit]
>  ? kunit_cleanup+0x120/0x120 [kunit]
>  kunit_generic_run_threadfn_adapter+0x73/0x100 [kunit]
>  kthread+0x46a/0x570
>  ? kunit_try_catch_run+0x620/0x620 [kunit]
>  ? kthread_blkcg+0xb0/0xb0
>  ret_from_fork+0x3c/0x70
>  ? kthread_blkcg+0xb0/0xb0
>  ret_from_fork_asm+0x11/0x20
>  </TASK>
> 
> The buggy address belongs to the virtual mapping at
>  [ffffc90015c00000, ffffc90016201000) created by:
>  fortify_test_alloc_size_kvmalloc_const+0x2dfb/0x7170 [fortify_kunit]
> 
> The buggy address belongs to the physical page:
> page: refcount:1 mapcount:0 mapping:0000000000000000 index:0x7f281927d pfn:0x128600
> flags: 0x4000000000000000(zone=1)
> raw: 4000000000000000 0000000000000000 dead000000000122 0000000000000000
> raw: 00000007f281927d 0000000000000000 00000001ffffffff 0000000000000000
> page dumped because: kasan: bad access detected
> 
> Memory state around the buggy address:
>  ffffc90016000f00: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
>  ffffc90016000f80: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
> >ffffc90016001000: f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8  
>                    ^
>  ffffc90016001080: f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8
>  ffffc90016001100: f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8
> ==================================================================
> Disabling lock debugging due to kernel taint
>     not ok 7 fortify_test_alloc_size_kvmalloc_const
>     ok 8 fortify_test_alloc_size_kvmalloc_dynamic
>     ok 9 fortify_test_alloc_size_devm_kmalloc_const
>     ok 10 fortify_test_alloc_size_devm_kmalloc_dynamic
>     ok 11 fortify_test_realloc_size
>     ok 12 fortify_test_strlen
>     ok 13 fortify_test_strnlen
>     ok 14 fortify_test_strcpy
>     ok 15 fortify_test_strncpy
>     ok 16 fortify_test_strscpy
>     ok 17 fortify_test_strcat
>     ok 18 fortify_test_strncat
>     ok 19 fortify_test_strlcat
>     ok 20 fortify_test_memcpy
>     ok 21 fortify_test_memmove
>     ok 22 fortify_test_memscan
>     ok 23 fortify_test_memchr
>     ok 24 fortify_test_memchr_inv
>     ok 25 fortify_test_memcmp
>     ok 26 fortify_test_kmemdup
> # fortify: pass:25 fail:1 skip:0 total:26
> # Totals: pass:25 fail:1 skip:0 total:26
> not ok 1 fortify
> 
> 
> Kernel .config attached.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250421120408.04d7abdf%40outsider.home.
