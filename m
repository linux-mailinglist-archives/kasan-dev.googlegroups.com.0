Return-Path: <kasan-dev+bncBDQ27FVWWUFRB7EUQTXQKGQEE6T7BQY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63d.google.com (mail-pl1-x63d.google.com [IPv6:2607:f8b0:4864:20::63d])
	by mail.lfdr.de (Postfix) with ESMTPS id C864210D57C
	for <lists+kasan-dev@lfdr.de>; Fri, 29 Nov 2019 13:09:33 +0100 (CET)
Received: by mail-pl1-x63d.google.com with SMTP id t17sf5588088ply.5
        for <lists+kasan-dev@lfdr.de>; Fri, 29 Nov 2019 04:09:33 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1575029372; cv=pass;
        d=google.com; s=arc-20160816;
        b=XPg+U41iC9w8UWpdILYTpz0z76tIhfBSemYd0yfgO/t7LtS4nf5qOl2mhABBCVT+9k
         ZYAv6ednD3ZevaANKLOTXPr34u/JtP2dcYyuJnZipRu3cRQ7cx85iBfSGV1NPsMfPpGe
         OD7w2Oq7Kp6o+XzK5710L2V5D3Sgl+bLuGEKYV/z5Yuq1rkORGA8FiNgcrqBH6SWiyNR
         w8RotcmK7EDvaa3DcOT1LWM1pe4DRPb2B8tLJxcEjaxhXduasCZ2ChKinXeSOYBba4Yn
         4VZX3yZu1Jo087rmmWCBsynCz8NWrn+28Z8Ovq51WA0XGW+34m8B2B1ac6O8XOCpw8h5
         HLGw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :references:in-reply-to:subject:cc:to:from:sender:dkim-signature;
        bh=M8AO+4ogHYMSuVt5be/unFwIgn8B8CE9QBZJPu7BChY=;
        b=YZgY5uuNBQHP0k5e7nowUPmK0ujxGnbDE3Unlv+dACiJbKryPthooqlPe+wV5wGgTp
         2Vs4iqTRuqtFro/3XF9qwv1uIroCOsznLYxCesZ4Uee9dYCyYldFSdv8D3x/HmruACOI
         vhJ6aUtnKJ7PfZGDvgyYQWsFsaT8fHuBKVnpMmXNIxaSvRy6qCQiBCPbdrpMtzqKwYF0
         19AClF1+vBNBezFO6dxSYMtZ5NVsPg3k2xu28LQyHoMShxKl0d66KlPtqOJzrxeAsOm7
         YuMLkH0UoSwwKiVVzEO0G7m/qK/3SjymsQiFj7VhmnDiq9WLGF4sHKhXYC+HFlIuIXDO
         fqnA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=RmK+wv0p;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::442 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:in-reply-to:references:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=M8AO+4ogHYMSuVt5be/unFwIgn8B8CE9QBZJPu7BChY=;
        b=WdQA5Hn2JxjcF20yrvz0dh5UE7+n9865wV0vpY7iOthCLY6uhBWIr+km9AZYm6GrZ8
         DsdU9cJCKzd3C1OZDcX3tMjFelrqCfQVFXyzuCGn3Ajw6r8x37gnV8sLle7PLCtATrAd
         2mtndYhiyaaOa1AXWpoQAbTj+95FbkClO3GD7/de3sZT61FrH5RAFzedOD1frry8viY3
         ZtR0gFNxnJVePBWPRG04cZQIgYREYI3Y7E+fPAdaBKjm+pRmeAewubitlxBZoGVYQF16
         v4Kh0rtSUidBaO/B1T5mjecdVzU7ZGhc2/M924/JGcgOSohJiz2/3TpsafEJbwCBItxs
         seNQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:in-reply-to:references
         :date:message-id:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=M8AO+4ogHYMSuVt5be/unFwIgn8B8CE9QBZJPu7BChY=;
        b=fixhuVFmX0oRz0b/BQGzuvJ7CQuogwRrfXKbI9xMGCVqfLoE3nRrKhJZoeNZkN23ok
         H3GXBz7NiBZNJkwJAa73W6Ki+N/rDjos0BCjalTo1mGmbz3h97nXmYyvQSRZhR8mlah0
         x996183FI0QmH5wg/WdV6n0mQ+3suhoKyim/ehBB01Q4FfrYlDQF3Ai9CfL6QIwl+PtI
         0q7qNliPYdZQPqmB8OCr7qHpkN26SDUNJuufRWmnDcqjiXe0lyuAJJmBPkY/m8Q2HvZY
         oQR76zGep2Ailh9oIgojhoIL5JSNIsQ52LPh2Vj8UIX8wCp4O5Z+rNXi4ysO7/lIQUdL
         1Q9g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVeFjc9aMrN+cm27EiN8kZvTENHN+nhDpYOOaPJ3LvvRguXCTlS
	1gouF7Et/qEzmbL+au8OLKk=
X-Google-Smtp-Source: APXvYqzA+HF33RGDjyX3669y4Np/gdcXsdNraS4MZf4CMniJCpnyzVnes366mT6/vQinwiz7sQ3sMQ==
X-Received: by 2002:a63:e80d:: with SMTP id s13mr16702717pgh.134.1575029372205;
        Fri, 29 Nov 2019 04:09:32 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:f314:: with SMTP id ca20ls99016pjb.3.gmail; Fri, 29
 Nov 2019 04:09:31 -0800 (PST)
X-Received: by 2002:a17:902:bf06:: with SMTP id bi6mr14475901plb.168.1575029371695;
        Fri, 29 Nov 2019 04:09:31 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1575029371; cv=none;
        d=google.com; s=arc-20160816;
        b=yTkq74TAH5ZIyLH9HYmW90KQ22rGpzNvGa9HIGtR+pemXHFDNVAWrkNQWSG4n7ZDzi
         GlayN5Hks2Wo+Dwd/Fk6qmeJ/+4WV6N75jppOWBLxDpiX/5Vg1C7v2Zuh2J/Yhw9VWuo
         951DNn7/PpFzXQjPUDtjsy67X15Z5L1W7iFySEsfbxob1vaGVpcxbGakRJgh21WzIs1D
         UHzCD8/lr1VJvJjXr/U5dR0Z07hb5gvHqA/dyqCUvAnO3hCjVqkt2s/xrldwrfunboZ5
         vLoZVulxlcrqVPTZIBJgMntcQc95fMySn3lHpk0wM2JeyJqHwfHD1qxSbkykedx5LjWt
         grzw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:references:in-reply-to:subject:cc:to
         :from:dkim-signature;
        bh=Qm6oKiM2ABO+RifKesimvx+ONcOc9pjFmAlUk+XGKuc=;
        b=ohiPCr0zDAtOzL8YDkutbJmkugrxyBdiS34SIkTLs+/BSNENpW9MSuzIYg0O5PfvD+
         0rbJKcoPfpK+kwHc8AEfndE9OdCPCBLMuFNlsdtur7538UhvHdmDx5so3OuxA9lddLdM
         Ee9szKSjLToBOWaehtBvlSMa5Fhf5IQ5+LJRtZ/HoaC5SY4CgOmL2Li+LiBil5vdpgG4
         D1GcE09FK2VTjatWcaAklw1Vh2WK4YkA6CnpK9tLlHN0o6c06JRZClS52RCS1PUBQb6G
         7oHuMXG0eDfVpSDNjMVsC6JQ8wN8TdIdOqOy1T1yxq2LQLiAKM4Zl6UzdqfBvcOxcjLV
         sD0A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=RmK+wv0p;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::442 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pf1-x442.google.com (mail-pf1-x442.google.com. [2607:f8b0:4864:20::442])
        by gmr-mx.google.com with ESMTPS id cu4si116349pjb.1.2019.11.29.04.09.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 29 Nov 2019 04:09:31 -0800 (PST)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::442 as permitted sender) client-ip=2607:f8b0:4864:20::442;
Received: by mail-pf1-x442.google.com with SMTP id b19so14582287pfd.3
        for <kasan-dev@googlegroups.com>; Fri, 29 Nov 2019 04:09:31 -0800 (PST)
X-Received: by 2002:a63:4d1f:: with SMTP id a31mr16309174pgb.360.1575029371290;
        Fri, 29 Nov 2019 04:09:31 -0800 (PST)
Received: from localhost (2001-44b8-111e-5c00-4092-39f5-bb9d-b59a.static.ipv6.internode.on.net. [2001:44b8:111e:5c00:4092:39f5:bb9d:b59a])
        by smtp.gmail.com with ESMTPSA id q9sm8641213pjb.27.2019.11.29.04.09.29
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 29 Nov 2019 04:09:30 -0800 (PST)
From: Daniel Axtens <dja@axtens.net>
To: Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>
Cc: Qian Cai <cai@lca.pw>, kasan-dev <kasan-dev@googlegroups.com>, Linux-MM <linux-mm@kvack.org>, the arch/x86 maintainers <x86@kernel.org>, Alexander Potapenko <glider@google.com>, Andy Lutomirski <luto@kernel.org>, LKML <linux-kernel@vger.kernel.org>, Mark Rutland <mark.rutland@arm.com>, Christophe Leroy <christophe.leroy@c-s.fr>, linuxppc-dev <linuxppc-dev@lists.ozlabs.org>, Vasily Gorbik <gor@linux.ibm.com>
Subject: Re: [PATCH v11 1/4] kasan: support backing vmalloc space with real shadow memory
In-Reply-To: <CACT4Y+Z+VhfVpkfg-WFq_kFMY=DE+9b_DCi-mCSPK-udaf_Arg@mail.gmail.com>
References: <20191031093909.9228-1-dja@axtens.net> <20191031093909.9228-2-dja@axtens.net> <1573835765.5937.130.camel@lca.pw> <871ru5hnfh.fsf@dja-thinkpad.axtens.net> <952ec26a-9492-6f71-bab1-c1def887e528@virtuozzo.com> <CACT4Y+ZGO8b88fUyFe-WtV3Ubr11ChLY2mqk8YKWN9o0meNtXA@mail.gmail.com> <CACT4Y+Z+VhfVpkfg-WFq_kFMY=DE+9b_DCi-mCSPK-udaf_Arg@mail.gmail.com>
Date: Fri, 29 Nov 2019 23:09:27 +1100
Message-ID: <874kymg9zc.fsf@dja-thinkpad.axtens.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=RmK+wv0p;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::442 as
 permitted sender) smtp.mailfrom=dja@axtens.net
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

Hi Dmitry,

>> I am testing this support on next-20191129 and seeing the following warnings:
>>
>> BUG: sleeping function called from invalid context at mm/page_alloc.c:4681
>> in_atomic(): 1, irqs_disabled(): 0, non_block: 0, pid: 44, name: kworker/1:1
>> 4 locks held by kworker/1:1/44:
>>  #0: ffff888067c26d28 ((wq_completion)events){+.+.}, at:
>> __write_once_size include/linux/compiler.h:247 [inline]
>>  #0: ffff888067c26d28 ((wq_completion)events){+.+.}, at:
>> arch_atomic64_set arch/x86/include/asm/atomic64_64.h:34 [inline]
>>  #0: ffff888067c26d28 ((wq_completion)events){+.+.}, at: atomic64_set
>> include/asm-generic/atomic-instrumented.h:868 [inline]
>>  #0: ffff888067c26d28 ((wq_completion)events){+.+.}, at:
>> atomic_long_set include/asm-generic/atomic-long.h:40 [inline]
>>  #0: ffff888067c26d28 ((wq_completion)events){+.+.}, at: set_work_data
>> kernel/workqueue.c:615 [inline]
>>  #0: ffff888067c26d28 ((wq_completion)events){+.+.}, at:
>> set_work_pool_and_clear_pending kernel/workqueue.c:642 [inline]
>>  #0: ffff888067c26d28 ((wq_completion)events){+.+.}, at:
>> process_one_work+0x88b/0x1750 kernel/workqueue.c:2235
>>  #1: ffffc900002afdf0 (pcpu_balance_work){+.+.}, at:
>> process_one_work+0x8c0/0x1750 kernel/workqueue.c:2239
>>  #2: ffffffff8943f080 (pcpu_alloc_mutex){+.+.}, at:
>> pcpu_balance_workfn+0xcc/0x13e0 mm/percpu.c:1845
>>  #3: ffffffff89450c78 (vmap_area_lock){+.+.}, at: spin_lock
>> include/linux/spinlock.h:338 [inline]
>>  #3: ffffffff89450c78 (vmap_area_lock){+.+.}, at:
>> pcpu_get_vm_areas+0x1449/0x3df0 mm/vmalloc.c:3431
>> Preemption disabled at:
>> [<ffffffff81a84199>] spin_lock include/linux/spinlock.h:338 [inline]
>> [<ffffffff81a84199>] pcpu_get_vm_areas+0x1449/0x3df0 mm/vmalloc.c:3431
>> CPU: 1 PID: 44 Comm: kworker/1:1 Not tainted 5.4.0-next-20191129+ #5
>> Hardware name: QEMU Standard PC (Q35 + ICH9, 2009), BIOS 1.12.0-1 04/01/2014
>> Workqueue: events pcpu_balance_workfn
>> Call Trace:
>>  __dump_stack lib/dump_stack.c:77 [inline]
>>  dump_stack+0x199/0x216 lib/dump_stack.c:118
>>  ___might_sleep.cold.97+0x1f5/0x238 kernel/sched/core.c:6800
>>  __might_sleep+0x95/0x190 kernel/sched/core.c:6753
>>  prepare_alloc_pages mm/page_alloc.c:4681 [inline]
>>  __alloc_pages_nodemask+0x3cd/0x890 mm/page_alloc.c:4730
>>  alloc_pages_current+0x10c/0x210 mm/mempolicy.c:2211
>>  alloc_pages include/linux/gfp.h:532 [inline]
>>  __get_free_pages+0xc/0x40 mm/page_alloc.c:4786
>>  kasan_populate_vmalloc_pte mm/kasan/common.c:762 [inline]
>>  kasan_populate_vmalloc_pte+0x2f/0x1b0 mm/kasan/common.c:753
>>  apply_to_pte_range mm/memory.c:2041 [inline]
>>  apply_to_pmd_range mm/memory.c:2068 [inline]
>>  apply_to_pud_range mm/memory.c:2088 [inline]
>>  apply_to_p4d_range mm/memory.c:2108 [inline]
>>  apply_to_page_range+0x5ca/0xa00 mm/memory.c:2133
>>  kasan_populate_vmalloc+0x69/0xa0 mm/kasan/common.c:791
>>  pcpu_get_vm_areas+0x1596/0x3df0 mm/vmalloc.c:3439
>>  pcpu_create_chunk+0x240/0x7f0 mm/percpu-vm.c:340
>>  pcpu_balance_workfn+0x1033/0x13e0 mm/percpu.c:1934
>>  process_one_work+0x9b5/0x1750 kernel/workqueue.c:2264
>>  worker_thread+0x8b/0xd20 kernel/workqueue.c:2410
>>  kthread+0x365/0x450 kernel/kthread.c:255
>>  ret_from_fork+0x24/0x30 arch/x86/entry/entry_64.S:352
>>
>>
>> Not sure if it's the same or not. Is it addressed by something in flight?

It looks like this one is the same.

There is a patch to fix it:
https://lore.kernel.org/linux-mm/20191120052719.7201-1-dja@axtens.net/

Andrew said he had picked it up on the 22nd:
https://marc.info/?l=linux-mm-commits&m=157438241512561&w=2
It's landed in mmots but not mmotm, so hopefully that will happen and
then it will land in -next very soon!

I will look into your other bug report shortly.

Regards,
Daniel

>>
>> My config:
>> https://gist.githubusercontent.com/dvyukov/36c7be311fdec9cd51c649f7c3cb2ddb/raw/39c6f864fdd0ffc53f0822b14c354a73c1695fa1/gistfile1.txt
>
>
> I've tried this fix for pcpu_get_vm_areas:
> https://groups.google.com/d/msg/kasan-dev/t_F2X1MWKwk/h152Z3q2AgAJ
> and it helps. But this will break syzbot on linux-next soon.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/874kymg9zc.fsf%40dja-thinkpad.axtens.net.
