Return-Path: <kasan-dev+bncBC7OBJGL2MHBBRHWRDYQKGQE2MUV5JI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103a.google.com (mail-pj1-x103a.google.com [IPv6:2607:f8b0:4864:20::103a])
	by mail.lfdr.de (Postfix) with ESMTPS id 03579141480
	for <lists+kasan-dev@lfdr.de>; Fri, 17 Jan 2020 23:55:02 +0100 (CET)
Received: by mail-pj1-x103a.google.com with SMTP id c2sf4907014pjr.9
        for <lists+kasan-dev@lfdr.de>; Fri, 17 Jan 2020 14:55:01 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1579301700; cv=pass;
        d=google.com; s=arc-20160816;
        b=TaxKc83MZ6yAXmpDO1eKtbKU4oKNkUyaHMV0HGqZfgOEQ/Y4Pl+wDASX0UgnL+AbVb
         DNUy0T0PQGQPQkOa2OtRM9IFBxL65ZX+skCVclMiQ4zkgCbvDtEwmcmQyhv8f5IgyPRM
         vLUzLklHldzNW6v9a1ESA6xkexKu7Jl3rzqGkz+d1SYtXjANgC14PPydC6TRkWeSoLKw
         uNBY2moJZP5V/MgEBoS2MVWgsSjI92zc8hInYrHj+vv8q+NnDYoxOS27gj1u3cf1Qr59
         xZ09EiACr6TkgaEfLb5J4UrX5ePycbqDWSxh1ndaxxtRkiEjn/sYTPfhgxkfiPmcZ5TM
         9hXg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=kvEzsNxbtTiJ+DIhsFl3TbpYhGU4IgcqAJkfNqqoEPU=;
        b=NS4GxzgQqydsbXGqnTTREChWyQEKVwKWc4HRHOPPbrGFmnvYzCpXp04shratNI/qRv
         nd3DwoOiPKZdUYxQVOIlgg9XMZniVAp1WIBHTqjPqVuDIaEQG1S5DMAL740TDAmlgyov
         6ybnikBRg0bjwRza1+Fn1BAGT7GVfEa9lj4VDKtpDyDIOmWu03zeuD845hHwHkTRxTzX
         3BNoG5xMRE3W4276PRK9my+ksu8K8F+8GaF7zY6ENK+JNwyXa89x+f/VbH85yT+0EWwa
         CEyLK3Q6sCY4XM31as19o6o/7BmS9tCRDbIA6Cx0WPAHWTGe4e107EVFtAJ5GWXJi6/B
         GtxA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=GYHiijcK;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::344 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=kvEzsNxbtTiJ+DIhsFl3TbpYhGU4IgcqAJkfNqqoEPU=;
        b=D5/4srFBok7rqbZ5M1al13Y6BKi+/sBSZf41nY3xx+f6IwkyEJ2Pne0+LP426GLZOU
         bohaNJ/9GqkA1Ed6gjLN2MCvMjNjfZ+ysy/VrspYFUdiM7bofGOG2weapHyNHVA5p3Ip
         exRijTMdcr5tghJBKzddsLuPArE33K+ns9pV4AAuToFVoD7s7hBC5iwljB+sLMYp2/T2
         iI1beTB7YOIRd1571TPClcBUgkNucCDkjWj8R1r6U2iTq3Dh05pNMda0LTFiG+n0yG8a
         1ydKg5M5vuJ3Mjlgw2Lcdh5CNgNJM5Ov9d5FU/1o2EV5Tctq0pZLu0BEEnJOe09tKYlc
         rrvg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=kvEzsNxbtTiJ+DIhsFl3TbpYhGU4IgcqAJkfNqqoEPU=;
        b=N6zkNS6KF2uZM+3b2REDgg1BxXkKWzZd93LY4kq0eTRK5cg+WSvu6b5ZN96gXP5TbP
         n0h2/xXvBrSclrFvHXyOWPC9fsbE7PaLphQqzK+XwJAE1O9jufCfwiBA3PU5M4laUUmm
         2BM2581HNoRwwyfCcC7tzj/V7+hl4zCaBzKwNei8RXEwujlMHwYRoeCkuH6kHx/BqzNd
         tlC7IIAb/PM4vlwY/Sps3Ay0dazgkNo2qljyqfBywZpJOAz5rqzk46exinKf9b9/ghp6
         EUqOEwdUdJXm0RD5N3EFW8ONo+UgUGKra+gB9WqfDu4SftKoWFFWAog+V4eQG/KPv+X1
         Ylgg==
X-Gm-Message-State: APjAAAX9T/U4PIZ2SAJrdiQ+gzwUPuW9rdbtp8Fy+f7PsGjq9B12A9wQ
	bve1ffUZzoozhMslbGG2Zjo=
X-Google-Smtp-Source: APXvYqyNK2tzvN4eusI3b5V1igZTDxc4K0ZuNQUSFTCTHl9tHSEf2TDw8xssURLKs4v0axl/AWqkNQ==
X-Received: by 2002:a17:902:6a8c:: with SMTP id n12mr1723686plk.152.1579301700472;
        Fri, 17 Jan 2020 14:55:00 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:28f:: with SMTP id az15ls2773011pjb.3.gmail; Fri, 17
 Jan 2020 14:55:00 -0800 (PST)
X-Received: by 2002:a17:90a:fa82:: with SMTP id cu2mr8728624pjb.109.1579301700004;
        Fri, 17 Jan 2020 14:55:00 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1579301700; cv=none;
        d=google.com; s=arc-20160816;
        b=QwVEZ+Jkroe4jtyHgNIrz5wM/ANuqyOVnp2YNF1kBfqKyN2MCmW8YBnpiTNzVrL+m2
         8H21YPf7pzNDsRPEhBAA+MXoRcRnuXFlA5FWolSBiFilVtVAgvrgYjxPRZdVPoB4+Hsu
         X5LUZsRCcPFEJedlrtiZDtiiOAgHVPqHXeH+exlXvXRVfg7ZWeYjrPK1JTt5VgAcq+Q4
         lT2mgIn5NxR0J1HKwpBl2MSwpGc7QsShB05wLntTWc6IAGdE8CYaTkvdmCtdXzNO091Z
         OrLFLsSA1eMuaUHrUh7P2Q7F+PVlyIEgp+UJoQSaTIj1QSfkg1V5rSUyBzR155K6Z1KE
         6j+Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=EO6vYFCbJQ5A65+0A//G9j+Gm8OpjBCrjsnSbCo5FK4=;
        b=rdMxSZ83vtFqF587CXFNiFoB1Ow2dA43Za8GYAW7LXVUWf7xaTryFKI3f/ROdbVhRv
         1yO/jsBXoLPaMdWLxHwaI4TNDWKe8zoLipn19H+u+rjsv4+2eq5RlwHgbag9Nx4nW6E6
         xi5EIG7J0tmYeg4ggLArSsiIui5qD+aSIZB2GsaMtksZSH/5OdY7kFs6okSaXQj2ylUU
         pfPYTzipUZWkKT6hYmAemya9LWTBWU2syNIoZisy9Ir+WgHp00NnIkyRJKYIOQhbOnOD
         qUOgdSLOJhh0Xd0LpxAoDeV60LTZiLXFvTA9kiAng0sYDOwAWU+JNnNhF6Il90rwzpBb
         B7Fg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=GYHiijcK;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::344 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x344.google.com (mail-ot1-x344.google.com. [2607:f8b0:4864:20::344])
        by gmr-mx.google.com with ESMTPS id m11si196109pjb.0.2020.01.17.14.54.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 17 Jan 2020 14:54:59 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::344 as permitted sender) client-ip=2607:f8b0:4864:20::344;
Received: by mail-ot1-x344.google.com with SMTP id a15so23984196otf.1
        for <kasan-dev@googlegroups.com>; Fri, 17 Jan 2020 14:54:59 -0800 (PST)
X-Received: by 2002:a05:6830:1d6a:: with SMTP id l10mr8142047oti.233.1579301698903;
 Fri, 17 Jan 2020 14:54:58 -0800 (PST)
MIME-Version: 1.0
References: <20200114124919.11891-1-elver@google.com> <CAG_fn=X1rFGd1gfML3D5=uiLKTmMbPUm0UD6D0+bg+_hJtQMqA@mail.gmail.com>
 <CANpmjNP6+NTr7_rkNPVDbczst5vutW2K6FXXqkqFg6GGbQC31Q@mail.gmail.com>
 <20200115163754.GA2935@paulmck-ThinkPad-P72> <B2717BA1-B964-4B0A-BE4F-5B244087B9E5@lca.pw>
 <CANpmjNNfJ=n-yUfUByLfXvHc3GfUGaECZLbu7Hh05z38WSgd4g@mail.gmail.com> <20200117164017.GA21582@paulmck-ThinkPad-P72>
In-Reply-To: <20200117164017.GA21582@paulmck-ThinkPad-P72>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 17 Jan 2020 23:54:47 +0100
Message-ID: <CANpmjNOetNDfuAu6eaDap=S0tTL5qaOz_Vh18EQ3uEfuCmFLWg@mail.gmail.com>
Subject: Re: [PATCH -rcu] kcsan: Make KCSAN compatible with lockdep
To: "Paul E. McKenney" <paulmck@kernel.org>
Cc: Qian Cai <cai@lca.pw>, Alexander Potapenko <glider@google.com>, 
	Andrey Konovalov <andreyknvl@google.com>, Dmitriy Vyukov <dvyukov@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, Ingo Molnar <mingo@redhat.com>, Will Deacon <will@kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=GYHiijcK;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::344 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Fri, 17 Jan 2020 at 17:40, Paul E. McKenney <paulmck@kernel.org> wrote:
>
> On Thu, Jan 16, 2020 at 07:57:30PM +0100, Marco Elver wrote:
> > On Thu, 16 Jan 2020 at 04:39, Qian Cai <cai@lca.pw> wrote:
> > > > On Jan 15, 2020, at 11:37 AM, Paul E. McKenney <paulmck@kernel.org> wrote:
> > > > On Wed, Jan 15, 2020 at 05:26:55PM +0100, Marco Elver wrote:
> > > >> On Tue, 14 Jan 2020 at 18:24, Alexander Potapenko <glider@google.com> wrote:
> > > >>>
> > > >>>> --- a/kernel/kcsan/core.c
> > > >>>> +++ b/kernel/kcsan/core.c
> > > >>>> @@ -337,7 +337,7 @@ kcsan_setup_watchpoint(const volatile void *ptr, size_t size, int type)
> > > >>>>         *      detection point of view) to simply disable preemptions to ensure
> > > >>>>         *      as many tasks as possible run on other CPUs.
> > > >>>>         */
> > > >>>> -       local_irq_save(irq_flags);
> > > >>>> +       raw_local_irq_save(irq_flags);
> > > >>>
> > > >>> Please reflect the need to use raw_local_irq_save() in the comment.
> > > >>>
> > > >>>>
> > > >>>>        watchpoint = insert_watchpoint((unsigned long)ptr, size, is_write);
> > > >>>>        if (watchpoint == NULL) {
> > > >>>> @@ -429,7 +429,7 @@ kcsan_setup_watchpoint(const volatile void *ptr, size_t size, int type)
> > > >>>>
> > > >>>>        kcsan_counter_dec(KCSAN_COUNTER_USED_WATCHPOINTS);
> > > >>>> out_unlock:
> > > >>>> -       local_irq_restore(irq_flags);
> > > >>>> +       raw_local_irq_restore(irq_flags);
> > > >>>
> > > >>> Ditto
> > > >>
> > > >> Done. v2: http://lkml.kernel.org/r/20200115162512.70807-1-elver@google.com
> > > >
> > > > Alexander and Qian, could you please let me know if this fixes things
> > > > up for you?
> > >
> > > The lockdep warning is gone, so feel free to add,
> > >
> > > Tested-by: Qian Cai <cai@lca.pw>
> >
> > Thank you for testing!
> >
> > > for that patch, but the system is still unable to boot due to spam of
> > > warnings due to incompatible with debug_pagealloc, debugobjects, so
> > > the warning rate limit does not help.
> >
> > You may also try to set CONFIG_KCSAN_REPORT_ONCE_IN_MS to something
> > large, say 1000000000 (effectively reporting each data race once).
> >
> > That being said, there are 2 options here:
> >
> > Option 1. If that still isn't satisfactory, we can try to make the
> > system somehow tolerate the excessive number of data race reports
> > (there may indeed be other printk limits based on rate or context we
> > are hitting). More important appears to be the below...
> >
> > Option 2. Investigate and fix the bugs, or declare them "benign" to
> > the tool. Compared to option (1) this will have much bigger impact on
> > the kernel, as it not only improves the kernel with all the debugging
> > tools enabled, but more importantly, improves the kernel *without* the
> > debugging tools. This is what should be our goal here.
>
> True enough, but even if we reach the nirvana state where there is general
> agreement on what constitutes a data race in need of fixing and KCSAN
> faithfully checks based on that data-race definition, we need to handle
> the case where someone introduces a bug that results in a destructive
> off-CPU access to a per-CPU variable, which is exactly the sort of thing
> that KCSAN is supposed to detect.  But suppose that this variable is
> frequently referenced from functions that are inlined all over the place.
>
> Then that one bug might result in huge numbers of data-race reports in
> a very short period of time, especially on a large system.
>
> So, yes, option 2 is important, but it is in no way a substitute for
> KCSAN doing a good job of handling of option 1.
>
> And given limited console bandwidth, there will be cases where data-race
> reports
> must be dropped.  After all, in such cases, the only other option is to
> hang the system.  There are ways to reduce the number of such cases, and
> of course your recent (and much appreciated!) patches merging identical
> reports is a great example of this.  But Qian's experience indicates that
> this does not cover all cases -- nor would I expect it to have done so.

Agreed. And I'll keep looking into this.

> > With that in mind, I tried to fix debugobjects data races:
> >   http://lkml.kernel.org/r/20200116185529.11026-1-elver@google.com
> > Feel free to test, and reply to that patch with comments.
>
> Very good!
>
> For my part, I am quite a bit closer to having RCU free of KCSAN reports.
> One of the remaining ones looks related to a bug in rcu_barrier()'s
> handling of no-CBs CPUs that shows up once per few hundred hours
> of rcutorture testing of TREE04.  KCSAN did find some real bugs, so
> thank you!  Sadly, it does not (yet) find this one, but it does find
> consequences of it, which will at least reduce the testing burden once
> I do get it fixed.

Interesting.  I wonder if it doesn't find it because of missing
instrumentation of some arch asm?

Thanks,
-- Marco


> (So, yes, if anyone is seeing rcu_barrier() returning too soon on systems
> with CONFIG_RCU_NOCB_CPU=y on a system whose console output includes the
> string "Offload RCU callbacks from CPUs" with at least one CPU listed
> (as opposed to the string "(none)", please do let me know!  My best
> guess is that this was introduced in v5.4.)
>
>                                                         Thanx, Paul
>
> > Thanks,
> > -- Marco
> >
> >
> >
> >
> >
> >
> > > [   28.992752][  T394] Reported by Kernel Concurrency Sanitizer on:
> > > [   28.992752][  T394] CPU: 0 PID: 394 Comm: pgdatinit0 Not tainted 5.5.0-rc6-next-20200115+ #3
> > > [   28.992752][  T394] Hardware name: HP ProLiant XL230a Gen9/ProLiant XL230a Gen9, BIOS U13 01/22/2018
> > > [   28.992752][  T394] ===============================================================
> > > [   28.992752][  T394] ==================================================================
> > > [   28.992752][  T394] BUG: KCSAN: data-race in __change_page_attr / __change_page_attr
> > > [   28.992752][  T394]
> > > [   28.992752][  T394] read to 0xffffffffa01a6de0 of 8 bytes by task 395 on cpu 16:
> > > [   28.992752][  T394]  __change_page_attr+0xe81/0x1620
> > > [   28.992752][  T394]  __change_page_attr_set_clr+0xde/0x4c0
> > > [   28.992752][  T394]  __set_pages_np+0xcc/0x100
> > > [   28.992752][  T394]  __kernel_map_pages+0xd6/0xdb
> > > [   28.992752][  T394]  __free_pages_ok+0x1a8/0x730
> > > [   28.992752][  T394]  __free_pages+0x51/0x90
> > > [   28.992752][  T394]  __free_pages_core+0x1c7/0x2c0
> > > [   28.992752][  T394]  deferred_free_range+0x59/0x8f
> > > [   28.992752][  T394]  deferred_init_max21d
> > > [   28.992752][  T394]  deferred_init_memmap+0x14a/0x1c1
> > > [   28.992752][  T394]  kthread+0x1e0/0x200
> > > [   28.992752][  T394]  ret_from_fork+0x3a/0x50
> > > [   28.992752][  T394]
> > > [   28.992752][  T394] write to 0xffffffffa01a6de0 of 8 bytes by task 394 on cpu 0:
> > > [   28.992752][  T394]  __change_page_attr+0xe9c/0x1620
> > > [   28.992752][  T394]  __change_page_attr_set_clr+0xde/0x4c0
> > > [   28.992752][  T394]  __set_pages_np+0xcc/0x100
> > > [   28.992752][  T394]  __kernel_map_pages+0xd6/0xdb
> > > [   28.992752][  T394]  __free_pages_ok+0x1a8/0x730
> > > [   28.992752][  T394]  __free_pages+0x51/0x90
> > > [   28.992752][  T394]  __free_pages_core+0x1c7/0x2c0
> > > [   28.992752][  T394]  deferred_free_range+0x59/0x8f
> > > [   28.992752][  T394]  deferred_init_maxorder+0x1d6/0x21d
> > > [   28.992752][  T394]  deferred_init_memmap+0x14a/0x1c1
> > > [   28.992752][  T394]  kthread+0x1e0/0x200
> > > [   28.992752][  T394]  ret_from_fork+0x3a/0x50
> > >
> > >
> > > [   93.233621][  T349] Reported by Kernel Concurrency Sanitizer on:
> > > [   93.261902][  T349] CPU: 19 PID: 349 Comm: kworker/19:1 Not tainted 5.5.0-rc6-next-20200115+ #3
> > > [   93.302634][  T349] Hardware name: HP ProLiant XL230a Gen9/ProLiant XL230a Gen9, BIOS U13 01/22/2018
> > > [   93.345413][  T349] Workqueue: memcg_kmem_cache memcg_kmem_cache_create_func
> > > [   93.378715][  T349] ==================================================================
> > > [   93.416183][  T616] ==================================================================
> > > [   93.453415][  T616] BUG: KCSAN: data-race in __debug_object_init / fill_pool
> > > [   93.486775][  T616]
> > > [   93.497644][  T616] read to 0xffffffff9ff33b78 of 4 bytes by task 617 on cpu 12:
> > > [   93.534139][  T616]  fill_pool+0x38/0x700
> > > [   93.554913][  T616]  __debug_object_init+0x3f/0x900
> > > [   93.579459][  T616]  debug_object_init+0x39/0x50
> > > [   93.601952][  T616]  __init_work+0x3e/0x50
> > > [   93.620611][  T616]  memcg_kmem_get_cache+0x3c8/0x480
> > > [   93.643619][  T616]  slab_pre_alloc_hook+0x5d/0xa0
> > > [   93.665134][  T616]  __kmalloc_node+0x60/0x300
> > > [   93.685094][  T616]  kvmalloc_node+0x83/0xa0
> > > [   93.704235][  T616]  seq_read+0x57c/0x7a0
> > > [   93.722460][  T616]  proc_reg_read+0x11a/0x160
> > > [   93.743570][  T616]  __vfs_read+0x59/0xa0
> > > [   93.761660][  T616]  vfs_read+0xcf/0x1c0
> > > [   93.779269][  T616]  ksys_read+0x9d/0x130
> > > [   93.797267][  T616]  __x64_sys_read+0x4c/0x60
> > > [   93.817205][  T616]  do_syscall_64+0x91/0xb47
> > > [   93.837590][  T616]  entry_SYSCALL_64_after_hwframe+0x49/0xbe
> > > [   93.864425][  T616]
> > > [   93.874830][  T616] write to 0xffffffff9ff33b78 of 4 bytes by task 616 on cpu 61:
> > > [   93.908534][  T616]  __debug_object_init+0x6e5/0x900
> > > [   93.931018][  T616]  debug_object_activate+0x1fc/0x350
> > > [   93.954131][  T616]  call_rcu+0x4c/0x4e0
> > > [   93.971959][  T616]  put_object+0x6a/0x90
> > > [   93.989955][  T616]  __delete_object+0xb9/0xf0
> > > [   94.009996][  T616]  delete_object_full+0x2d/0x40
> > > [   94.031812][  T616]  kmemleak_free+0x5f/0x90
> > > [   94.054671][  T616]  slab_free_freelist_hook+0x124/0x1c0
> > > [   94.082027][  T616]  kmem_cache_free+0x10c/0x3a0
> > > [   94.103806][  T616]  vm_area_free+0x31/0x40
> > > [   94.124587][  T616]  remove_vma+0xb0/0xc0
> > > [   94.143484][  T616]  exit_mmap+0x14c/0x220
> > > [   94.163826][  T616]  mmput+0x10e/0x270
> > > [   94.181736][  T616]  flush_old_exec+0x572/0xfe0
> > > [   94.202760][  T616]  load_elf_binary+0x467/0x2180
> > > [   94.224819][  T616]  search_binary_handler+0xd8/0x2b0
> > > [   94.248735][  T616]  __do_execve_file+0xb61/0x1080
> > > [   94.270943][  T616]  __x64_sys_execve+0x5f/0x70
> > > [   94.292254][  T616]  do_syscall_64+0x91/0xb47
> > > [   94.312712][  T616]  entry_SYSCALL_64_after_hwframe+0x49/0xbe
> > >
> > > [  103.455945][   C22] Reported by Kernel Concurrency Sanitizer on:
> > > [  103.483032][   C22] CPU: 22 PID: 0 Comm: swapper/22 Not tainted 5.5.0-rc6-next-20200115+ #3
> > > [  103.520563][   C22] Hardware name: HP ProLiant XL230a Gen9/ProLiant XL230a Gen9, BIOS U13 01/22/2018
> > > [  103.561771][   C22] ==================================================================
> > > [  103.598005][   C41] ==================================================================
> > > [  103.633820][   C41] BUG: KCSAN: data-race in intel_pstate_update_util / intel_pstate_update_util
> > > [  103.673408][   C41]
> > > [  103.683214][   C41] read to 0xffffffffa9098a58 of 2 bytes by interrupt on cpu 2:
> > > [  103.716645][   C41]  intel_pstate_update_util+0x580/0xb40
> > > [  103.740609][   C41]  cpufreq_update_util+0xb0/0x160
> > > [  103.762611][   C41]  update_blocked_averages+0x585/0x630
> > > [  103.786435][   C41]  run_rebalance_domains+0xd5/0x240
> > > [  103.812821][   C41]  __do_softirq+0xd9/0x57c
> > > [  103.834438][   C41]  irq_exit+0xa2/0xc0
> > > [  103.851773][   C41]  smp_apic_timer_interrupt+0x190/0x480
> > > [  103.876005][   C41]  apic_timer_interrupt+0xf/0x20
> > > [  103.897495][   C41]  cpuidle_enter_state+0x18a/0x9b0
> > > [  103.919324][   C41]  cpuidle_enter+0x69/0xc0
> > > [  103.938405][   C41]  call_cpuidle+0x23/0x40
> > > [  103.957152][   C41]  do_idle+0x248/0x280
> > > [  103.974728][   C41]  cpu_startup_entry+0x1d/0x1f
> > > [  103.995059][   C41]  start_secondary+0x1ad/0x230
> > > [  104.015920][   C41]  secondary_startup_64+0xb6/0xc0
> > > [  104.037376][   C41]
> > > [  104.047144][   C41] write to 0xffffffffa9098a59 of 1 bytes by interrupt on cpu 41:
> > > [  104.081113][   C41]  intel_pstate_update_util+0x4cf/0xb40
> > > [  104.105862][   C41]  cpufreq_update_util+0xb0/0x160
> > > [  104.127759][   C41]  update_load_avg+0x70e/0x800
> > > [  104.148400][   C41]  task_tick_fair+0x5c/0x680
> > > [  104.168325][   C41]  scheduler_tick+0xab/0x120
> > > [  104.188881][   C41]  update_process_times+0x44/0x60
> > > [  104.210811][   C41]  tick_sched_handle+0x4f/0xb0
> > > [  104.231137][   C41]  tick_sched_timer+0x45/0xc0
> > > [  104.251431][   C41]  __hrtimer_run_queues+0x243/0x800
> > > [  104.274362][   C41]  hrtimer_interrupt+0x1d4/0x3e0
> > > [  104.295860][   C41]  smp_apic_timer_interrupt+0x11d/0x480
> > > [  104.325136][   C41]  apic_timer_interrupt+0xf/0x20
> > > [  104.347864][   C41]  __kcsan_check_access+0x1a/0x120
> > > [  104.370100][   C41]  __read_once_size+0x1f/0xe0
> > > [  104.390064][   C41]  smp_call_function_many+0x4b0/0x5d0
> > > [  104.413591][   C41]  on_each_cpu+0x46/0x90
> > > [  104.431954][   C41]  flush_tlb_kernel_range+0x97/0xc0
> > > [  104.454702][   C41]  free_unmap_vmap_area+0xaa/0xe0
> > > [  104.476699][   C41]  remove_vm_area+0xf4/0x100
> > > [  104.496763][   C41]  __vunmap+0x10a/0x460
> > > [  104.514807][   C41]  __vfree+0x33/0x90
> > > [  104.531597][   C41]  vfree+0x47/0x80
> > > [  104.547600][   C41]  n_tty_close+0x56/0x80
> > > [  104.565988][   C41]  tty_ldisc_close+0x76/0xa0
> > > [  104.585912][   C41]  tty_ldisc_kill+0x51/0xa0
> > > [  104.605864][   C41]  tty_ldisc_release+0xf4/0x1a0
> > > [  104.627098][   C41]  tty_release_struct+0x23/0x60
> > > [  104.648268][   C41]  tty_release+0x673/0x9c0
> > > [  104.667517][   C41]  __fput+0x187/0x410
> > > [  104.684357][   C41]  ____fput+0x1e/0x30
> > > [  104.701542][   C41]  task_work_run+0xed/0x140
> > > [  104.721358][   C41]  do_syscall_64+0x803/0xb47
> > > [  104.740872][   C41]  entry_SYSCALL_64_after_hwframe+0x49/0xbe
> > >
> > > [  136.745789][   C34] Reported by Kernel Concurrency Sanitizer on:
> > > [  136.774278][   C34] CPU: 34 PID: 0 Comm: swapper/34 Not tainted 5.5.0-rc6-next-20200115+ #3
> > > [  136.814948][   C34] Hardware name: HP ProLiant XL230a Gen9/ProLiant XL230a Gen9, BIOS U13 01/22/2018
> > > [  136.861974][   C34] ==================================================================
> > > [  136.911354][    T1] ==================================================================
> > > [  136.948491][    T1] BUG: KCSAN: data-race in __debug_object_init / fill_pool
> > > [  136.981645][    T1]
> > > [  136.992045][    T1] read to 0xffffffff9ff33b78 of 4 bytes by task 762 on cpu 25:
> > > [  137.026513][    T1]  fill_pool+0x38/0x700
> > > [  137.045575][    T1]  __debug_object_init+0x3f/0x900
> > > [  137.068826][    T1]  debug_object_activate+0x1fc/0x350
> > > [  137.093102][    T1]  call_rcu+0x4c/0x4e0
> > > [  137.111520][    T1]  __fput+0x23a/0x410
> > > [  137.129618][    T1]  ____fput+0x1e/0x30
> > > [  137.147627][    T1]  task_work_run+0xed/0x140
> > > [  137.168322][    T1]  do_syscall_64+0x803/0xb47
> > > [  137.188572][    T1]  entry_SYSCALL_64_after_hwframe+0x49/0xbe
> > > [  137.215309][    T1]
> > > [  137.225579][    T1] write to 0xffffffff9ff33b78 of 4 bytes by task 1 on cpu 7:
> > > [  137.259867][    T1]  __debug_object_init+0x6e5/0x900
> > > [  137.283065][    T1]  debug_object_activate+0x1fc/0x350
> > > [  137.306988][    T1]  call_rcu+0x4c/0x4e0
> > > [  137.326804][    T1]  dentry_free+0x70/0xe0
> > > [  137.347208][    T1]  __dentry_kill+0x1db/0x300
> > > [  137.369468][    T1]  shrink_dentry_list+0x153/0x2e0
> > > [  137.393437][    T1]  shrink_dcache_parent+0x1ee/0x320
> > > [  137.417174][    T1]  d_invalidate+0x80/0x130
> > > [  137.437280][    T1]  proc_flush_task+0x14c/0x2b0
> > > [  137.459263][    T1]  release_task.part.21+0x156/0xb50
> > > [  137.483580][    T1]  wait_consider_task+0x17a8/0x1960
> > > [  137.507550][    T1]  do_wait+0x25b/0x560
> > > [  137.526175][    T1]  kernel_waitid+0x194/0x270
> > > [  137.547105][    T1]  __do_sys_waitid+0x18e/0x1e0
> > > [  137.568951][    T1]  __x64_sys_waitid+0x70/0x90
> > > [  137.590291][    T1]  do_syscall_64+0x91/0xb47
> > > [  137.610681][    T1]  entry_SYSCALL_64_after_hwframe+0x49/0xbe
> > >

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOetNDfuAu6eaDap%3DS0tTL5qaOz_Vh18EQ3uEfuCmFLWg%40mail.gmail.com.
