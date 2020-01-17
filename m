Return-Path: <kasan-dev+bncBC7OBJGL2MHBBEPVRDYQKGQEUEDVWCY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33d.google.com (mail-ot1-x33d.google.com [IPv6:2607:f8b0:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id B54BB14145F
	for <lists+kasan-dev@lfdr.de>; Fri, 17 Jan 2020 23:52:02 +0100 (CET)
Received: by mail-ot1-x33d.google.com with SMTP id e11sf14050859otq.1
        for <lists+kasan-dev@lfdr.de>; Fri, 17 Jan 2020 14:52:02 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1579301521; cv=pass;
        d=google.com; s=arc-20160816;
        b=byjiYfvUoD9LG3Zt9Xji/gUijqYs170+KU/JLwX+pWBmn0S1YtO6Vm1FW7GLIb4TDx
         mV1UJI8Td+LRhIy/8fvrU0StHuK2MzDHAs81jQW95acbvj8U1agUjdarlxgtxmDXtBQ8
         DjM0JhubVjmDgb8Yfe6Jx8Q4elswEGque/ZzgMskA9kGJvj+P0IxJts0zwA/KjMnmoif
         nQaMipbrJg7A385HZibzgbC9MPvaeiprElDvFQDmWpna0vMnxKgCVqMGeNaufzDP1p+K
         KoEay7zfy3vNTbbEXEjwD1YdKZFYIODlmVpTHvE5PMgjAQGr4yAsbP/dAsI9/RBMC2vJ
         Af8Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=92vIzEkr+sD0z+RWoCyboHlpna05xsxLvPo44jIqvuM=;
        b=ktXN8HZlB/WK+Bgg2HWrk8UvvM01IcAZ6z9or5yceJjwvvtAlCiTekb5cc3ASrmV6U
         UkFbPtzBoCu0rT+hy4LMPCY2P61p9X2RsX7e7rLjpvgRd+DtcBMpGf7gyrOcjpBOLzY+
         fBJvMo7pDP/DSGpnucEB2kMbyzvcsi1G1R9Dbj0MlUEu8haEyB/VqCSkcn1G94/8ZMTh
         hT26wgdozB2hZCumAN4X9xkbKVLZ0DwmGzjGxf3bxl1z3iLr/MMK1dAP6HtZehVIUKdg
         LiE+js78y5n1InPQxL2l9xI5W70Oas4Xo9fEuxull+7+QaAgKbtB/VEaOCxYgomaSwTP
         8new==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Z6i13jfN;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::242 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=92vIzEkr+sD0z+RWoCyboHlpna05xsxLvPo44jIqvuM=;
        b=XjPt0Oz5VuRzQrm50bKirmEO5cZ8zmr5mPSjSfhrJDZdrdae1IGE4DykGq0LQroMQ9
         5lPIhFwmvSjI6EBlfyIDjHail2qMuleavk5tpsipXv7z34lMFP9mkerANhFXGsrVN0c8
         HRcUj7dV6gOM8045Dq7wa792g6QCA8oX7l+UX3a40zbW+qpKL4ON1PuP664BpWlDXPcM
         Hd8uHLpn+JEs+T2SnmD3uFw2fKonSAomSXl17pWJCJySu3juJ6ZQGlv3AG85Il7v+HRl
         7Caha3av9NTFH/0U2VZ8XYhboOFrX+kJxSIQi+upqHNS6vMryDeie3VYdY1TDhl/yipn
         uT3Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=92vIzEkr+sD0z+RWoCyboHlpna05xsxLvPo44jIqvuM=;
        b=nlw5eUGD8GnwuJcO6aKKgKTqc/v5xhjpLwpyTreiuyYkv14U6iO40i+F7ykuggZ4Xh
         2mJ91ETyZ5+jjRnuywAcTOby0IpUb4bGPkD+ZXf9QVTOxjV4UxC5gFJREUXWOV1GiVqt
         uVtiwwQgrth9bAmx1LU+Y9VoIBaP3dtjtj+a95zuLt2m1Ct+/ANL+oFP4hqK/+YJyh8l
         H2vplkTOgz3hSt9U8Uf4qilXAU+3tCW6Hv7FC3oS6CG3ow0o9uU3g4Wa+W+ebh407G5H
         hjio9Fga7JmeSVxZAhimFI4mefIRIhFZVIrKvddAfHBEdO6XtCdp1AtbojfH3PS0rKkT
         VkMQ==
X-Gm-Message-State: APjAAAX4EG4DzzUejfEI9JqQr+kUNVrrTZCPjyTdDOcfF+Ho4tTdfzne
	19b50gxJjJgzE2C5oOdMFLo=
X-Google-Smtp-Source: APXvYqx1S64kOdflkvwSFFEYkaPdS4ecMZYLz2vW8yPGEGcl39L8suwPmT5cxT/j3aZ3ccfJTjVmIQ==
X-Received: by 2002:aca:d6d2:: with SMTP id n201mr5341429oig.112.1579301521157;
        Fri, 17 Jan 2020 14:52:01 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:af4a:: with SMTP id y71ls4907389oie.16.gmail; Fri, 17
 Jan 2020 14:52:00 -0800 (PST)
X-Received: by 2002:a05:6808:3c2:: with SMTP id o2mr5219801oie.145.1579301520786;
        Fri, 17 Jan 2020 14:52:00 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1579301520; cv=none;
        d=google.com; s=arc-20160816;
        b=KX0hUitGyUGzx3HdSeuz8RQ/UQ+fmY2jXPdGrAVcittqEyVzUYjOtfGpxB9aUdZRJY
         XVvDnFrsrATJGOablkkn9BhO4Zc5V/UjGvpPLPC7GSKuwSqv0jTndbyrQG4KpS/HOHzY
         4lxpon5n9lYryXpVwKNN/N+dmCJsdNiAft1/q+l0o4u+NDn3ndfFs32fdpzLqfJ5eWtk
         caPJ3whDGggpiSALS42QyM22pngNAtKXWa5xDhhmhtzStwUvcTjEWmQ2AuqKvz0zWbGJ
         1mz5C++EC5rwx4LHIak1XKH+4L1S8rBmOjHT2qpUCbmSGQT7CqDWlk4o6Wnhp3XRa+eV
         Unlg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=bPRY1mht45VkQ0r3COkN8IZorbBTnfRW7uTMCnHTRE0=;
        b=WscJEdu80ZqgQc7Rxg2zZyEfu9uH8O2oZxLOe6sajY0i+UNyeNjxm7O0VMXQA7XPBL
         2vYIa9MxGRgbl4CRbq8gfA9RmZhJtF5fiGQVm0/EJJEakSUq9RZAegMCNNoI/NQ0gTad
         N5N7gbGSPDrTi/7/Lcsue9/n7FUoYRPGv6IM62PN8Qb1dRrmtUUs1tPShfA0xn9K6Q7V
         ekgXqwPYg3JbgV0ThzLTWwgs6Ta5wBGPUvOioBUXlww9SZnxPF+3b8wj+CCWQjUfc5Rj
         49//mlSG/H2YtDUTh3Ad0oGWO35SqW1GPc+Opi5VfGkiD4g+jP8k83urtkzB+JW64Fgs
         qNSw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Z6i13jfN;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::242 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x242.google.com (mail-oi1-x242.google.com. [2607:f8b0:4864:20::242])
        by gmr-mx.google.com with ESMTPS id q188si842504oic.5.2020.01.17.14.52.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 17 Jan 2020 14:52:00 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::242 as permitted sender) client-ip=2607:f8b0:4864:20::242;
Received: by mail-oi1-x242.google.com with SMTP id 18so23665895oin.9
        for <kasan-dev@googlegroups.com>; Fri, 17 Jan 2020 14:52:00 -0800 (PST)
X-Received: by 2002:aca:d4c1:: with SMTP id l184mr5259065oig.172.1579301520140;
 Fri, 17 Jan 2020 14:52:00 -0800 (PST)
MIME-Version: 1.0
References: <20200117164017.GA21582@paulmck-ThinkPad-P72> <3760F60F-4133-4FE1-9A4C-F335A8230285@lca.pw>
In-Reply-To: <3760F60F-4133-4FE1-9A4C-F335A8230285@lca.pw>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 17 Jan 2020 23:51:48 +0100
Message-ID: <CANpmjNPdfB=hrcXJbPzdisxnBUZW3JEK9UbTpTy+a20b=6OdJg@mail.gmail.com>
Subject: Re: [PATCH -rcu] kcsan: Make KCSAN compatible with lockdep
To: Qian Cai <cai@lca.pw>
Cc: "Paul E. McKenney" <paulmck@kernel.org>, Alexander Potapenko <glider@google.com>, 
	Andrey Konovalov <andreyknvl@google.com>, Dmitriy Vyukov <dvyukov@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, Ingo Molnar <mingo@redhat.com>, Will Deacon <will@kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=Z6i13jfN;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::242 as
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

On Fri, 17 Jan 2020 at 17:59, Qian Cai <cai@lca.pw> wrote:
>
>
>
> > On Jan 17, 2020, at 11:40 AM, Paul E. McKenney <paulmck@kernel.org> wrote:
> >
> > True enough, but even if we reach the nirvana state where there is general
> > agreement on what constitutes a data race in need of fixing and KCSAN
> > faithfully checks based on that data-race definition, we need to handle
> > the case where someone introduces a bug that results in a destructive
> > off-CPU access to a per-CPU variable, which is exactly the sort of thing
> > that KCSAN is supposed to detect.  But suppose that this variable is
> > frequently referenced from functions that are inlined all over the place.
> >
> > Then that one bug might result in huge numbers of data-race reports in
> > a very short period of time, especially on a large system.
>
> It sounds like the case with debug_pagealloc where it prints a spam of those, and then the system is just dead.
>
> [   28.992752][  T394] Reported by Kernel Concurrency Sanitizer on:
> [   28.992752][  T394] CPU: 0 PID: 394 Comm: pgdatinit0 Not tainted 5.5.0-rc6-next-20200115+ #3
> [   28.992752][  T394] Hardware name: HP ProLiant XL230a Gen9/ProLiant XL230a Gen9, BIOS U13 01/22/2018
> [   28.992752][  T394] ===============================================================
> [   28.992752][  T394] ==================================================================
> [   28.992752][  T394] BUG: KCSAN: data-race in __change_page_attr / __change_page_attr
> [   28.992752][  T394]
> [   28.992752][  T394] read to 0xffffffffa01a6de0 of 8 bytes by task 395 on cpu 16:
> [   28.992752][  T394]  __change_page_attr+0xe81/0x1620
> [   28.992752][  T394]  __change_page_attr_set_clr+0xde/0x4c0
> [   28.992752][  T394]  __set_pages_np+0xcc/0x100
> [   28.992752][  T394]  __kernel_map_pages+0xd6/0xdb
> [   28.992752][  T394]  __free_pages_ok+0x1a8/0x730
> [   28.992752][  T394]  __free_pages+0x51/0x90
> [   28.992752][  T394]  __free_pages_core+0x1c7/0x2c0
> [   28.992752][  T394]  deferred_free_range+0x59/0x8f
> [   28.992752][  T394]  deferred_init_max21d
> [   28.992752][  T394]  deferred_init_memmap+0x14a/0x1c1
> [   28.992752][  T394]  kthread+0x1e0/0x200
> [   28.992752][  T394]  ret_from_fork+0x3a/0x50
> [   28.992752][  T394]
> [   28.992752][  T394] write to 0xffffffffa01a6de0 of 8 bytes by task 394 on cpu 0:
> [   28.992752][  T394]  __change_page_attr+0xe9c/0x1620
> [   28.992752][  T394]  __change_page_attr_set_clr+0xde/0x4c0
> [   28.992752][  T394]  __set_pages_np+0xcc/0x100
> [   28.992752][  T394]  __kernel_map_pages+0xd6/0xdb
> [   28.992752][  T394]  __free_pages_ok+0x1a8/0x730
> [   28.992752][  T394]  __free_pages+0x51/0x90
> [   28.992752][  T394]  __free_pages_core+0x1c7/0x2c0
> [   28.992752][  T394]  deferred_free_range+0x59/0x8f
> [   28.992752][  T394]  deferred_init_maxorder+0x1d6/0x21d
> [   28.992752][  T394]  deferred_init_memmap+0x14a/0x1c1
> [   28.992752][  T394]  kthread+0x1e0/0x200
> [   28.992752][  T394]  ret_from_fork+0x3a/0x50
>
> It point out to this,
>
>                 pgprot_val(new_prot) &= ~pgprot_val(cpa->mask_clr);
>                 pgprot_val(new_prot) |= pgprot_val(cpa->mask_set);
>
>                 cpa_inc_4k_install();
>                 /* Hand in lpsize = 0 to enforce the protection mechanism */
>                 new_prot = static_protections(new_prot, address, pfn, 1, 0,
>                                               CPA_PROTECT);
>
> In static_protections(),
>
>         /*
>          * There is no point in checking RW/NX conflicts when the requested
>          * mapping is setting the page !PRESENT.
>          */
>         if (!(pgprot_val(prot) & _PAGE_PRESENT))
>                 return prot;
>
> Is there a data race there?

Yes. I was finally able to reproduce this data race on linux-next (my
system doesn't crash though, maybe not enough cores?). Here is a trace
with line numbers:

read to 0xffffffffaa59a000 of 8 bytes by interrupt on cpu 7:
 cpa_inc_4k_install arch/x86/mm/pat/set_memory.c:131 [inline]
 __change_page_attr+0x10cf/0x1840 arch/x86/mm/pat/set_memory.c:1514
 __change_page_attr_set_clr+0xce/0x490 arch/x86/mm/pat/set_memory.c:1636
 __set_pages_np+0xc4/0xf0 arch/x86/mm/pat/set_memory.c:2148
 __kernel_map_pages+0xb0/0xc8 arch/x86/mm/pat/set_memory.c:2178
 kernel_map_pages include/linux/mm.h:2719 [inline]
<snip>

write to 0xffffffffaa59a000 of 8 bytes by task 1 on cpu 6:
 cpa_inc_4k_install arch/x86/mm/pat/set_memory.c:131 [inline]
 __change_page_attr+0x10ea/0x1840 arch/x86/mm/pat/set_memory.c:1514
 __change_page_attr_set_clr+0xce/0x490 arch/x86/mm/pat/set_memory.c:1636
 __set_pages_p+0xc4/0xf0 arch/x86/mm/pat/set_memory.c:2129
 __kernel_map_pages+0x2e/0xc8 arch/x86/mm/pat/set_memory.c:2176
 kernel_map_pages include/linux/mm.h:2719 [inline]
<snip>

Both accesses are due to the same "cpa_4k_install++" in
cpa_inc_4k_install. Now you can see that a data race here could be
potentially undesirable: depending on compiler optimizations or how
x86 executes a non-LOCK'd increment, you may lose increments, corrupt
the counter, etc. Since this counter only seems to be used for
printing some stats, this data race itself is unlikely to cause harm
to the system though.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPdfB%3DhrcXJbPzdisxnBUZW3JEK9UbTpTy%2Ba20b%3D6OdJg%40mail.gmail.com.
