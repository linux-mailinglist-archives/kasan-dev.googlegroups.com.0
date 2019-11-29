Return-Path: <kasan-dev+bncBCMIZB7QWENRB4MXQTXQKGQEBLFBWLY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83c.google.com (mail-qt1-x83c.google.com [IPv6:2607:f8b0:4864:20::83c])
	by mail.lfdr.de (Postfix) with ESMTPS id 780AA10D58C
	for <lists+kasan-dev@lfdr.de>; Fri, 29 Nov 2019 13:15:47 +0100 (CET)
Received: by mail-qt1-x83c.google.com with SMTP id f14sf18892455qto.2
        for <lists+kasan-dev@lfdr.de>; Fri, 29 Nov 2019 04:15:47 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1575029746; cv=pass;
        d=google.com; s=arc-20160816;
        b=mUVMfV8/ohZeMMJS/sId4hZYgsqOdT4c3ZkLFAEk3MqufCp29H9TuC/UGfIXkvJmIQ
         nY18kny0CFZAncz+UY+FX5cvut0eaN3OXyfwrEKKBDZhIn4jmIcwoRcBgFmP3QSjwGhO
         QpzRPkDauLsnyhx8Q1+NsciHKfA1bW8qy2JfDzM6RqQudw4khavcxT3HjCSjPL7sfA+T
         xDUgrh/k+Gx6aSZ77IewCwl545y2ZayyMwYZH9toaxyHMwg082HwmXuYekXT9SourOzW
         OS26DIh6JWkilTDvQ7ZvcJuw1z7zG1lnO5lMgTO8Xidx8/hiLdGMFbnXsbUtkreQdn5O
         3k0w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=DE4dJKoCsiQh8adXqszjoA4vBsNHiQsghEJyFfqYnF8=;
        b=Mg4HyzhCD9Ba0U+dM3ljT07I2UiHdP0CtajamOgL4KrXlMR3c6r2pkzOukvk7XhHHF
         UHS1M2mPvCj/XYFSGKsBmsd5WSD3NjbuQXAYhxtZN4buAw6W7TKLqzl/EBVCQ4F4sx9C
         6v5SKO01Knf6EyF6KakWnjH7SmD0m+ewBNJgXYxmnmJVf/c62ZyBKpVK0Shiimp2sEWL
         +8zYaN08l9HtAXUdMvasnV+1tjQyXuALs7yTLMwmhIOjulniCLkVEDKgyTe9BulVAZ+D
         0Yf3qEu+EIZt8/5UAn2F8sWQnjURaEr8CIoRR06EDQzDGQkuO/WXbrLotH6P1sZSvIXa
         stoQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=DKA8tIwm;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::a42 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=DE4dJKoCsiQh8adXqszjoA4vBsNHiQsghEJyFfqYnF8=;
        b=SPq6coc50cf4ncNH6bMFEMCFWggLdxSdBrabK4O445wAwfJdYke5GM0uHn3Afnx9JC
         +ORDsGLNLfu+0TER6aclYADfSyep7d4FgKnI5Qz3LrXihW2AeVqncZ2n6nctIEksFyxa
         0GVrZaffClUNgMxw71LZYW2s8ixAmBxqZK9vekyinMmruOlJ3BODD5OYg9CTG6klaU2R
         DwHHq0cM9jByb7WZQCTNh2VA5aW/ahtMdZ09E+nQtUrvGLb2g/3hkUwPaSnOTpidspBg
         Ub4ZIPj4tWz28zbJGeTSHJ7noLCvsWTlJLywI6tXGljwUR9vOyFZezmmYdmncb78ZjTY
         9phw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=DE4dJKoCsiQh8adXqszjoA4vBsNHiQsghEJyFfqYnF8=;
        b=uU4Ls4QMB/acOZqpe3vfnJ5UkuYN8HupZB10x0DfSxmqstxIcV/JTfsxu7T5NB9J2n
         CcVtcVmO9v5qQfloinbWNwdJvTPOQAztU4CiR/38seu3qAfgIzybeqXZsqlvfIbhhcPA
         mTjZHghA+cqrjxZaM8dfAg/hxn5hNi5PvQjtZFEkYwVvY5iHnzK6Bx91ln6YMfd93dGC
         SK6/hSPQGv1HadGPppAuuxLFeB5CnWXHnJlyA3Bd3iU2YKiUpFVBMVKMyrThusYPU+NN
         gd9JyhdcB2znxXVAf6mthAjNqni+ekRSHo+eyzXCqVmNCipcfyaT/dgJK36QQSU3eKLw
         m4KQ==
X-Gm-Message-State: APjAAAXAmupuVhZ93Sti2zewmvdFdmTPGukWsmMT4llLCifFf6WJ+XeV
	DbgmZzFkN970IfHAldPcp4g=
X-Google-Smtp-Source: APXvYqxnEBuR4qZNK6EvNFIKxpkRgF6KlRdy1Uz4W+G4MNo8MC1F68M1IzwwEop99sSJnSX9sb4ovQ==
X-Received: by 2002:a05:620a:1eb:: with SMTP id x11mr15924470qkn.254.1575029745943;
        Fri, 29 Nov 2019 04:15:45 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:478c:: with SMTP id k12ls1986920qtq.3.gmail; Fri, 29 Nov
 2019 04:15:45 -0800 (PST)
X-Received: by 2002:ac8:664c:: with SMTP id j12mr36842427qtp.350.1575029745565;
        Fri, 29 Nov 2019 04:15:45 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1575029745; cv=none;
        d=google.com; s=arc-20160816;
        b=hu3s7vN4U7ZXntJFYoVde7zjMcOaj45IUhEGecmYWRHNDYt1EFrL+jtfTOJ2q6lnDB
         nEGAICIOC4X4YAtBWB72mGQmCHBTyAEj9lFQDbZCDBAGZRKt3IJVLoll9RT7buoIjxY6
         gdcQhQx4FoBqU0kkipapyzcgjrE52uGa22AAVhowslzj36n7e7nuf1L09gFn4Mrc+hGC
         fwAiQOTCDrxhs6LqWZm+uLK2tqxdcFin2ELU9AsPfIFy35MDxIGTtxbb0UZo5TzH7UCo
         7d7X221bQs9/uQ9eYJ0HHvojTxnj6N/EHnKCJf6TwsTc0K79CTDxXXUNmSpJEBEVRygW
         qbYw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=0WhiOTotl5RS7Nhgu+DEp8rXQD1OdZR5GYdZuvSwXtw=;
        b=SPnJo/WC9kP2d3qvAnxJPEh8CRrJqjJrCmLlo0jeBPMrphFwCknZ+KuvgQnkLyKiDf
         KhEi+WwAncUPewUy6SPh8RoAN4sKNIfNmr2sFN0S36WB7XaIH4mRwv+a0Br4u2fN0CaV
         IoWDHQiJqNSrkzx0EhX0aKfJnDErz3NzKgJ3IPCH/vrIZqIimzr8Dle4Fk5icXJysh0T
         Fc9c/i894AdiwJgFDQ3vRuouuY576rhwrDQjRiWcv5LQNwqdHIJVA0nLPoyYUXmal/8e
         EJ8IerYhQR8G64yWXwcr+knAeioRVJ3vOfJCPJ/UNeG7NM2N2TIc/8tZXo+f3jVS2auy
         XCig==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=DKA8tIwm;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::a42 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-vk1-xa42.google.com (mail-vk1-xa42.google.com. [2607:f8b0:4864:20::a42])
        by gmr-mx.google.com with ESMTPS id z194si813813qka.5.2019.11.29.04.15.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 29 Nov 2019 04:15:45 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::a42 as permitted sender) client-ip=2607:f8b0:4864:20::a42;
Received: by mail-vk1-xa42.google.com with SMTP id m128so5569844vkb.5
        for <kasan-dev@googlegroups.com>; Fri, 29 Nov 2019 04:15:45 -0800 (PST)
X-Received: by 2002:a1f:e784:: with SMTP id e126mr9488593vkh.102.1575029743872;
 Fri, 29 Nov 2019 04:15:43 -0800 (PST)
MIME-Version: 1.0
References: <20191031093909.9228-1-dja@axtens.net> <20191031093909.9228-2-dja@axtens.net>
 <1573835765.5937.130.camel@lca.pw> <871ru5hnfh.fsf@dja-thinkpad.axtens.net>
 <952ec26a-9492-6f71-bab1-c1def887e528@virtuozzo.com> <CACT4Y+ZGO8b88fUyFe-WtV3Ubr11ChLY2mqk8YKWN9o0meNtXA@mail.gmail.com>
 <CACT4Y+Z+VhfVpkfg-WFq_kFMY=DE+9b_DCi-mCSPK-udaf_Arg@mail.gmail.com> <874kymg9zc.fsf@dja-thinkpad.axtens.net>
In-Reply-To: <874kymg9zc.fsf@dja-thinkpad.axtens.net>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 29 Nov 2019 13:15:28 +0100
Message-ID: <CACT4Y+bOBUDO9BuPQ4PX6e42_skqsWfXdfojgX+yx8RX2DGHzA@mail.gmail.com>
Subject: Re: [PATCH v11 1/4] kasan: support backing vmalloc space with real
 shadow memory
To: Daniel Axtens <dja@axtens.net>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Qian Cai <cai@lca.pw>, 
	kasan-dev <kasan-dev@googlegroups.com>, Linux-MM <linux-mm@kvack.org>, 
	"the arch/x86 maintainers" <x86@kernel.org>, Alexander Potapenko <glider@google.com>, Andy Lutomirski <luto@kernel.org>, 
	LKML <linux-kernel@vger.kernel.org>, Mark Rutland <mark.rutland@arm.com>, 
	Christophe Leroy <christophe.leroy@c-s.fr>, linuxppc-dev <linuxppc-dev@lists.ozlabs.org>, 
	Vasily Gorbik <gor@linux.ibm.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=DKA8tIwm;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::a42
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Dmitry Vyukov <dvyukov@google.com>
Reply-To: Dmitry Vyukov <dvyukov@google.com>
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

On Fri, Nov 29, 2019 at 1:09 PM Daniel Axtens <dja@axtens.net> wrote:
>
> Hi Dmitry,
>
> >> I am testing this support on next-20191129 and seeing the following warnings:
> >>
> >> BUG: sleeping function called from invalid context at mm/page_alloc.c:4681
> >> in_atomic(): 1, irqs_disabled(): 0, non_block: 0, pid: 44, name: kworker/1:1
> >> 4 locks held by kworker/1:1/44:
> >>  #0: ffff888067c26d28 ((wq_completion)events){+.+.}, at:
> >> __write_once_size include/linux/compiler.h:247 [inline]
> >>  #0: ffff888067c26d28 ((wq_completion)events){+.+.}, at:
> >> arch_atomic64_set arch/x86/include/asm/atomic64_64.h:34 [inline]
> >>  #0: ffff888067c26d28 ((wq_completion)events){+.+.}, at: atomic64_set
> >> include/asm-generic/atomic-instrumented.h:868 [inline]
> >>  #0: ffff888067c26d28 ((wq_completion)events){+.+.}, at:
> >> atomic_long_set include/asm-generic/atomic-long.h:40 [inline]
> >>  #0: ffff888067c26d28 ((wq_completion)events){+.+.}, at: set_work_data
> >> kernel/workqueue.c:615 [inline]
> >>  #0: ffff888067c26d28 ((wq_completion)events){+.+.}, at:
> >> set_work_pool_and_clear_pending kernel/workqueue.c:642 [inline]
> >>  #0: ffff888067c26d28 ((wq_completion)events){+.+.}, at:
> >> process_one_work+0x88b/0x1750 kernel/workqueue.c:2235
> >>  #1: ffffc900002afdf0 (pcpu_balance_work){+.+.}, at:
> >> process_one_work+0x8c0/0x1750 kernel/workqueue.c:2239
> >>  #2: ffffffff8943f080 (pcpu_alloc_mutex){+.+.}, at:
> >> pcpu_balance_workfn+0xcc/0x13e0 mm/percpu.c:1845
> >>  #3: ffffffff89450c78 (vmap_area_lock){+.+.}, at: spin_lock
> >> include/linux/spinlock.h:338 [inline]
> >>  #3: ffffffff89450c78 (vmap_area_lock){+.+.}, at:
> >> pcpu_get_vm_areas+0x1449/0x3df0 mm/vmalloc.c:3431
> >> Preemption disabled at:
> >> [<ffffffff81a84199>] spin_lock include/linux/spinlock.h:338 [inline]
> >> [<ffffffff81a84199>] pcpu_get_vm_areas+0x1449/0x3df0 mm/vmalloc.c:3431
> >> CPU: 1 PID: 44 Comm: kworker/1:1 Not tainted 5.4.0-next-20191129+ #5
> >> Hardware name: QEMU Standard PC (Q35 + ICH9, 2009), BIOS 1.12.0-1 04/01/2014
> >> Workqueue: events pcpu_balance_workfn
> >> Call Trace:
> >>  __dump_stack lib/dump_stack.c:77 [inline]
> >>  dump_stack+0x199/0x216 lib/dump_stack.c:118
> >>  ___might_sleep.cold.97+0x1f5/0x238 kernel/sched/core.c:6800
> >>  __might_sleep+0x95/0x190 kernel/sched/core.c:6753
> >>  prepare_alloc_pages mm/page_alloc.c:4681 [inline]
> >>  __alloc_pages_nodemask+0x3cd/0x890 mm/page_alloc.c:4730
> >>  alloc_pages_current+0x10c/0x210 mm/mempolicy.c:2211
> >>  alloc_pages include/linux/gfp.h:532 [inline]
> >>  __get_free_pages+0xc/0x40 mm/page_alloc.c:4786
> >>  kasan_populate_vmalloc_pte mm/kasan/common.c:762 [inline]
> >>  kasan_populate_vmalloc_pte+0x2f/0x1b0 mm/kasan/common.c:753
> >>  apply_to_pte_range mm/memory.c:2041 [inline]
> >>  apply_to_pmd_range mm/memory.c:2068 [inline]
> >>  apply_to_pud_range mm/memory.c:2088 [inline]
> >>  apply_to_p4d_range mm/memory.c:2108 [inline]
> >>  apply_to_page_range+0x5ca/0xa00 mm/memory.c:2133
> >>  kasan_populate_vmalloc+0x69/0xa0 mm/kasan/common.c:791
> >>  pcpu_get_vm_areas+0x1596/0x3df0 mm/vmalloc.c:3439
> >>  pcpu_create_chunk+0x240/0x7f0 mm/percpu-vm.c:340
> >>  pcpu_balance_workfn+0x1033/0x13e0 mm/percpu.c:1934
> >>  process_one_work+0x9b5/0x1750 kernel/workqueue.c:2264
> >>  worker_thread+0x8b/0xd20 kernel/workqueue.c:2410
> >>  kthread+0x365/0x450 kernel/kthread.c:255
> >>  ret_from_fork+0x24/0x30 arch/x86/entry/entry_64.S:352
> >>
> >>
> >> Not sure if it's the same or not. Is it addressed by something in flight?
>
> It looks like this one is the same.
>
> There is a patch to fix it:
> https://lore.kernel.org/linux-mm/20191120052719.7201-1-dja@axtens.net/
>
> Andrew said he had picked it up on the 22nd:
> https://marc.info/?l=linux-mm-commits&m=157438241512561&w=2
> It's landed in mmots but not mmotm, so hopefully that will happen and
> then it will land in -next very soon!
>
> I will look into your other bug report shortly.

Thanks for the quick responses, Andrey, Daniel.


> Regards,
> Daniel
>
> >>
> >> My config:
> >> https://gist.githubusercontent.com/dvyukov/36c7be311fdec9cd51c649f7c3cb2ddb/raw/39c6f864fdd0ffc53f0822b14c354a73c1695fa1/gistfile1.txt
> >
> >
> > I've tried this fix for pcpu_get_vm_areas:
> > https://groups.google.com/d/msg/kasan-dev/t_F2X1MWKwk/h152Z3q2AgAJ
> > and it helps. But this will break syzbot on linux-next soon.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BbOBUDO9BuPQ4PX6e42_skqsWfXdfojgX%2Byx8RX2DGHzA%40mail.gmail.com.
