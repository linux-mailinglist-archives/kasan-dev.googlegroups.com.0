Return-Path: <kasan-dev+bncBCMIZB7QWENRBR7VQPXQKGQESUXV5QI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x93a.google.com (mail-ua1-x93a.google.com [IPv6:2607:f8b0:4864:20::93a])
	by mail.lfdr.de (Postfix) with ESMTPS id E473510D483
	for <lists+kasan-dev@lfdr.de>; Fri, 29 Nov 2019 12:02:32 +0100 (CET)
Received: by mail-ua1-x93a.google.com with SMTP id m10sf5049282uan.9
        for <lists+kasan-dev@lfdr.de>; Fri, 29 Nov 2019 03:02:32 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1575025351; cv=pass;
        d=google.com; s=arc-20160816;
        b=Qc9pon8s5H1T8urAK/6oiAEy3cr01kBUL0NzbmOyA/79iWMGgqrLJ0GsFmvLtwNv+J
         QrwAmjNgZLCZnR1cicCzlHpbhhD21c2FFeLxJcp67KRBPvOMp7P1Mjjz2LX9Ur8u1L3O
         J++0Cdbuq5/OQibZleOHRtXnjmLfs84ySY2hvhERus8eoxsvdWlpcGFWIRRGryCwI6nQ
         KhXqZ5n5n73IdazzIZa/f52DJLpN9R2u8B7RlXSnJphB9rP60IC0SYIBqniFTVXoOLbw
         mPdifJKTZhgJVnBkrEptNpxhWtVanWDLd4gVTxIbu4PVjoKUq/34bJWY0jvvUmabvoOF
         uX8A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=tyHkBdZpWzNjuLpbhCaj26PUh/pyRICmlPwgNBiQM3U=;
        b=z+2GXIk2Mcag25yG9SwgCo+Q/XHvK1XRtyt8uLtQfIlm+qhJEHq15kx0kl4z97tJdT
         wU07PNd8zMB1Oix66+oEu9zffsVW0C7gpCrtuLngO2eYVvbmDOYZmAmkst/oS41Fgwuc
         shgOB0FTBj6riEopJygXEYeI4mU92nZVr5DJ5e9sPfr9/XBAT6MjVkPuKy4Qu3f5lKP+
         7zmKgxs10HrgDALG95HdSrnS4szUnJmGkRvb3KtqYOazJvfQenROeXovZj9Aj4uBQ3RR
         DmDvGsiiD/pmjZlKB0RzgO9UoaxuMrxVOFsexzvNR7sdvYssPke+K0LHOEkBPkW1o7oy
         V/+Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=kgjOmxEy;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f42 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=tyHkBdZpWzNjuLpbhCaj26PUh/pyRICmlPwgNBiQM3U=;
        b=hefhhFOfg4ZGK7TBuZCMPduYOhN03/MOcXoWsRZ9801of7vmO0GgNfNW8shPEJpGU6
         I8OxChMnBIc3rhb6SVF7t6br8KXXjasT/bLzEwdOZn6lkrfmEsq57sC1YmxWaZEXKQPA
         bgaet+kI8jU43IA62Ovf+yZK5up7ZI81P7gxo49DF4als9f/XSbv2IlqejbZJQlJhijZ
         av1p4bVdtQPPsxSLNxcfyVJl17JBThIvNktazUOZp3KVtUHyXEEbygr0sa3nV+jxcyjR
         4+/Y3NH/B4ngde307xd9vLzw/MkRDWYIdQ7eqBSx1GsSuvz06pU5YUGqLROg4HYHZqso
         adjA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=tyHkBdZpWzNjuLpbhCaj26PUh/pyRICmlPwgNBiQM3U=;
        b=dHqCjX53g7xsUohIXdrc2tVCuB9/9KkeYRzcsNDYg5ybciKIecdLUOVBcwPj9j1icw
         fCj85IsO8Vq/oRVLUSbQqu22q52niCGHcGRfEVetRNMcAzhaGrLrGeHh3He3WjE/4qW4
         pz33wNJJjvF9VwK1f3zjuAibkWK31XWR9/yWhPfXJSH+s/21cHoWdeIPge7WQX9ZpnbK
         IjNKE/24ElhOamHu6tsE1vDZjvzBOiE/wmjvsCr+RTZOo70471ncc91mMEtek9xnG7lk
         vFhgSTveVUwbHcVz53xIAKHFTyx8ZsV4UO7/nBdJgVolzB0uJSS13FsC0zB5gUIjRK7Z
         G3OA==
X-Gm-Message-State: APjAAAWs36IU5jxFHckrdNOH4+HuHwA6y7UBRmEjbsAWZObH0hJZV4Bq
	SuKf/Hhqx3BfYFYpi/Luu+I=
X-Google-Smtp-Source: APXvYqzj4ggSsJ9j9xpMUXZiZyIJz5uXOVHq43nnZRZwIXlk4sAe9Im7o8teXMqQM51OXZJPNuDB3A==
X-Received: by 2002:a1f:4942:: with SMTP id w63mr9016355vka.49.1575025351530;
        Fri, 29 Nov 2019 03:02:31 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:e8ca:: with SMTP id y10ls3121111vsn.7.gmail; Fri, 29 Nov
 2019 03:02:31 -0800 (PST)
X-Received: by 2002:a67:fac4:: with SMTP id g4mr1119915vsq.222.1575025351052;
        Fri, 29 Nov 2019 03:02:31 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1575025351; cv=none;
        d=google.com; s=arc-20160816;
        b=Yn5KIVFKhFCoNpOL/V0jGr7ExkQdZMrd6l6J5tQv7M+RFcmQjKlfAxRYtodNKp4uqo
         DfVSPBOioYwNV3BpCrW5MAh5cmxUVqIMmXHZOhCWIq2xf1cjN4GdN5BHIW0NwlN0yBDc
         pH6YDXYDZOB24WsYyPc8gvGr3zg3l8Jw7OCvulmFsv5IRCVJKuorSe8lpZc3Qjj/ds5Q
         Y5HeX8H2aXZobq3EFYfRSj8Jo7TIndftaTxquRusTxrmYjLzKS9bBn8XetdRwhp8Ovjz
         YvvXs7hDj2+uyoBWLH0IYx0bhCNfxTYrOD2TjHdz9eEUZm9JJNh1ILcQ5V9trm5y8ibV
         FZaw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=FUXiN1jVXt44HLAwzWJlzAbonJeKoTnOjciuM0nUVO0=;
        b=zRq2N599AXK3ROhGImZ5vcYETpm9WBXtJ+n1VCH+J1hooVSN5c3i2ZXM4vlAf/YxL+
         GSu3i5+wzdaXi4rPhWAfDYVwRBwip6ZWPrmexfLZj24X9QytyvMLByQWehDCFF0jvEuv
         1DiVMdlv6btmNPhSKdHdsH5f3VC+hLH00jgvkdg4uDKuzdOVBkw6nLoOxs4rNUUDyJx9
         pOeTtiW1D2nVhaaPmH3H3uTGRFqVZhKXruhrrquZYaPc5xFzFODFAqdep+WqPJEfw494
         +EMrY0FMj7YLbJQzdTyhqhE/C1UQ9TBcq4mjvhBSowsUauyP0GCcJkxx8c3cqvATnItB
         a/nA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=kgjOmxEy;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f42 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf42.google.com (mail-qv1-xf42.google.com. [2607:f8b0:4864:20::f42])
        by gmr-mx.google.com with ESMTPS id o19si230585vka.4.2019.11.29.03.02.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 29 Nov 2019 03:02:31 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f42 as permitted sender) client-ip=2607:f8b0:4864:20::f42;
Received: by mail-qv1-xf42.google.com with SMTP id o18so4156757qvf.1
        for <kasan-dev@googlegroups.com>; Fri, 29 Nov 2019 03:02:31 -0800 (PST)
X-Received: by 2002:a0c:b446:: with SMTP id e6mr16469317qvf.159.1575025350172;
 Fri, 29 Nov 2019 03:02:30 -0800 (PST)
MIME-Version: 1.0
References: <20191031093909.9228-1-dja@axtens.net> <20191031093909.9228-2-dja@axtens.net>
 <1573835765.5937.130.camel@lca.pw> <871ru5hnfh.fsf@dja-thinkpad.axtens.net>
 <952ec26a-9492-6f71-bab1-c1def887e528@virtuozzo.com> <CACT4Y+ZGO8b88fUyFe-WtV3Ubr11ChLY2mqk8YKWN9o0meNtXA@mail.gmail.com>
 <CACT4Y+Z+VhfVpkfg-WFq_kFMY=DE+9b_DCi-mCSPK-udaf_Arg@mail.gmail.com>
In-Reply-To: <CACT4Y+Z+VhfVpkfg-WFq_kFMY=DE+9b_DCi-mCSPK-udaf_Arg@mail.gmail.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 29 Nov 2019 12:02:18 +0100
Message-ID: <CACT4Y+Yog=PHF1SsLuoehr2rcbmfvLUW+dv7Vo+1RfdTOx7AUA@mail.gmail.com>
Subject: Re: [PATCH v11 1/4] kasan: support backing vmalloc space with real
 shadow memory
To: Andrey Ryabinin <aryabinin@virtuozzo.com>
Cc: Daniel Axtens <dja@axtens.net>, Qian Cai <cai@lca.pw>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux-MM <linux-mm@kvack.org>, "the arch/x86 maintainers" <x86@kernel.org>, 
	Alexander Potapenko <glider@google.com>, Andy Lutomirski <luto@kernel.org>, LKML <linux-kernel@vger.kernel.org>, 
	Mark Rutland <mark.rutland@arm.com>, Christophe Leroy <christophe.leroy@c-s.fr>, 
	linuxppc-dev <linuxppc-dev@lists.ozlabs.org>, Vasily Gorbik <gor@linux.ibm.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=kgjOmxEy;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f42
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

On Fri, Nov 29, 2019 at 11:58 AM Dmitry Vyukov <dvyukov@google.com> wrote:
>
> On Fri, Nov 29, 2019 at 11:43 AM Dmitry Vyukov <dvyukov@google.com> wrote:
> >
> > On Tue, Nov 19, 2019 at 10:54 AM Andrey Ryabinin
> > <aryabinin@virtuozzo.com> wrote:
> > > On 11/18/19 6:29 AM, Daniel Axtens wrote:
> > > > Qian Cai <cai@lca.pw> writes:
> > > >
> > > >> On Thu, 2019-10-31 at 20:39 +1100, Daniel Axtens wrote:
> > > >>>     /*
> > > >>>      * In this function, newly allocated vm_struct has VM_UNINITIALIZED
> > > >>>      * flag. It means that vm_struct is not fully initialized.
> > > >>> @@ -3377,6 +3411,9 @@ struct vm_struct **pcpu_get_vm_areas(const unsigned long *offsets,
> > > >>>
> > > >>>             setup_vmalloc_vm_locked(vms[area], vas[area], VM_ALLOC,
> > > >>>                              pcpu_get_vm_areas);
> > > >>> +
> > > >>> +           /* assume success here */
> > > >>> +           kasan_populate_vmalloc(sizes[area], vms[area]);
> > > >>>     }
> > > >>>     spin_unlock(&vmap_area_lock);
> > > >>
> > > >> Here it is all wrong. GFP_KERNEL with in_atomic().
> > > >
> > > > I think this fix will work, I will do a v12 with it included.
> > >
> > > You can send just the fix. Andrew will fold it into the original patch before sending it to Linus.
> > >
> > >
> > >
> > > > diff --git a/mm/vmalloc.c b/mm/vmalloc.c
> > > > index a4b950a02d0b..bf030516258c 100644
> > > > --- a/mm/vmalloc.c
> > > > +++ b/mm/vmalloc.c
> > > > @@ -3417,11 +3417,14 @@ struct vm_struct **pcpu_get_vm_areas(const unsigned long *offsets,
> > > >
> > > >                 setup_vmalloc_vm_locked(vms[area], vas[area], VM_ALLOC,
> > > >                                  pcpu_get_vm_areas);
> > > > +       }
> > > > +       spin_unlock(&vmap_area_lock);
> > > >
> > > > +       /* populate the shadow space outside of the lock */
> > > > +       for (area = 0; area < nr_vms; area++) {
> > > >                 /* assume success here */
> > > >                 kasan_populate_vmalloc(sizes[area], vms[area]);
> > > >         }
> > > > -       spin_unlock(&vmap_area_lock);
> > > >
> > > >         kfree(vas);
> > > >         return vms;
> >
> > Hi,
> >
> > I am testing this support on next-20191129 and seeing the following warnings:
> >
> > BUG: sleeping function called from invalid context at mm/page_alloc.c:4681
> > in_atomic(): 1, irqs_disabled(): 0, non_block: 0, pid: 44, name: kworker/1:1
> > 4 locks held by kworker/1:1/44:
> >  #0: ffff888067c26d28 ((wq_completion)events){+.+.}, at:
> > __write_once_size include/linux/compiler.h:247 [inline]
> >  #0: ffff888067c26d28 ((wq_completion)events){+.+.}, at:
> > arch_atomic64_set arch/x86/include/asm/atomic64_64.h:34 [inline]
> >  #0: ffff888067c26d28 ((wq_completion)events){+.+.}, at: atomic64_set
> > include/asm-generic/atomic-instrumented.h:868 [inline]
> >  #0: ffff888067c26d28 ((wq_completion)events){+.+.}, at:
> > atomic_long_set include/asm-generic/atomic-long.h:40 [inline]
> >  #0: ffff888067c26d28 ((wq_completion)events){+.+.}, at: set_work_data
> > kernel/workqueue.c:615 [inline]
> >  #0: ffff888067c26d28 ((wq_completion)events){+.+.}, at:
> > set_work_pool_and_clear_pending kernel/workqueue.c:642 [inline]
> >  #0: ffff888067c26d28 ((wq_completion)events){+.+.}, at:
> > process_one_work+0x88b/0x1750 kernel/workqueue.c:2235
> >  #1: ffffc900002afdf0 (pcpu_balance_work){+.+.}, at:
> > process_one_work+0x8c0/0x1750 kernel/workqueue.c:2239
> >  #2: ffffffff8943f080 (pcpu_alloc_mutex){+.+.}, at:
> > pcpu_balance_workfn+0xcc/0x13e0 mm/percpu.c:1845
> >  #3: ffffffff89450c78 (vmap_area_lock){+.+.}, at: spin_lock
> > include/linux/spinlock.h:338 [inline]
> >  #3: ffffffff89450c78 (vmap_area_lock){+.+.}, at:
> > pcpu_get_vm_areas+0x1449/0x3df0 mm/vmalloc.c:3431
> > Preemption disabled at:
> > [<ffffffff81a84199>] spin_lock include/linux/spinlock.h:338 [inline]
> > [<ffffffff81a84199>] pcpu_get_vm_areas+0x1449/0x3df0 mm/vmalloc.c:3431
> > CPU: 1 PID: 44 Comm: kworker/1:1 Not tainted 5.4.0-next-20191129+ #5
> > Hardware name: QEMU Standard PC (Q35 + ICH9, 2009), BIOS 1.12.0-1 04/01/2014
> > Workqueue: events pcpu_balance_workfn
> > Call Trace:
> >  __dump_stack lib/dump_stack.c:77 [inline]
> >  dump_stack+0x199/0x216 lib/dump_stack.c:118
> >  ___might_sleep.cold.97+0x1f5/0x238 kernel/sched/core.c:6800
> >  __might_sleep+0x95/0x190 kernel/sched/core.c:6753
> >  prepare_alloc_pages mm/page_alloc.c:4681 [inline]
> >  __alloc_pages_nodemask+0x3cd/0x890 mm/page_alloc.c:4730
> >  alloc_pages_current+0x10c/0x210 mm/mempolicy.c:2211
> >  alloc_pages include/linux/gfp.h:532 [inline]
> >  __get_free_pages+0xc/0x40 mm/page_alloc.c:4786
> >  kasan_populate_vmalloc_pte mm/kasan/common.c:762 [inline]
> >  kasan_populate_vmalloc_pte+0x2f/0x1b0 mm/kasan/common.c:753
> >  apply_to_pte_range mm/memory.c:2041 [inline]
> >  apply_to_pmd_range mm/memory.c:2068 [inline]
> >  apply_to_pud_range mm/memory.c:2088 [inline]
> >  apply_to_p4d_range mm/memory.c:2108 [inline]
> >  apply_to_page_range+0x5ca/0xa00 mm/memory.c:2133
> >  kasan_populate_vmalloc+0x69/0xa0 mm/kasan/common.c:791
> >  pcpu_get_vm_areas+0x1596/0x3df0 mm/vmalloc.c:3439
> >  pcpu_create_chunk+0x240/0x7f0 mm/percpu-vm.c:340
> >  pcpu_balance_workfn+0x1033/0x13e0 mm/percpu.c:1934
> >  process_one_work+0x9b5/0x1750 kernel/workqueue.c:2264
> >  worker_thread+0x8b/0xd20 kernel/workqueue.c:2410
> >  kthread+0x365/0x450 kernel/kthread.c:255
> >  ret_from_fork+0x24/0x30 arch/x86/entry/entry_64.S:352
> >
> >
> > Not sure if it's the same or not. Is it addressed by something in flight?
> >
> > My config:
> > https://gist.githubusercontent.com/dvyukov/36c7be311fdec9cd51c649f7c3cb2ddb/raw/39c6f864fdd0ffc53f0822b14c354a73c1695fa1/gistfile1.txt
>
>
> I've tried this fix for pcpu_get_vm_areas:
> https://groups.google.com/d/msg/kasan-dev/t_F2X1MWKwk/h152Z3q2AgAJ
> and it helps. But this will break syzbot on linux-next soon.


Can this be related as well?
Crashes on accesses to shadow on the ion memory...

BUG: unable to handle page fault for address: fffff52006000000
#PF: supervisor read access in kernel mode
#PF: error_code(0x0000) - not-present page
PGD 7ffcd067 P4D 7ffcd067 PUD 2cd10067 PMD 0
Oops: 0000 [#1] PREEMPT SMP KASAN
CPU: 2 PID: 3472 Comm: ion_system_heap Not tainted 5.4.0-next-20191129+ #6
Hardware name: QEMU Standard PC (Q35 + ICH9, 2009), BIOS
rel-1.12.0-59-gc9ba5276e321-prebuilt.qemu.org 04/01/2014
RIP: 0010:memory_is_nonzero mm/kasan/generic.c:121 [inline]
RIP: 0010:memory_is_poisoned_n mm/kasan/generic.c:135 [inline]
RIP: 0010:memory_is_poisoned mm/kasan/generic.c:166 [inline]
RIP: 0010:check_memory_region_inline mm/kasan/generic.c:182 [inline]
RIP: 0010:check_memory_region+0x83/0x1d0 mm/kasan/generic.c:192
Code: 83 fb 10 0f 8e a9 00 00 00 45 89 c8 41 83 e0 07 75 66 4c 8d 43
07 48 85 db 4c 0f 49 c3 49 c1 f8 03 45 85 c0 0f 84 3f 01 00 00 <48> 83
38 00 75 1c 41 83 e8 01 4e 8d 44 c0 08 48 83 c0 08 49 39 c0
RSP: 0018:ffffc900011c7b10 EFLAGS: 00010206
RAX: fffff52006000000 RBX: 0000000000004000 RCX: ffffffff85988df8
RDX: 0000000000000001 RSI: 0000000000020000 RDI: ffffc90030000000
RBP: ffffc900011c7b28 R08: 0000000000000800 R09: fffff52006000000
R10: fffff52006003fff R11: ffffc9003001ffff R12: fffff52006004000
R13: 0000000000000000 R14: dffffc0000000000 R15: 0000000000000000
FS:  0000000000000000(0000) GS:ffff88802d400000(0000) knlGS:0000000000000000
CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
CR2: fffff52006000000 CR3: 00000000680fb004 CR4: 0000000000760ee0
DR0: 0000000000000000 DR1: 0000000000000000 DR2: 0000000000000000
DR3: 0000000000000000 DR6: 00000000fffe0ff0 DR7: 0000000000000400
PKRU: 55555554
Call Trace:
 memset+0x23/0x40 mm/kasan/common.c:107
 memset include/linux/string.h:410 [inline]
 ion_heap_clear_pages+0x48/0x70 drivers/staging/android/ion/ion_heap.c:106
 ion_heap_sglist_zero+0x1f9/0x260 drivers/staging/android/ion/ion_heap.c:123
 ion_heap_buffer_zero+0xf8/0x150 drivers/staging/android/ion/ion_heap.c:145
 ion_system_heap_free+0x227/0x290
drivers/staging/android/ion/ion_system_heap.c:163
 ion_buffer_destroy+0x15a/0x2d0 drivers/staging/android/ion/ion.c:93
 ion_heap_deferred_free+0x267/0x5e0 drivers/staging/android/ion/ion_heap.c:239
 kthread+0x365/0x450 kernel/kthread.c:255
 ret_from_fork+0x24/0x30 arch/x86/entry/entry_64.S:352
Modules linked in:
Dumping ftrace buffer:
   (ftrace buffer empty)
CR2: fffff52006000000
---[ end trace c101f19526ce3d42 ]---
RIP: 0010:memory_is_nonzero mm/kasan/generic.c:121 [inline]
RIP: 0010:memory_is_poisoned_n mm/kasan/generic.c:135 [inline]
RIP: 0010:memory_is_poisoned mm/kasan/generic.c:166 [inline]
RIP: 0010:check_memory_region_inline mm/kasan/generic.c:182 [inline]
RIP: 0010:check_memory_region+0x83/0x1d0 mm/kasan/generic.c:192
Code: 83 fb 10 0f 8e a9 00 00 00 45 89 c8 41 83 e0 07 75 66 4c 8d 43
07 48 85 db 4c 0f 49 c3 49 c1 f8 03 45 85 c0 0f 84 3f 01 00 00 <48> 83
38 00 75 1c 41 83 e8 01 4e 8d 44 c0 08 48 83 c0 08 49 39 c0
RSP: 0018:ffffc900011c7b10 EFLAGS: 00010206
RAX: fffff52006000000 RBX: 0000000000004000 RCX: ffffffff85988df8
RDX: 0000000000000001 RSI: 0000000000020000 RDI: ffffc90030000000
RBP: ffffc900011c7b28 R08: 0000000000000800 R09: fffff52006000000
R10: fffff52006003fff R11: ffffc9003001ffff R12: fffff52006004000
R13: 0000000000000000 R14: dffffc0000000000 R15: 0000000000000000
FS:  0000000000000000(0000) GS:ffff88802d400000(0000) knlGS:0000000000000000
CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
CR2: fffff52006000000 CR3: 00000000680fb004 CR4: 0000000000760ee0
DR0: 0000000000000000 DR1: 0000000000000000 DR2: 0000000000000000
DR3: 0000000000000000 DR6: 00000000fffe0ff0 DR7: 0000000000000400
PKRU: 55555554

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BYog%3DPHF1SsLuoehr2rcbmfvLUW%2Bdv7Vo%2B1RfdTOx7AUA%40mail.gmail.com.
