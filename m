Return-Path: <kasan-dev+bncBCMIZB7QWENRBYHTQPXQKGQEJQ3GWKQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53b.google.com (mail-pg1-x53b.google.com [IPv6:2607:f8b0:4864:20::53b])
	by mail.lfdr.de (Postfix) with ESMTPS id 1B69710D47A
	for <lists+kasan-dev@lfdr.de>; Fri, 29 Nov 2019 11:58:42 +0100 (CET)
Received: by mail-pg1-x53b.google.com with SMTP id i13sf16377215pgp.0
        for <lists+kasan-dev@lfdr.de>; Fri, 29 Nov 2019 02:58:42 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1575025120; cv=pass;
        d=google.com; s=arc-20160816;
        b=AFC1ArLQ3WnRDcZc7sO6aCRU3MrvyvfCohyKkXoAkbhHOCnRRRMI19Dxo7SlqbhU+k
         TQdFQknYj1z05a+BRNbyVbY6Cuk0sXzin5sGnr2g+8NHD7WubMw/QNUHirrqLJVkXEds
         BtssHaIIpiIKdQMKNiPMLDE+oq0h0EPLfFVuNfIdq6Pwom0affiUu3O8rJWvCZ09BHst
         6uXrRVlNjCfSjOGDc+6A3BWOvFTjIaTnWY8zCteAgNFhTICVwbWR6hdcoAH1S3kWANF8
         xUllMHIRAhGo9O+Kng9zG6Kp6CZ/M0sO+4Lepf/znENU73C7hZ9DGuINmS+h6yEBuj1Z
         umRQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=so/78zyhfycsJhDdlDCFbatJQ5MtmJNnmZuSe2DWbSg=;
        b=XzjA/u9j+6SUWlvGvYU2/WcUJDqGb9M5BqK42w+PG7EEWHi6t0AI8boSpBhkUg1zkJ
         lbAWDpAo07/7wto+cL3udxVyC63lq1tvGivRbhNLrvpvcdDj9w0XLxYb7URuX2sJU2Nu
         TX0Xxg+Sf4stJi8qGsLOVzjdXtaeylJS0bWzp9JweBBDwHaWKJyuxJv4PCuuWcm2xmsd
         66JrQyDQJvf+jMjPpl8zqLD9ZO8DSHowoor2Cj2rwxUevdJ12OnTzvgNb++IT9/IbSB4
         JMIvU2BkmeJoqyo1Sod43fLzkFVcRsO+17fPsSrANQwUNOQqRyBZ+h5cqvt2QBT1ggFJ
         kteg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=HbGOPNvm;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::842 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=so/78zyhfycsJhDdlDCFbatJQ5MtmJNnmZuSe2DWbSg=;
        b=CwZcF+kleAvRW2AMPDyuD3r/eepVRd9IT5DPo+aYZ6yZgJ13xrf6aXEwf3klydw0J0
         cvF33VEtRmocZ34ND3WRSuvT5yQQS6Boez8U90SWe14pUE4pGvO6XfQW9YRfIuzqgu6v
         B/aqk9aLlziY99gndTD6tAM0qGWh0BZudo7z6kfG/N+FcSN6BFvRaf61pfh8d3x8NwgP
         LsqUwl944yYKnxcTCpYaeFPWDvFRiszIQ/7zE4vDEzCiU7Gmcq1a/du24gPKj4YzDa9s
         0lBfQt6s+ItDbnUlfLSAobTGkn3rqANc7ygNJmLaoy43dCApSWWf99UxqQ8OgYsv70qY
         bIig==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=so/78zyhfycsJhDdlDCFbatJQ5MtmJNnmZuSe2DWbSg=;
        b=NO12lH3DraRuBMfZrMVL/cgGeAiMWkmgwKjNgBYLXGaE8Sqs68wYWsk4WsACAKM8ok
         a0SLGFnZ7xqM3Un1S0SUZxXUlkqcVF0Cd349MrfmQIFbMCOYYGxwLmUQC5+MuBuv16ul
         idyJMYjxu/+9H02CKcKDZo4gMkoRlRV+6rN0aacbBR/dGakw/31H9yt43TRdfO7Vr8e/
         J8DBwavdxMrN1MdF9/VRMYRD4KbuF4gZimMqqZhS6n8t0d6P/V0HXpWVqCaU97KwX/Ub
         7FX0WjWVszZszNP9Gc1fKaA3Iw1gkWjdkPKmY+UBrf+n2ounZG6A47wrDEKreC/ZUYjo
         75jg==
X-Gm-Message-State: APjAAAV0y5tmsgv6ibNRdY4yM9kYxl2uZq2aaqGgzhRPh/Etoetr2KMF
	TaEMNik3cXEHhbubGkKzXv8=
X-Google-Smtp-Source: APXvYqwi8ycgYiC5QsNBzjOrxKMF6x+sEX3pNnMws6kRKRtx0chQsxJnhbfGr2wOSLZ93i7TTtDELA==
X-Received: by 2002:a63:fc5d:: with SMTP id r29mr16324035pgk.282.1575025120258;
        Fri, 29 Nov 2019 02:58:40 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:2ec5:: with SMTP id u188ls7383245pfu.0.gmail; Fri, 29
 Nov 2019 02:58:39 -0800 (PST)
X-Received: by 2002:aa7:9465:: with SMTP id t5mr13518314pfq.18.1575025119874;
        Fri, 29 Nov 2019 02:58:39 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1575025119; cv=none;
        d=google.com; s=arc-20160816;
        b=t8yeUlBAaWu9XRwdLuWfDESRCb5v0DAzZ5xgpQ/aaEKliJ+t7sWzzEohT9K7u6HMAr
         n5pCr0rHc/SRocwG7pX0b/HBLrBhGEF2Hodx3ai7DhLYgNUP/hM8U3f5f98Kof/D8zO/
         DVglYSsGTnmGjwLa6gdW0UjloMDgljmCZeCODmrw44tVjpdwITOid1hcsVE+WWvxuLyi
         bpYD4KsVZr69w2r3uRThqX/2fZO99Ez6ZDImqRohCQwRbdpQc7kGuYaWA2w99l7tdFDm
         xF0/r2Wa/9vYIoBT93pZxBTwKXfUGnQczHxxf9lCMfI+TthziQ43pxTgjvb6gTLTFrEw
         HJyA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=mUIDLOf0hRQ3RLmdINFRjn4uoKtHaDbKGQ7fzoYrou4=;
        b=OKj3pers9LvshuenHejXDk7o6PP0VdZPFbmaQTdQ+mM2aphXVd/Y9jYFVcF4BLNnq8
         PDNIoHGER2GTjMQIeLhMhjrXhwLoHsC7R0eBjcDvKF/v536oAQ2ad5O3+a8q1CmuwFs6
         /pDJrJV4nZg37GB1aiBH01bNbd+GMSamgmNsXQH29DhihbbMLpPlGMqGHgRtVWIULaQQ
         iUpCMktd5MQK3zZI6jNt1QFLLyWmwkLbc0mZ+Cl412Koq+NpP+CPfDnCfPya5AFK45VR
         iCA4s3lxRiMPZNWD/LFXrwUtOgUjsLaG1zSI0Xoz1vosOyKaXQssWuEsXwGBhrwAsflx
         2iWg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=HbGOPNvm;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::842 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x842.google.com (mail-qt1-x842.google.com. [2607:f8b0:4864:20::842])
        by gmr-mx.google.com with ESMTPS id w4si451135pjr.1.2019.11.29.02.58.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 29 Nov 2019 02:58:39 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::842 as permitted sender) client-ip=2607:f8b0:4864:20::842;
Received: by mail-qt1-x842.google.com with SMTP id d5so2834722qto.0
        for <kasan-dev@googlegroups.com>; Fri, 29 Nov 2019 02:58:39 -0800 (PST)
X-Received: by 2002:ac8:610a:: with SMTP id a10mr41103027qtm.50.1575025118594;
 Fri, 29 Nov 2019 02:58:38 -0800 (PST)
MIME-Version: 1.0
References: <20191031093909.9228-1-dja@axtens.net> <20191031093909.9228-2-dja@axtens.net>
 <1573835765.5937.130.camel@lca.pw> <871ru5hnfh.fsf@dja-thinkpad.axtens.net>
 <952ec26a-9492-6f71-bab1-c1def887e528@virtuozzo.com> <CACT4Y+ZGO8b88fUyFe-WtV3Ubr11ChLY2mqk8YKWN9o0meNtXA@mail.gmail.com>
In-Reply-To: <CACT4Y+ZGO8b88fUyFe-WtV3Ubr11ChLY2mqk8YKWN9o0meNtXA@mail.gmail.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 29 Nov 2019 11:58:27 +0100
Message-ID: <CACT4Y+Z+VhfVpkfg-WFq_kFMY=DE+9b_DCi-mCSPK-udaf_Arg@mail.gmail.com>
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
 header.i=@google.com header.s=20161025 header.b=HbGOPNvm;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::842
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

On Fri, Nov 29, 2019 at 11:43 AM Dmitry Vyukov <dvyukov@google.com> wrote:
>
> On Tue, Nov 19, 2019 at 10:54 AM Andrey Ryabinin
> <aryabinin@virtuozzo.com> wrote:
> > On 11/18/19 6:29 AM, Daniel Axtens wrote:
> > > Qian Cai <cai@lca.pw> writes:
> > >
> > >> On Thu, 2019-10-31 at 20:39 +1100, Daniel Axtens wrote:
> > >>>     /*
> > >>>      * In this function, newly allocated vm_struct has VM_UNINITIALIZED
> > >>>      * flag. It means that vm_struct is not fully initialized.
> > >>> @@ -3377,6 +3411,9 @@ struct vm_struct **pcpu_get_vm_areas(const unsigned long *offsets,
> > >>>
> > >>>             setup_vmalloc_vm_locked(vms[area], vas[area], VM_ALLOC,
> > >>>                              pcpu_get_vm_areas);
> > >>> +
> > >>> +           /* assume success here */
> > >>> +           kasan_populate_vmalloc(sizes[area], vms[area]);
> > >>>     }
> > >>>     spin_unlock(&vmap_area_lock);
> > >>
> > >> Here it is all wrong. GFP_KERNEL with in_atomic().
> > >
> > > I think this fix will work, I will do a v12 with it included.
> >
> > You can send just the fix. Andrew will fold it into the original patch before sending it to Linus.
> >
> >
> >
> > > diff --git a/mm/vmalloc.c b/mm/vmalloc.c
> > > index a4b950a02d0b..bf030516258c 100644
> > > --- a/mm/vmalloc.c
> > > +++ b/mm/vmalloc.c
> > > @@ -3417,11 +3417,14 @@ struct vm_struct **pcpu_get_vm_areas(const unsigned long *offsets,
> > >
> > >                 setup_vmalloc_vm_locked(vms[area], vas[area], VM_ALLOC,
> > >                                  pcpu_get_vm_areas);
> > > +       }
> > > +       spin_unlock(&vmap_area_lock);
> > >
> > > +       /* populate the shadow space outside of the lock */
> > > +       for (area = 0; area < nr_vms; area++) {
> > >                 /* assume success here */
> > >                 kasan_populate_vmalloc(sizes[area], vms[area]);
> > >         }
> > > -       spin_unlock(&vmap_area_lock);
> > >
> > >         kfree(vas);
> > >         return vms;
>
> Hi,
>
> I am testing this support on next-20191129 and seeing the following warnings:
>
> BUG: sleeping function called from invalid context at mm/page_alloc.c:4681
> in_atomic(): 1, irqs_disabled(): 0, non_block: 0, pid: 44, name: kworker/1:1
> 4 locks held by kworker/1:1/44:
>  #0: ffff888067c26d28 ((wq_completion)events){+.+.}, at:
> __write_once_size include/linux/compiler.h:247 [inline]
>  #0: ffff888067c26d28 ((wq_completion)events){+.+.}, at:
> arch_atomic64_set arch/x86/include/asm/atomic64_64.h:34 [inline]
>  #0: ffff888067c26d28 ((wq_completion)events){+.+.}, at: atomic64_set
> include/asm-generic/atomic-instrumented.h:868 [inline]
>  #0: ffff888067c26d28 ((wq_completion)events){+.+.}, at:
> atomic_long_set include/asm-generic/atomic-long.h:40 [inline]
>  #0: ffff888067c26d28 ((wq_completion)events){+.+.}, at: set_work_data
> kernel/workqueue.c:615 [inline]
>  #0: ffff888067c26d28 ((wq_completion)events){+.+.}, at:
> set_work_pool_and_clear_pending kernel/workqueue.c:642 [inline]
>  #0: ffff888067c26d28 ((wq_completion)events){+.+.}, at:
> process_one_work+0x88b/0x1750 kernel/workqueue.c:2235
>  #1: ffffc900002afdf0 (pcpu_balance_work){+.+.}, at:
> process_one_work+0x8c0/0x1750 kernel/workqueue.c:2239
>  #2: ffffffff8943f080 (pcpu_alloc_mutex){+.+.}, at:
> pcpu_balance_workfn+0xcc/0x13e0 mm/percpu.c:1845
>  #3: ffffffff89450c78 (vmap_area_lock){+.+.}, at: spin_lock
> include/linux/spinlock.h:338 [inline]
>  #3: ffffffff89450c78 (vmap_area_lock){+.+.}, at:
> pcpu_get_vm_areas+0x1449/0x3df0 mm/vmalloc.c:3431
> Preemption disabled at:
> [<ffffffff81a84199>] spin_lock include/linux/spinlock.h:338 [inline]
> [<ffffffff81a84199>] pcpu_get_vm_areas+0x1449/0x3df0 mm/vmalloc.c:3431
> CPU: 1 PID: 44 Comm: kworker/1:1 Not tainted 5.4.0-next-20191129+ #5
> Hardware name: QEMU Standard PC (Q35 + ICH9, 2009), BIOS 1.12.0-1 04/01/2014
> Workqueue: events pcpu_balance_workfn
> Call Trace:
>  __dump_stack lib/dump_stack.c:77 [inline]
>  dump_stack+0x199/0x216 lib/dump_stack.c:118
>  ___might_sleep.cold.97+0x1f5/0x238 kernel/sched/core.c:6800
>  __might_sleep+0x95/0x190 kernel/sched/core.c:6753
>  prepare_alloc_pages mm/page_alloc.c:4681 [inline]
>  __alloc_pages_nodemask+0x3cd/0x890 mm/page_alloc.c:4730
>  alloc_pages_current+0x10c/0x210 mm/mempolicy.c:2211
>  alloc_pages include/linux/gfp.h:532 [inline]
>  __get_free_pages+0xc/0x40 mm/page_alloc.c:4786
>  kasan_populate_vmalloc_pte mm/kasan/common.c:762 [inline]
>  kasan_populate_vmalloc_pte+0x2f/0x1b0 mm/kasan/common.c:753
>  apply_to_pte_range mm/memory.c:2041 [inline]
>  apply_to_pmd_range mm/memory.c:2068 [inline]
>  apply_to_pud_range mm/memory.c:2088 [inline]
>  apply_to_p4d_range mm/memory.c:2108 [inline]
>  apply_to_page_range+0x5ca/0xa00 mm/memory.c:2133
>  kasan_populate_vmalloc+0x69/0xa0 mm/kasan/common.c:791
>  pcpu_get_vm_areas+0x1596/0x3df0 mm/vmalloc.c:3439
>  pcpu_create_chunk+0x240/0x7f0 mm/percpu-vm.c:340
>  pcpu_balance_workfn+0x1033/0x13e0 mm/percpu.c:1934
>  process_one_work+0x9b5/0x1750 kernel/workqueue.c:2264
>  worker_thread+0x8b/0xd20 kernel/workqueue.c:2410
>  kthread+0x365/0x450 kernel/kthread.c:255
>  ret_from_fork+0x24/0x30 arch/x86/entry/entry_64.S:352
>
>
> Not sure if it's the same or not. Is it addressed by something in flight?
>
> My config:
> https://gist.githubusercontent.com/dvyukov/36c7be311fdec9cd51c649f7c3cb2ddb/raw/39c6f864fdd0ffc53f0822b14c354a73c1695fa1/gistfile1.txt


I've tried this fix for pcpu_get_vm_areas:
https://groups.google.com/d/msg/kasan-dev/t_F2X1MWKwk/h152Z3q2AgAJ
and it helps. But this will break syzbot on linux-next soon.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BZ%2BVhfVpkfg-WFq_kFMY%3DDE%2B9b_DCi-mCSPK-udaf_Arg%40mail.gmail.com.
