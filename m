Return-Path: <kasan-dev+bncBCMIZB7QWENRBZHMQPXQKGQEZQ4DR7Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-xc38.google.com (mail-yw1-xc38.google.com [IPv6:2607:f8b0:4864:20::c38])
	by mail.lfdr.de (Postfix) with ESMTPS id 75CA010D454
	for <lists+kasan-dev@lfdr.de>; Fri, 29 Nov 2019 11:43:49 +0100 (CET)
Received: by mail-yw1-xc38.google.com with SMTP id 16sf5043080ywz.5
        for <lists+kasan-dev@lfdr.de>; Fri, 29 Nov 2019 02:43:49 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1575024228; cv=pass;
        d=google.com; s=arc-20160816;
        b=RypEs0CYI457BATDTn7/G2OdpO5UYkuvtl/oCttY3O5jtxtG1Vl6rtHBuaxM2lbPFg
         G3PR+zqca/lakqr1lvh2joFaqTkmzHC0STkNitRxEEU0X9QFwrmzXkSj7IraLYPlr7Z/
         aayYJZK5vfYmHVarrt3uja5uF/Zim3Jhspg/0GrUpUTKZv/u3ZzCO46Pydi+jMUWeEze
         UN58C47rqp7yCB0Rln5QDq27F3n5ipLlVlTR2W85O2X0iCbSQKYVqawg0sLUJd7KHiO9
         7zA6p8IQHNWq6os7OBhOyjsu7Zdx5xQXLeyaZuTZ1+nk7NSoCOhMxk5FJrPSPUxOvll3
         W1ZA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=TzVO6FIZsQLi+aJHA3bq85++ZdFTOwKOGvfMXNmkvzI=;
        b=oDsxJTdEVN5b48MFq6OXKiVGtjMQZT+GP6JEdtw0PvyGmavSb8VXKnbt6HlNdMNS4H
         XyUD1wuGI6w+Bjc8K1e8h1PyUBOXqxGaT71fMU0rTWbQD8TdsPw+KUXo+RhfX6UDPyZ/
         +ldEwhZ+3naYEaIyXJgmz2oh8XUpqUM7uGlMBFeqYFch3fvfPoeubY6TepD+JznAwgGM
         yWlyV5BLJcgqG8wC4ey0yywFXCNu7g85mUt2tddlVEfR9DC4W2bqMstvcqutVBpyAcjE
         MeaX0V+rHO/sR4ZAUVZpn0NLJfi6E6s2JC1/BUYekJcIhaPzhePV/sM0uRCNyi9S9GMX
         Ykow==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=nBYMKIdo;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::744 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=TzVO6FIZsQLi+aJHA3bq85++ZdFTOwKOGvfMXNmkvzI=;
        b=kswE9Tt3ji+JUZOJVmVEwh/s6RbRw7cFMNx4HFlUkNKAYrTETiuCV/XvskaM/fdOHp
         HloTQNLcxdDPbF2G12OkNoyssjDBESy+UFCX0i+3ojO9v2PMXlDCTPM8lSpNY3d1tR6F
         NjmKiOVJMYXlpnLn8zvcAkGyu7NQUJby1HXyqr+MFJFJSTl4CKUDAlU2c8gJ7eUPC7o3
         tAVIpjTcZsMTDZsZI09tS0QmKrclZ7CjpbNsHp6eqB667Oz1ydCG2DbO4Z213oa6JhvP
         IWGuqNucUw6Va+v0IQlqLo3FDI6SG+XxrEJrsCCnFX7/ZTuCUAucI4/VIfX0gY4yT/fF
         /hXw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=TzVO6FIZsQLi+aJHA3bq85++ZdFTOwKOGvfMXNmkvzI=;
        b=nrlVnvckelHbQixAEYaSPAQBPeQDjFOMJGXNiJ+XUm+co3FcutpU9fzY1+z6FCvTIC
         TxJWSNB24BFMmNYflUD3sW122eG5jDb+czGAbsQWLIRcb+cMXkawuESQ4r2yTbexkAE4
         Zbuk6cYLpJ4fVHL8oyk0lOAcjb4l1KOV+iX+FhzaT4Ys1KVOz28dINxad1NvMhSWNmbZ
         hCBJ76Z4zXZAYBCFcQjwXma7bIdBbrOvMvnzDHn0+c0ob92KYCHgOTqjrG3IPys3cdG1
         VYRcRmn+IJ4uzguCKmowhw3ArPe1iakzUL7KN46U3KjunqEfYrQj4LP5x2RLfqNlX0TB
         dUiA==
X-Gm-Message-State: APjAAAVAKrannDGELsP/OcOgWiqqU9oyEs2iFf4RTZ+2negJvhUA1R29
	NahWNKi+ja9sJ5xuPXcG4uM=
X-Google-Smtp-Source: APXvYqwch71pqCHLAZ9Gk0fKsHY27tYt4lVHDQf5pxpUc409d7rowSQ9JmYeqShxzUqAisSp57bpXw==
X-Received: by 2002:a81:6707:: with SMTP id b7mr8811510ywc.36.1575024228222;
        Fri, 29 Nov 2019 02:43:48 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:1445:: with SMTP id 66ls4968760ybu.5.gmail; Fri, 29 Nov
 2019 02:43:47 -0800 (PST)
X-Received: by 2002:a25:b94:: with SMTP id 142mr8516434ybl.193.1575024227790;
        Fri, 29 Nov 2019 02:43:47 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1575024227; cv=none;
        d=google.com; s=arc-20160816;
        b=LoLpa43aKTjsbIxYcNUtXoGVFyRPUZBY0YiIQRBzt9aqP3pHBmSCIIouTpmGDejBH5
         VUJCKJ0Cb7p/IRUm6+U/77lc7KOTV2OVEapPofJ9KPv36yoI/ym42psDimuniFx48pZD
         ZC9vMUm0Cxqlr/p9a4VX4nDki3oiBxOWUaJahgDg1VsYsvcIWHrTsPsKotNrtiEQOkHZ
         UUOW8thbk9CyDuKU09DFOd9cSEUtHP7g26JAhKArpLLErl2HPsr7zWXdk+UU6mzlMMVn
         DdBOkhVHWGm7c85ITDo3d1wv5KvoP4VkifXXqJ/GWpJKSgoWRsRb5qZrH1WYZDK89H3y
         CyNg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=WNKcPwP14dCsuwOlqDsykLyVDhKlBHISB9+4LszAs1E=;
        b=VbSIhV1Xt4c2cwtmFzXT3bxKL7JLs3socatX90wn5Vi8MQ5jXTrCnQ6poGuUEI/OGJ
         sK23jfmq7ZzPm6WV53+/eWTBSQsr1/LxT68/PXuaJe8kSba9n8O2qqoUxAJJVSRnh4v6
         m4WfnpWFdjmsNj+rEuse3fzF1wUZGWbbYNE5DQjZCUZDyngRNnB9qJy8DDmkjDBBeECB
         u6o6LG5tdVTXMFFs0XoDsMVM3V0AUQ+5sP+J2HSeZkzDCow9vgJoOeCUFkrqDMxtnTHv
         u4U5O6Wj9n/UvpIYQPbybwSDZJg0axBVvnAv2yqaVD05e2SMGb1kFlvgh2Iu/TtpzSsB
         esbw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=nBYMKIdo;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::744 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x744.google.com (mail-qk1-x744.google.com. [2607:f8b0:4864:20::744])
        by gmr-mx.google.com with ESMTPS id u17si236532ybu.1.2019.11.29.02.43.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 29 Nov 2019 02:43:47 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::744 as permitted sender) client-ip=2607:f8b0:4864:20::744;
Received: by mail-qk1-x744.google.com with SMTP id d202so16799138qkb.1
        for <kasan-dev@googlegroups.com>; Fri, 29 Nov 2019 02:43:47 -0800 (PST)
X-Received: by 2002:a37:e312:: with SMTP id y18mr11683779qki.250.1575024226915;
 Fri, 29 Nov 2019 02:43:46 -0800 (PST)
MIME-Version: 1.0
References: <20191031093909.9228-1-dja@axtens.net> <20191031093909.9228-2-dja@axtens.net>
 <1573835765.5937.130.camel@lca.pw> <871ru5hnfh.fsf@dja-thinkpad.axtens.net> <952ec26a-9492-6f71-bab1-c1def887e528@virtuozzo.com>
In-Reply-To: <952ec26a-9492-6f71-bab1-c1def887e528@virtuozzo.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 29 Nov 2019 11:43:35 +0100
Message-ID: <CACT4Y+ZGO8b88fUyFe-WtV3Ubr11ChLY2mqk8YKWN9o0meNtXA@mail.gmail.com>
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
 header.i=@google.com header.s=20161025 header.b=nBYMKIdo;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::744
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

On Tue, Nov 19, 2019 at 10:54 AM Andrey Ryabinin
<aryabinin@virtuozzo.com> wrote:
> On 11/18/19 6:29 AM, Daniel Axtens wrote:
> > Qian Cai <cai@lca.pw> writes:
> >
> >> On Thu, 2019-10-31 at 20:39 +1100, Daniel Axtens wrote:
> >>>     /*
> >>>      * In this function, newly allocated vm_struct has VM_UNINITIALIZED
> >>>      * flag. It means that vm_struct is not fully initialized.
> >>> @@ -3377,6 +3411,9 @@ struct vm_struct **pcpu_get_vm_areas(const unsigned long *offsets,
> >>>
> >>>             setup_vmalloc_vm_locked(vms[area], vas[area], VM_ALLOC,
> >>>                              pcpu_get_vm_areas);
> >>> +
> >>> +           /* assume success here */
> >>> +           kasan_populate_vmalloc(sizes[area], vms[area]);
> >>>     }
> >>>     spin_unlock(&vmap_area_lock);
> >>
> >> Here it is all wrong. GFP_KERNEL with in_atomic().
> >
> > I think this fix will work, I will do a v12 with it included.
>
> You can send just the fix. Andrew will fold it into the original patch before sending it to Linus.
>
>
>
> > diff --git a/mm/vmalloc.c b/mm/vmalloc.c
> > index a4b950a02d0b..bf030516258c 100644
> > --- a/mm/vmalloc.c
> > +++ b/mm/vmalloc.c
> > @@ -3417,11 +3417,14 @@ struct vm_struct **pcpu_get_vm_areas(const unsigned long *offsets,
> >
> >                 setup_vmalloc_vm_locked(vms[area], vas[area], VM_ALLOC,
> >                                  pcpu_get_vm_areas);
> > +       }
> > +       spin_unlock(&vmap_area_lock);
> >
> > +       /* populate the shadow space outside of the lock */
> > +       for (area = 0; area < nr_vms; area++) {
> >                 /* assume success here */
> >                 kasan_populate_vmalloc(sizes[area], vms[area]);
> >         }
> > -       spin_unlock(&vmap_area_lock);
> >
> >         kfree(vas);
> >         return vms;

Hi,

I am testing this support on next-20191129 and seeing the following warnings:

BUG: sleeping function called from invalid context at mm/page_alloc.c:4681
in_atomic(): 1, irqs_disabled(): 0, non_block: 0, pid: 44, name: kworker/1:1
4 locks held by kworker/1:1/44:
 #0: ffff888067c26d28 ((wq_completion)events){+.+.}, at:
__write_once_size include/linux/compiler.h:247 [inline]
 #0: ffff888067c26d28 ((wq_completion)events){+.+.}, at:
arch_atomic64_set arch/x86/include/asm/atomic64_64.h:34 [inline]
 #0: ffff888067c26d28 ((wq_completion)events){+.+.}, at: atomic64_set
include/asm-generic/atomic-instrumented.h:868 [inline]
 #0: ffff888067c26d28 ((wq_completion)events){+.+.}, at:
atomic_long_set include/asm-generic/atomic-long.h:40 [inline]
 #0: ffff888067c26d28 ((wq_completion)events){+.+.}, at: set_work_data
kernel/workqueue.c:615 [inline]
 #0: ffff888067c26d28 ((wq_completion)events){+.+.}, at:
set_work_pool_and_clear_pending kernel/workqueue.c:642 [inline]
 #0: ffff888067c26d28 ((wq_completion)events){+.+.}, at:
process_one_work+0x88b/0x1750 kernel/workqueue.c:2235
 #1: ffffc900002afdf0 (pcpu_balance_work){+.+.}, at:
process_one_work+0x8c0/0x1750 kernel/workqueue.c:2239
 #2: ffffffff8943f080 (pcpu_alloc_mutex){+.+.}, at:
pcpu_balance_workfn+0xcc/0x13e0 mm/percpu.c:1845
 #3: ffffffff89450c78 (vmap_area_lock){+.+.}, at: spin_lock
include/linux/spinlock.h:338 [inline]
 #3: ffffffff89450c78 (vmap_area_lock){+.+.}, at:
pcpu_get_vm_areas+0x1449/0x3df0 mm/vmalloc.c:3431
Preemption disabled at:
[<ffffffff81a84199>] spin_lock include/linux/spinlock.h:338 [inline]
[<ffffffff81a84199>] pcpu_get_vm_areas+0x1449/0x3df0 mm/vmalloc.c:3431
CPU: 1 PID: 44 Comm: kworker/1:1 Not tainted 5.4.0-next-20191129+ #5
Hardware name: QEMU Standard PC (Q35 + ICH9, 2009), BIOS 1.12.0-1 04/01/2014
Workqueue: events pcpu_balance_workfn
Call Trace:
 __dump_stack lib/dump_stack.c:77 [inline]
 dump_stack+0x199/0x216 lib/dump_stack.c:118
 ___might_sleep.cold.97+0x1f5/0x238 kernel/sched/core.c:6800
 __might_sleep+0x95/0x190 kernel/sched/core.c:6753
 prepare_alloc_pages mm/page_alloc.c:4681 [inline]
 __alloc_pages_nodemask+0x3cd/0x890 mm/page_alloc.c:4730
 alloc_pages_current+0x10c/0x210 mm/mempolicy.c:2211
 alloc_pages include/linux/gfp.h:532 [inline]
 __get_free_pages+0xc/0x40 mm/page_alloc.c:4786
 kasan_populate_vmalloc_pte mm/kasan/common.c:762 [inline]
 kasan_populate_vmalloc_pte+0x2f/0x1b0 mm/kasan/common.c:753
 apply_to_pte_range mm/memory.c:2041 [inline]
 apply_to_pmd_range mm/memory.c:2068 [inline]
 apply_to_pud_range mm/memory.c:2088 [inline]
 apply_to_p4d_range mm/memory.c:2108 [inline]
 apply_to_page_range+0x5ca/0xa00 mm/memory.c:2133
 kasan_populate_vmalloc+0x69/0xa0 mm/kasan/common.c:791
 pcpu_get_vm_areas+0x1596/0x3df0 mm/vmalloc.c:3439
 pcpu_create_chunk+0x240/0x7f0 mm/percpu-vm.c:340
 pcpu_balance_workfn+0x1033/0x13e0 mm/percpu.c:1934
 process_one_work+0x9b5/0x1750 kernel/workqueue.c:2264
 worker_thread+0x8b/0xd20 kernel/workqueue.c:2410
 kthread+0x365/0x450 kernel/kthread.c:255
 ret_from_fork+0x24/0x30 arch/x86/entry/entry_64.S:352


Not sure if it's the same or not. Is it addressed by something in flight?

My config:
https://gist.githubusercontent.com/dvyukov/36c7be311fdec9cd51c649f7c3cb2ddb/raw/39c6f864fdd0ffc53f0822b14c354a73c1695fa1/gistfile1.txt

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BZGO8b88fUyFe-WtV3Ubr11ChLY2mqk8YKWN9o0meNtXA%40mail.gmail.com.
