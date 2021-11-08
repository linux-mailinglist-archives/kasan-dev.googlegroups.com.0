Return-Path: <kasan-dev+bncBCMIZB7QWENRBNM2USGAMGQEJZXEI3A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13a.google.com (mail-il1-x13a.google.com [IPv6:2607:f8b0:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id DEC07447F13
	for <lists+kasan-dev@lfdr.de>; Mon,  8 Nov 2021 12:42:46 +0100 (CET)
Received: by mail-il1-x13a.google.com with SMTP id w6-20020a056e021a6600b0027553e5c4e9sf8097848ilv.16
        for <lists+kasan-dev@lfdr.de>; Mon, 08 Nov 2021 03:42:46 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1636371765; cv=pass;
        d=google.com; s=arc-20160816;
        b=FhgHD6yMbo+YYY8zhOV2f5zavXcJvP9DrzOs99bUq0SWnNVjFswJZ5yUfX0SIAORqM
         EPTpyx2WD6604f2Vqe7+beQS3rakE2lvRHN3JCy7NLQ8HAmNtEkrE1UtMFTEOdJujql/
         lF8jun/imxPM85Ft+q7nMrWicQuCem6rGuMA6rbQMzk5M/9JEDoO7z78S7x/EeP2oook
         MxLoPEpiHPnGxUbi9yIpSxT3Ve4+RLDUfLYmOC5ghz86lLeRTNHNnhmzhGhYbkriRZa+
         mEW/rqj/9tovLGYQ/NiZOpibQ4+JzIvA2QdbT0HMiy5RgEOXfiN/nfBvVJulJtFjn5QM
         SBZg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=DHCAtJRZYLxe1mZTRt4z3/gav3gqALAYe4Q0UGEdGL8=;
        b=VkIbeyRvso7i7MhEZN/08K9uuc47I50/Ye2hX1jLv6ca1sv1gy1FfCKjoUC1viia61
         Z629pAS6G03f12O4c0SMP1OOkremp7rmUDtyUQpYDxOUdcyOjI57Hb2zotdcfNVcVC39
         fa0Miq2MePqLRx02CYSYA/8EAnlJPF/FRxk9zBNpCMBx1K7dbBnFIwhBhLN7nbufZi/n
         fFOCw7Oa/2QnCMe2Sb/vFDlNRr61URZED9eb7QnVuybv56x1lV7dR7hxB9aPUuzCX3GP
         SpxFq+3mVc5d6vpxdli+TzCOJlVblNsx7TNT9CvB0UzhNlnrEi/Ik4jK2/CxOFDWKcGB
         nf8Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=YeQ9YEBX;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::c2b as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=DHCAtJRZYLxe1mZTRt4z3/gav3gqALAYe4Q0UGEdGL8=;
        b=S3lxxEc+5rJEgK/mA5wZWLeH7jI58RoTMc1t38Ds/20dl92QXhxAZG7ZOl8UyKMR/i
         cP5u+j2T1A6Lcfv/vkiytBwzDuTy8UG0PzCK7o6U13r1prYFdmytozDXZxeiwslJZlNJ
         CgP/caHEtVgA7th6ScQn7vl59kptrM7wi20w0xaD4Fo+9mP6JFnHyOh+6zyArIW/kyK6
         IwkDqgEMowOYEdwooxDd39/dz8kR+VBM4DqGq5f2XfoW7j8rkCMK2GaeCK6T6V/bv0ao
         aeJHbcbs+tG7sGM7FYyz7sIRVB/1QkhgxOFTqO3Y07sNKKh3AFjNSLU3AqUmmuiy7P8U
         d41w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=DHCAtJRZYLxe1mZTRt4z3/gav3gqALAYe4Q0UGEdGL8=;
        b=SczS730GHo3XYrKWzad+zgL16wTdA85dCJeRDYDdW02lzFH8IOKZxicFFeEpjG1QCy
         HpFotPRJlITgyQW+BQcx0keuq3t+upgdmRsl7WdmxyaPycfJAR/sc4ra85UMyPAuGae3
         MUA9pDz3dSRa9RZ3HEMhhowfvG+i0hasLKwRRx2NBmTjHqryGnaAIe6aRN+tJ2tBLisr
         b7yQQDg+iuoHZvNIonfq0mcKoa2F2y58W1gUSmD/UmQzfcGcxk0H1plZHvdssvuQusLO
         fiNZy+cuI77ogpn24ltbceVhszX7u4W/aNlxlPNzBdd3FtFGVhrDIjlYt5hNGPta5T5k
         1q6g==
X-Gm-Message-State: AOAM533UYwAPTaNPSgCYBxK6MWiHq6uL0vsBhTfphGfhcjnJAGd0i1Zj
	V4Xw6IAbuW/GH42BFnlSOUc=
X-Google-Smtp-Source: ABdhPJxrBryWEgb9/2nvqMgRJNKeJXFs/uVBRgcjhrERaG+zqC5W2s6e/rQRhiDfyTF5jlBGG1RxhQ==
X-Received: by 2002:a05:6602:134a:: with SMTP id i10mr12701364iov.7.1636371765674;
        Mon, 08 Nov 2021 03:42:45 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:1846:: with SMTP id b6ls2974056ilv.7.gmail; Mon, 08
 Nov 2021 03:42:45 -0800 (PST)
X-Received: by 2002:a92:d752:: with SMTP id e18mr53561747ilq.31.1636371765293;
        Mon, 08 Nov 2021 03:42:45 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1636371765; cv=none;
        d=google.com; s=arc-20160816;
        b=MvnDXemEYeQ/3sio9wBMhTdAMMU8uxKLrfp56hNQ6R+vG8gj24p9jOYNI21RydkLry
         XP29jDhWg8oiiGQ8n8jked/oRJGzcrmqeFQb62NfoziYL+bCzoYubNuVSxysP2/cRvZX
         iNFV5btyaw+WEiNyP6kvu8x3Avfrg+qUX74p7/HZBCiS4qvjsYCoeCyP0r33PKTt0ivY
         b84O+4h1rswavZAP57jYX5hLLwQTzA2I7gIkZ6ZWLR0E0uBcWvrzEq+D3Eqo5j13TjHm
         ehRSR7aod6S6fiJ/oXZTNTBHwctj1cbQQ0ixC5p2/qeVfoXXRaHJxNfA3GgI1hyLSVEp
         INQQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=t0CLCOJqTl97SWBVXsn+FLxAY1FZRpeC0I3mqMnmY7M=;
        b=a0S0VIlYPStQejtnvoIFGCsw54OBF0a+2DtTP1xZ9OVsXVh31hNLtyekGsNRM41liN
         NZ64E4uzxALFm9SSJta1KDC6Kf4BVFBbSFRJpRo6K3qdpFLr1Ad06iLnR0val/VeLo5Z
         RVfnm50+8RcaSesgPTILH+sDEU57gH2ysiFkqsADO7yd+Q14owJbSJoUWmEslKbwQo+Z
         08zUnOIqbaOjB3huHixmdHAGAI5tmqWa1H5YpTDUhUHKFk/8sFvK5zwR8iJHQ0ddh/tI
         snvI0S9S1MpzceOyFGDRf3NeBW9czQFDUNpBYj6VjF1GhiTbR6h6PZpx+azDvwVzh3tg
         3EMA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=YeQ9YEBX;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::c2b as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oo1-xc2b.google.com (mail-oo1-xc2b.google.com. [2607:f8b0:4864:20::c2b])
        by gmr-mx.google.com with ESMTPS id o6si577112ilu.4.2021.11.08.03.42.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 08 Nov 2021 03:42:45 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::c2b as permitted sender) client-ip=2607:f8b0:4864:20::c2b;
Received: by mail-oo1-xc2b.google.com with SMTP id a17-20020a4a6851000000b002b59bfbf669so5750395oof.9
        for <kasan-dev@googlegroups.com>; Mon, 08 Nov 2021 03:42:45 -0800 (PST)
X-Received: by 2002:a4a:b385:: with SMTP id p5mr21194703ooo.21.1636371764628;
 Mon, 08 Nov 2021 03:42:44 -0800 (PST)
MIME-Version: 1.0
References: <20211101103158.3725704-1-jun.miao@windriver.com>
 <96f9d669-b9da-f387-199e-e6bf36081fbd@windriver.com> <CA+KHdyU98uHkf1VKbvFs0wcXz7SaizENRXn4BEpKJhe+KmXZuw@mail.gmail.com>
 <baa768a3-aacf-ba3a-8d20-0abc78eca2f7@windriver.com> <CA+KHdyUEtBQjh61Xx+4a-AS0+z18CW1W5GzaRVsihuy=PUpUxA@mail.gmail.com>
 <20211103181315.GT880162@paulmck-ThinkPad-P17-Gen-1> <20211103212117.GA631708@paulmck-ThinkPad-P17-Gen-1>
 <309b8284-1c31-7cc4-eb40-ba6d8d136c09@windriver.com> <20211104012843.GD641268@paulmck-ThinkPad-P17-Gen-1>
In-Reply-To: <20211104012843.GD641268@paulmck-ThinkPad-P17-Gen-1>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 8 Nov 2021 12:42:33 +0100
Message-ID: <CACT4Y+bih9gX2+XvRh3q7XYe8rbgCDF5=5eMV8cxBimvPLQtug@mail.gmail.com>
Subject: Re: [PATCH] rcu: avoid alloc_pages() when recording stack
To: paulmck@kernel.org, kasan-dev <kasan-dev@googlegroups.com>
Cc: Jun Miao <jun.miao@windriver.com>, Uladzislau Rezki <urezki@gmail.com>, 
	Josh Triplett <josh@joshtriplett.org>, Steven Rostedt <rostedt@goodmis.org>, 
	Mathieu Desnoyers <mathieu.desnoyers@efficios.com>, Lai Jiangshan <jiangshanlai@gmail.com>, 
	Joel Fernandes <joel@joelfernandes.org>, qiang.zhang1211@gmail.com, 
	RCU <rcu@vger.kernel.org>, LKML <linux-kernel@vger.kernel.org>, miaojun0823@163.com, 
	ryabinin.a.a@gmail.com, Alexander Potapenko <glider@google.com>, jianwei.hu@windriver.com, 
	melver@google.com
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=YeQ9YEBX;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::c2b
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

On Thu, 4 Nov 2021 at 02:28, Paul E. McKenney <paulmck@kernel.org> wrote:
>
> On Thu, Nov 04, 2021 at 09:09:24AM +0800, Jun Miao wrote:
> >
> > On 11/4/21 5:21 AM, Paul E. McKenney wrote:
> > > [Please note: This e-mail is from an EXTERNAL e-mail address]
> > >
> > > On Wed, Nov 03, 2021 at 11:13:15AM -0700, Paul E. McKenney wrote:
> > > > On Wed, Nov 03, 2021 at 02:55:48PM +0100, Uladzislau Rezki wrote:
> > > > > On Wed, Nov 3, 2021 at 7:51 AM Jun Miao <jun.miao@windriver.com> =
wrote:
> > > > > >
> > > > > > On 11/2/21 10:53 PM, Uladzislau Rezki wrote:
> > > > > > > [Please note: This e-mail is from an EXTERNAL e-mail address]
> > > > > > >
> > > > > > > > Add KASAN maintainers
> > > > > > > >
> > > > > > > > On 11/1/21 6:31 PM, Jun Miao wrote:
> > > > > > > > > The default kasan_record_aux_stack() calls stack_depot_sa=
ve() with GFP_NOWAIT,
> > > > > > > > > which in turn can then call alloc_pages(GFP_NOWAIT, ...).=
  In general, however,
> > > > > > > > > it is not even possible to use either GFP_ATOMIC nor GFP_=
NOWAIT in certain
> > > > > > > > > non-preemptive contexts/RT kernel including raw_spin_lock=
s (see gfp.h and ab00db216c9c7).
> > > > > > > > >
> > > > > > > > > Fix it by instructing stackdepot to not expand stack stor=
age via alloc_pages()
> > > > > > > > > in case it runs out by using kasan_record_aux_stack_noall=
oc().
> > > > > > > > >
> > > > > > > > > Jianwei Hu reported:
> > > > > > > > >     BUG: sleeping function called from invalid context at=
 kernel/locking/rtmutex.c:969
> > > > > > > > >     in_atomic(): 0, irqs_disabled(): 1, non_block: 0, pid=
: 15319, name: python3
> > > > > > > > >     INFO: lockdep is turned off.
> > > > > > > > >     irq event stamp: 0
> > > > > > > > >     hardirqs last  enabled at (0): [<0000000000000000>] 0=
x0
> > > > > > > > >     hardirqs last disabled at (0): [<ffffffff856c8b13>] c=
opy_process+0xaf3/0x2590
> > > > > > > > >     softirqs last  enabled at (0): [<ffffffff856c8b13>] c=
opy_process+0xaf3/0x2590
> > > > > > > > >     softirqs last disabled at (0): [<0000000000000000>] 0=
x0
> > > > > > > > >     CPU: 6 PID: 15319 Comm: python3 Tainted: G        W  =
O 5.15-rc7-preempt-rt #1
> > > > > > > > >     Hardware name: Supermicro SYS-E300-9A-8C/A2SDi-8C-HLN=
4F, BIOS 1.1b 12/17/2018
> > > > > > > > >     Call Trace:
> > > > > > > > >      show_stack+0x52/0x58
> > > > > > > > >      dump_stack+0xa1/0xd6
> > > > > > > > >      ___might_sleep.cold+0x11c/0x12d
> > > > > > > > >      rt_spin_lock+0x3f/0xc0
> > > > > > > > >      rmqueue+0x100/0x1460
> > > > > > > > >      rmqueue+0x100/0x1460
> > > > > > > > >      mark_usage+0x1a0/0x1a0
> > > > > > > > >      ftrace_graph_ret_addr+0x2a/0xb0
> > > > > > > > >      rmqueue_pcplist.constprop.0+0x6a0/0x6a0
> > > > > > > > >       __kasan_check_read+0x11/0x20
> > > > > > > > >       __zone_watermark_ok+0x114/0x270
> > > > > > > > >       get_page_from_freelist+0x148/0x630
> > > > > > > > >       is_module_text_address+0x32/0xa0
> > > > > > > > >       __alloc_pages_nodemask+0x2f6/0x790
> > > > > > > > >       __alloc_pages_slowpath.constprop.0+0x12d0/0x12d0
> > > > > > > > >       create_prof_cpu_mask+0x30/0x30
> > > > > > > > >       alloc_pages_current+0xb1/0x150
> > > > > > > > >       stack_depot_save+0x39f/0x490
> > > > > > > > >       kasan_save_stack+0x42/0x50
> > > > > > > > >       kasan_save_stack+0x23/0x50
> > > > > > > > >       kasan_record_aux_stack+0xa9/0xc0
> > > > > > > > >       __call_rcu+0xff/0x9c0
> > > > > > > > >       call_rcu+0xe/0x10
> > > > > > > > >       put_object+0x53/0x70
> > > > > > > > >       __delete_object+0x7b/0x90
> > > > > > > > >       kmemleak_free+0x46/0x70
> > > > > > > > >       slab_free_freelist_hook+0xb4/0x160
> > > > > > > > >       kfree+0xe5/0x420
> > > > > > > > >       kfree_const+0x17/0x30
> > > > > > > > >       kobject_cleanup+0xaa/0x230
> > > > > > > > >       kobject_put+0x76/0x90
> > > > > > > > >       netdev_queue_update_kobjects+0x17d/0x1f0
> > > > > > > > >       ... ...
> > > > > > > > >       ksys_write+0xd9/0x180
> > > > > > > > >       __x64_sys_write+0x42/0x50
> > > > > > > > >       do_syscall_64+0x38/0x50
> > > > > > > > >       entry_SYSCALL_64_after_hwframe+0x44/0xa9
> > > > > > > > >
> > > > > > > > > Fixes: 84109ab58590 ("rcu: Record kvfree_call_rcu() call =
stack for KASAN")
> > > > > > > > > Fixes: 26e760c9a7c8 ("rcu: kasan: record and print call_r=
cu() call stack")
> > > > > > > > > Reported-by: Jianwei Hu <jianwei.hu@windriver.com>
> > > > > > > > > Signed-off-by: Jun Miao <jun.miao@windriver.com>
> > > > > > > > > ---
> > > > > > > > >     kernel/rcu/tree.c | 4 ++--
> > > > > > > > >     1 file changed, 2 insertions(+), 2 deletions(-)
> > > > > > > > >
> > > > > > > > > diff --git a/kernel/rcu/tree.c b/kernel/rcu/tree.c
> > > > > > > > > index 8270e58cd0f3..2c1034580f15 100644
> > > > > > > > > --- a/kernel/rcu/tree.c
> > > > > > > > > +++ b/kernel/rcu/tree.c
> > > > > > > > > @@ -3026,7 +3026,7 @@ __call_rcu(struct rcu_head *head, r=
cu_callback_t func)
> > > > > > > > >         head->func =3D func;
> > > > > > > > >         head->next =3D NULL;
> > > > > > > > >         local_irq_save(flags);
> > > > > > > > > -     kasan_record_aux_stack(head);
> > > > > > > > > +     kasan_record_aux_stack_noalloc(head);
> > > > > > > > >         rdp =3D this_cpu_ptr(&rcu_data);
> > > > > > > > >
> > > > > > > > >         /* Add the callback to our list. */
> > > > > > > > > @@ -3591,7 +3591,7 @@ void kvfree_call_rcu(struct rcu_hea=
d *head, rcu_callback_t func)
> > > > > > > > >                 return;
> > > > > > > > >         }
> > > > > > > > >
> > > > > > > > > -     kasan_record_aux_stack(ptr);
> > > > > > > > > +     kasan_record_aux_stack_noalloc(ptr);
> > > > > > > > >         success =3D add_ptr_to_bulk_krc_lock(&krcp, &flag=
s, ptr, !head);
> > > > > > > > >         if (!success) {
> > > > > > > > >                 run_page_cache_worker(krcp);
> > > > > > > Yep an allocation is tricky here. This change looks correct t=
o me at
> > > > > > > least from the point that it does not allocate.
> > > > > > >
> > > > > > > --
> > > > > > > Uladzislau Rezki
> > > > > > Thanks your approval. Could you like to give me a review?
> > > > > >
> > > > > Reviewed-by: Uladzislau Rezki (Sony) <urezki@gmail.com>
> > > > I have queued it for review and testing, thank you both!  I do have
> > > > some remaining concerns about this code being starved for memory.  =
I am
> > > > wondering if the code needs to check the interrupt state.  And perh=
aps
> > > > also whether locks are held.  I of course will refrain from sending
> > > > this to mainline until these concerns are resolved.
> > > >
> > > > Marco, Dmitry, thoughts?
> > > Well, the compiler does have an opinion:
> > >
> > > kernel/rcu/tree.c: In function =E2=80=98__call_rcu=E2=80=99:
> > > kernel/rcu/tree.c:3029:2: error: implicit declaration of function =E2=
=80=98kasan_record_aux_stack_noalloc=E2=80=99; did you mean =E2=80=98kasan_=
record_aux_stack=E2=80=99? [-Werror=3Dimplicit-function-declaration]
> > >   3029 |  kasan_record_aux_stack_noalloc(head);
> > >        |  ^~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
> > >        |  kasan_record_aux_stack
> > >
> > > I get the same message after merging in current mainline.
> > >
> > > I have therefore dropped this patch for the time being.
> > >
> > >                                                          Thanx, Paul
> > Hi Paul E,
> > The kasan_record_aux_stack_noalloc() is just introduce to linux-next no=
w,
> > and marking "Notice: this object is not reachable from any branch." in
> > commit.
> > https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/com=
mit/include/linux/kasan.h?h=3Dnext-20211029&id=3D2f64acf6b653d01fbdc92a693f=
12bbf71a205926
>
> That would explain it!  Feel free to resend once the functionality is
> more generally available.

+kasan-dev@googlegroups.com mailing list

I found the full commit with kasan_record_aux_stack_noalloc() implementatio=
n:
https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/=
?h=3Dnext-20211029&id=3D2f64acf6b653d01fbdc92a693f12bbf71a205926

but it calls kasan_save_stack() with second bool argument, and
kasan_save_stack() accepts only 1 argument:
https://elixir.bootlin.com/linux/latest/source/mm/kasan/common.c#L33
so I am lost and can't comment on any of the Paul's questions re
interrupts/spinlocks.

When re-sending this, please add kasan-dev@ mailing list and add links
to the dependencies.

Thanks

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CACT4Y%2Bbih9gX2%2BXvRh3q7XYe8rbgCDF5%3D5eMV8cxBimvPLQtug%40mail.=
gmail.com.
