Return-Path: <kasan-dev+bncBCS4VDMYRUNBBPVL2CGAMGQE6FIWDXA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3c.google.com (mail-oo1-xc3c.google.com [IPv6:2607:f8b0:4864:20::c3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 3F837453AFE
	for <lists+kasan-dev@lfdr.de>; Tue, 16 Nov 2021 21:34:08 +0100 (CET)
Received: by mail-oo1-xc3c.google.com with SMTP id q63-20020a4a3342000000b002c25d2d8772sf225767ooq.11
        for <lists+kasan-dev@lfdr.de>; Tue, 16 Nov 2021 12:34:08 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1637094846; cv=pass;
        d=google.com; s=arc-20160816;
        b=B4d+uWkMjbvCXISRwo5X3q4VzX8Q4BHYMDuaZA/T7PBO7MQ3fFrCdhHRLhyQyEplBn
         C1vBaDg5PbDRBwZUVJYjb18pnqn1XIZHBHZfWkWvhccof5pos6g2RvNU4hq16p43mWiA
         aDlkbXfmJxmxHn4rhWAhMrF31DYUU1jFm2KIKXkjyD+jGqIokTb1wZZEAL+obkO5YAKS
         xeoOVpITZKgzVF3CrbMEpe6gSxbkWwoFw8A8urJkOpBBp7FkbFAadD+wEI6gi80VwVvM
         scH6zGKd0bcDmWr1dhvUjwjAbI+Y4o6BkE5w7WYLPXtu3XvBbK1SWUQgahfBZBbFHHTt
         LIwA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:reply-to:message-id:subject:cc:to:from:date
         :sender:dkim-signature;
        bh=MSjS+57WNUDnMpY7k0CcZKHxNaN3rLuhhMDwb3Pmiqw=;
        b=CJ2DUEMSS/GznQ0A2ayyyGyx5QXbIY4MpUXbySaU61+jZYixvU7QhIbAcF+T6XCdHl
         qeQ2hpqcbL+UrUCNJoBmwEcaK7eJ3O+v268seppkAz5irz3uLN8tUZKYD1omrWG5xAFK
         hERTUxCq6GBoOpZE5xfvhoM6lQxZoNS/E9iEcjuQw/1+bKfI8rKBPgrsqV22iv6u5QU+
         WiFXwTcXb85PM9UGLOQQCBmNybFLMBLkWR/eyKQCUQt+C8Hb0wxw8FLQ7mlO4wurpS7y
         m4XKnxJEmOiS0o7uhXYnjvsAczn5NDN3Tlu3EAYyrPr1M2TAReByLHM/EQGDgYAkr6gZ
         6rUA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="YLPy/WNN";
       spf=pass (google.com: domain of srs0=nev0=qd=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=NEV0=QD=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=MSjS+57WNUDnMpY7k0CcZKHxNaN3rLuhhMDwb3Pmiqw=;
        b=m2JCltx5zGmGjyVZpYnPVaX6tBvNyceMRxnCYE1U+ESuyFpp/t4RSbD68IrJJgb5kU
         GocBdhKSiRd+tQmV+GK2ZABbDd84fbtgJc29xNmjoqeTUrKE1KCHvTsF5v7b5Ti7C/aa
         D8IfnOhIafp0WJKUK+kx+XPac24UjozIkbWcWVR2+tC3EHoFdzx427dFlfDSDuOAgIzx
         KzgdeKhrRBNcTwWcNGWhArDUKRuHoYr7sGijH9YhLDz5Fr5jGDFgNiVXRZhLUS/LLA1i
         i7RuewcRrvgOP2uKT4pFWk73A6mq6N+NUrmPRf2I1pP01/791wCIYXl6/+jEz8kHTH3c
         O5dg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=MSjS+57WNUDnMpY7k0CcZKHxNaN3rLuhhMDwb3Pmiqw=;
        b=zYiZjixj6ahWP+AMEG1cpE0b/V9tl5j7hrelweWC63S6oyHb5u5WxQ3esAtd+Cy77f
         YSPvoD3qJ+ksKeaSDh4XQf7L5W8gGCRpWmp4AgamQms3JkM8HBDQttacuR9+nY5O16s2
         vTC55ewL6oZ3uMtCj3dg8FthCxsWpE39oN1VCUjmMT8+fh45UOG2wdyQxaWQbs73sQxH
         v1GLdrzHWUmGH9sesvrcwbarNZ3N/Jp3weS+0hL7pJqvT+BqA/jqdeLAvYk70mIcgi/j
         9ye3rCGOcr0snVnenl+ijB6zUQqw49a7CQe+gCslMh2n/8JKQXo9TxprpJWyjQ2bFFbv
         N2nw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531gIt2TmQpjl87ZwycBg+JZ7XhtI8lYjMGzWJBRxt9IfoNyvZhF
	JevyjpnwVacY+xn8DICOf+k=
X-Google-Smtp-Source: ABdhPJyH7unAMxJvM15st5LGLwcX1n7IDROiWY7zUYBFgIdjE8pEuahikj24guJy/xwVUELqevFQKQ==
X-Received: by 2002:a9d:2923:: with SMTP id d32mr8246110otb.149.1637094846639;
        Tue, 16 Nov 2021 12:34:06 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:bca:: with SMTP id 68ls3867717oth.8.gmail; Tue, 16 Nov
 2021 12:34:06 -0800 (PST)
X-Received: by 2002:a9d:2647:: with SMTP id a65mr8541048otb.185.1637094846241;
        Tue, 16 Nov 2021 12:34:06 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1637094846; cv=none;
        d=google.com; s=arc-20160816;
        b=OrhxCO6h52T/nGSUoYIFRidzWljZCuiV5u66frgmu2PbcQzXEm8pje9ltFmoGdDIGg
         lfXidLYl60qpyforAa5yEd1eG/JEpsBL1rxWRUGrgwUFqNjO6HNJE1+IP8Vyv9HZxf+q
         N3hqHDAImCC3Ezay8qpJbZNzvacw6wG/LP4QwKAbShnxhfjqDgjBerjJKuvQGeCionfo
         Jf56ejxrOKuDG/aHN3RGhnWJnTaXBJ8iGg9qMRQLOe8Y3ARkhAu5kyZE0IHZ2sp6y4yc
         gY4ZgqIXGlPynkIGYoY8nSSX9vCFlYK1BWiJFeCKvpfB4crJWJhctFsNFgkmjPuZybvS
         LB0A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=50UCo7OMcAYkmBjj9XxJq2OOyl1zii+nrtvsdCVEy9Q=;
        b=PXjMqowSyc+dDTPPLtKX6zegGRzRn1CRHksr9Hejd9USYnleVwzoMOjQQAyMamIMhz
         n8ACvH/W/A98dOrCD6BT/N2NEWLtjemIh/j+a7AX9NFz32v54i9nAYfyXuekax/D6Pha
         Z5aKzkgbDX3Sx3LMcjypb45P23N1mTNME+kg3Q49XdT+mz4mA3UpG5+EXHKJeG8MTIBZ
         genEIp7vV6Pnp7Ncmy3s9sFKadOZoaWgJ7kjPAZZgV63aCMM0eZFYS+dLQqHWUEUOcmQ
         /sCYoKV3IQqJS6bb4FGYvbu/yp3I1DDnQK5nFqm5jTBPf2XokRf1jWK4PdsBc1cSItq2
         QPiA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="YLPy/WNN";
       spf=pass (google.com: domain of srs0=nev0=qd=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=NEV0=QD=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id g64si100340oia.1.2021.11.16.12.34.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 16 Nov 2021 12:34:06 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=nev0=qd=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 7519461037;
	Tue, 16 Nov 2021 20:34:05 +0000 (UTC)
Received: by paulmck-ThinkPad-P17-Gen-1.home (Postfix, from userid 1000)
	id 428345C0433; Tue, 16 Nov 2021 12:34:05 -0800 (PST)
Date: Tue, 16 Nov 2021 12:34:05 -0800
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Juri Lelli <juri.lelli@redhat.com>
Cc: Jun Miao <jun.miao@intel.com>, urezki@gmail.com, elver@google.com,
	josh@joshtriplett.org, rostedt@goodmis.org,
	mathieu.desnoyers@efficios.com, jiangshanlai@gmail.com,
	joel@joelfernandes.org, qiang.zhang1211@gmail.com,
	rcu@vger.kernel.org, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com, jianwei.hu@windriver.com
Subject: Re: [V2][PATCH] rcu: avoid alloc_pages() when recording stack
Message-ID: <20211116203405.GU641268@paulmck-ThinkPad-P17-Gen-1>
Reply-To: paulmck@kernel.org
References: <1637018582-10788-1-git-send-email-jun.miao@intel.com>
 <20211116173959.osdzlvv7niyxthd6@localhost.localdomain>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20211116173959.osdzlvv7niyxthd6@localhost.localdomain>
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b="YLPy/WNN";       spf=pass
 (google.com: domain of srs0=nev0=qd=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=NEV0=QD=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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

On Tue, Nov 16, 2021 at 05:39:59PM +0000, Juri Lelli wrote:
> Hi,
> 
> On 16/11/21 07:23, Jun Miao wrote:
> > The default kasan_record_aux_stack() calls stack_depot_save() with GFP_NOWAIT,
> > which in turn can then call alloc_pages(GFP_NOWAIT, ...).  In general, however,
> > it is not even possible to use either GFP_ATOMIC nor GFP_NOWAIT in certain
> > non-preemptive contexts/RT kernel including raw_spin_locks (see gfp.h and ab00db216c9c7).
> > Fix it by instructing stackdepot to not expand stack storage via alloc_pages()
> > in case it runs out by using kasan_record_aux_stack_noalloc().
> > 
> > Jianwei Hu reported:
> > BUG: sleeping function called from invalid context at kernel/locking/rtmutex.c:969
> > in_atomic(): 0, irqs_disabled(): 1, non_block: 0, pid: 15319, name: python3
> > INFO: lockdep is turned off.
> > irq event stamp: 0
> >   hardirqs last  enabled at (0): [<0000000000000000>] 0x0
> >   hardirqs last disabled at (0): [<ffffffff856c8b13>] copy_process+0xaf3/0x2590
> >   softirqs last  enabled at (0): [<ffffffff856c8b13>] copy_process+0xaf3/0x2590
> >   softirqs last disabled at (0): [<0000000000000000>] 0x0
> >   CPU: 6 PID: 15319 Comm: python3 Tainted: G        W  O 5.15-rc7-preempt-rt #1
> >   Hardware name: Supermicro SYS-E300-9A-8C/A2SDi-8C-HLN4F, BIOS 1.1b 12/17/2018
> >   Call Trace:
> >     show_stack+0x52/0x58
> >     dump_stack+0xa1/0xd6
> >     ___might_sleep.cold+0x11c/0x12d
> >     rt_spin_lock+0x3f/0xc0
> >     rmqueue+0x100/0x1460
> >     rmqueue+0x100/0x1460
> >     mark_usage+0x1a0/0x1a0
> >     ftrace_graph_ret_addr+0x2a/0xb0
> >     rmqueue_pcplist.constprop.0+0x6a0/0x6a0
> >      __kasan_check_read+0x11/0x20
> >      __zone_watermark_ok+0x114/0x270
> >      get_page_from_freelist+0x148/0x630
> >      is_module_text_address+0x32/0xa0
> >      __alloc_pages_nodemask+0x2f6/0x790
> >      __alloc_pages_slowpath.constprop.0+0x12d0/0x12d0
> >      create_prof_cpu_mask+0x30/0x30
> >      alloc_pages_current+0xb1/0x150
> >      stack_depot_save+0x39f/0x490
> >      kasan_save_stack+0x42/0x50
> >      kasan_save_stack+0x23/0x50
> >      kasan_record_aux_stack+0xa9/0xc0
> >      __call_rcu+0xff/0x9c0
> >      call_rcu+0xe/0x10
> >      put_object+0x53/0x70
> >      __delete_object+0x7b/0x90
> >      kmemleak_free+0x46/0x70
> >      slab_free_freelist_hook+0xb4/0x160
> >      kfree+0xe5/0x420
> >      kfree_const+0x17/0x30
> >      kobject_cleanup+0xaa/0x230
> >      kobject_put+0x76/0x90
> >      netdev_queue_update_kobjects+0x17d/0x1f0
> >      ... ...
> >      ksys_write+0xd9/0x180
> >      __x64_sys_write+0x42/0x50
> >      do_syscall_64+0x38/0x50
> >      entry_SYSCALL_64_after_hwframe+0x44/0xa9
> > 
> > Links: https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/include/linux/kasan.h?id=7cb3007ce2da27ec02a1a3211941e7fe6875b642
> > Fixes: 84109ab58590 ("rcu: Record kvfree_call_rcu() call stack for KASAN")
> > Fixes: 26e760c9a7c8 ("rcu: kasan: record and print call_rcu() call stack")
> > Reported-by: Jianwei Hu <jianwei.hu@windriver.com>
> > Reviewed-by: Uladzislau Rezki (Sony) <urezki@gmail.com>
> > Signed-off-by: Jun Miao <jun.miao@intel.com>
> > ---
> 
> I gave this a quick try on RT. No splats. Nice!
> 
> Tested-by: Juri Lelli <juri.lelli@redhat.com>

Applied with Juri's Tested-by and Marco's Acked-by.  Thank you all!

							Thanx, Paul

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211116203405.GU641268%40paulmck-ThinkPad-P17-Gen-1.
