Return-Path: <kasan-dev+bncBCV5TUXXRUIBBBGNZ34QKGQEEHGXWUI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33c.google.com (mail-wm1-x33c.google.com [IPv6:2a00:1450:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id E99D32426A5
	for <lists+kasan-dev@lfdr.de>; Wed, 12 Aug 2020 10:21:24 +0200 (CEST)
Received: by mail-wm1-x33c.google.com with SMTP id i15sf445554wmb.5
        for <lists+kasan-dev@lfdr.de>; Wed, 12 Aug 2020 01:21:24 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1597220484; cv=pass;
        d=google.com; s=arc-20160816;
        b=GlH/XwVy+3Rh60Yz6zdjcgA5EiEFUALxSFx8f9WThHjvHyhyR1tpCV8K25ajG3wxC4
         hkApjbr4raIuz1UOV5P1TY+Dw/8gjV8lSGVvLwF/QnrTnvGzVq3tGwNNDTMtVxDKqm1V
         HzKKKoeVoETClrQbOzu9+uHAoulr3+b0eEKH75xlkVQ1PCY2Fj3AFy78bHgzlwoMzZGB
         mFVxlRoza3S/Rj+8ukTt0AMxi0rfsP6U4OxHES2/Mzs1EoPc1Vs3OpvgvB+Le8ZuBNef
         OUPrR8FC5j5yRCrvfI1mO/TdsdcztbK92OhU16QuAsc9FOt8bwDTfawYU3+9wMSvRH9a
         gGMQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=BjnnmVu4Hgvmu4qW2IUxNrmz0XuZJXovIb5bUAUd6kw=;
        b=pP/8SxUL/RgNDGm01T2fByU11vLYJoNsSYep/IeB+7t2k858jb3KUR9wntTqYrxNTt
         6a+16MaMUgPE70uSfIiBe1Iqmpt1x1n83RZWYs9taxC4p+tKv1MTVw6l3bQUDKk96Qaj
         G1uIB06ymrFrTHKc+lEQAu3BmqsCWkxOxq0pnv6NnAdPH/CDWKZjUEwqLfL9oNM9Xigk
         Xky9pLOL8G3Ect9Ux+9YYXyvRdySmDxIZUnPFyoYlf57r7DBNoiGlQu+aKmznRU1DCWh
         tDunlJtlKdirchefo52ScrOCiUZzOGvIXbfLKktd0uHUb/bg80B4hDyGTym0pVPqrDzl
         xdpg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=kTn2pnqI;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=BjnnmVu4Hgvmu4qW2IUxNrmz0XuZJXovIb5bUAUd6kw=;
        b=n2WYgQeRbMeN6ceoM7sIDv+YMPwzAesVXissrQ54rsVUOpoHBa0L68sXtu5IEp/AqX
         /T11H0GY7A+EQo60+ZqDBlS7KZLYegP5hSMcXj8HwqyPpTC+0cHcpOo5jKnLCqkMSM3C
         jQm+CPcY+5uJ4D2D7FU514Rw+mx/mZ1n4R6dAefd7XfQ/mnz8NT9IBZRJEA/Rd/phy6g
         CyyRuKfGECS/qB4+Rzhs54xPfWuRJ1bJMKTgkp7kzyCS1m6ZN3xCrFxszjXJgwU1mWXH
         wwBl8asMZiP5tDWQZmgGD0ZFp6d9QrdANMG8lZGEA9rBlP3jWbnHII4X6f0XmVKXmTt7
         tK4w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=BjnnmVu4Hgvmu4qW2IUxNrmz0XuZJXovIb5bUAUd6kw=;
        b=et/vvACYW34zZDvBdryiUtWBq7KRBe/Irgm15GikzEBfz/cX+reLrUksBa4W7NVjyt
         91JlHBWz08Wiy9HLAMtKFiEmXe+36HUQ9Ne+avxlZact1W5Xh4BVLwoIYg/LO6ai9lEX
         mh9cjIKtVCeYhI752Jf4GC0EY3DMX3Af31oMWGnwcdnZ7aSwBG6yacHkGIZV5bTI2jFj
         hVobDvGfyp1/YMbQBhdMic9S1n07SdmqGHBKxXBNmtMfzVeAkYOwKzg/iTE3xerT05jO
         5ux42xshP0Z1aLv1ocn4m5j6G2qMYdVuu+/xkhNaCsyxZj717wgv3RaJs29CUXxe6b/2
         uo2Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530BOQ5CWiwC1Koug/dI6LA4ocGIkh0PAPrYSmR0q1+CJzTv8yVe
	g8pzVGCpM1caUBxaHpHXiVY=
X-Google-Smtp-Source: ABdhPJwAYIOB6UaufZMAfcgPuwpLfp2ZhAM556LwXZVsbPajqrcUGUTrWne+nvlPFj3B15jrKWME9Q==
X-Received: by 2002:a5d:4a0d:: with SMTP id m13mr34747214wrq.12.1597220484618;
        Wed, 12 Aug 2020 01:21:24 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:b1cf:: with SMTP id r15ls1445174wra.3.gmail; Wed, 12 Aug
 2020 01:21:24 -0700 (PDT)
X-Received: by 2002:a5d:6505:: with SMTP id x5mr5320145wru.336.1597220484047;
        Wed, 12 Aug 2020 01:21:24 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1597220484; cv=none;
        d=google.com; s=arc-20160816;
        b=K5WqveOWnUL+Xaqmr6c/PTHwj8/iVX0iE85mttnZ1li21C5dGX67Vg67VyRhodYN9Y
         V/vmJhZ+SJmT7pxqiwSa70QhSBcytfWhzM8fs95WetuOtJnnc4Y4m7AAyMOvvzEy/KUD
         GGldeVQqw4tw5ozC+k7+pfK9XeIp8Xz3GlzhTxx+PiwoGZiFtcTv1WipuI8+5nahjZGL
         8qkSMhU0iXrmY0oIZkUlikLl6ODRfqBZX4OAsDEKJlAatHAmfC8eOw36rpL8IIWRr8Dp
         QVGyuKFGo3GBM6RvGii+/I3Kbt2EXWZVxysg6aRcG20QY5hNlFxrXdwXz1VoszmjM3ri
         Fitg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=JgBMrxFhpXh3xpWdoZXYK4da8LqJW1ikTR27jgesG/k=;
        b=yoofm6cnQcS4V12bfjrKxL1DtPUNpSt433wRNehwMPvv42t/uwtiuBoAGqbC11kzPV
         +ksLrJoom4W3JumMifjHPxv3Grt6c+yHh5Yly0Iot6FoORSUwMCsS0WT6qPLKL4TJJjy
         Yk68vQiF/FQmrCWbSDtnjzRpWfE7Vkq5w+GbFt73KLYhOA4WdPNaYubBCxcevphsaZft
         BOZ9ANDailZVmEnwMJMkcRy8tEHinh8QFUnzF5iF9zHCAt3svUU4UboKKIHnX/CX7W/R
         00MAkM4rxMoaxiKLzj3VEuPnb+HINyEmgHWO27FmTYJmg1DCuW5l8HE2pdiCXzSLS/JX
         AB3A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=kTn2pnqI;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from casper.infradead.org (casper.infradead.org. [2001:8b0:10b:1236::1])
        by gmr-mx.google.com with ESMTPS id f134si332204wme.4.2020.08.12.01.21.24
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 12 Aug 2020 01:21:24 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) client-ip=2001:8b0:10b:1236::1;
Received: from j217100.upc-j.chello.nl ([24.132.217.100] helo=noisy.programming.kicks-ass.net)
	by casper.infradead.org with esmtpsa (Exim 4.92.3 #3 (Red Hat Linux))
	id 1k5lxz-0001nH-73; Wed, 12 Aug 2020 08:18:55 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id 7D08D300238;
	Wed, 12 Aug 2020 10:18:32 +0200 (CEST)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 1000)
	id 6679022281190; Wed, 12 Aug 2020 10:18:32 +0200 (CEST)
Date: Wed, 12 Aug 2020 10:18:32 +0200
From: peterz@infradead.org
To: Marco Elver <elver@google.com>
Cc: =?iso-8859-1?Q?J=FCrgen_Gro=DF?= <jgross@suse.com>,
	Borislav Petkov <bp@alien8.de>,
	Dave Hansen <dave.hansen@linux.intel.com>, fenghua.yu@intel.com,
	"H. Peter Anvin" <hpa@zytor.com>,
	LKML <linux-kernel@vger.kernel.org>, Ingo Molnar <mingo@redhat.com>,
	syzkaller-bugs <syzkaller-bugs@googlegroups.com>,
	Thomas Gleixner <tglx@linutronix.de>,
	"Luck, Tony" <tony.luck@intel.com>,
	the arch/x86 maintainers <x86@kernel.org>, yu-cheng.yu@intel.com,
	sdeep@vmware.com, virtualization@lists.linux-foundation.org,
	kasan-dev <kasan-dev@googlegroups.com>,
	syzbot <syzbot+8db9e1ecde74e590a657@syzkaller.appspotmail.com>,
	"Paul E. McKenney" <paulmck@kernel.org>,
	Wei Liu <wei.liu@kernel.org>, Steven Rostedt <rostedt@goodmis.org>
Subject: Re: [PATCH] x86/paravirt: Add missing noinstr to arch_local*()
 helpers
Message-ID: <20200812081832.GK2674@hirez.programming.kicks-ass.net>
References: <CANpmjNPau_DEYadey9OL+iFZKEaUTqnFnyFs1dU12o00mg7ofA@mail.gmail.com>
 <20200807151903.GA1263469@elver.google.com>
 <20200811074127.GR3982@worktop.programming.kicks-ass.net>
 <a2dffeeb-04f0-8042-b39a-b839c4800d6f@suse.com>
 <20200811081205.GV3982@worktop.programming.kicks-ass.net>
 <07f61573-fef1-e07c-03f2-a415c88dec6f@suse.com>
 <20200811092054.GB2674@hirez.programming.kicks-ass.net>
 <20200811094651.GH35926@hirez.programming.kicks-ass.net>
 <20200811201755.GI35926@hirez.programming.kicks-ass.net>
 <20200812080650.GA3894595@elver.google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20200812080650.GA3894595@elver.google.com>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=casper.20170209 header.b=kTn2pnqI;
       spf=pass (google.com: best guess record for domain of
 peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
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

On Wed, Aug 12, 2020 at 10:06:50AM +0200, Marco Elver wrote:
> On Tue, Aug 11, 2020 at 10:17PM +0200, peterz@infradead.org wrote:
> > On Tue, Aug 11, 2020 at 11:46:51AM +0200, peterz@infradead.org wrote:
> > 
> > > So let me once again see if I can't find a better solution for this all.
> > > Clearly it needs one :/
> > 
> > So the below boots without triggering the debug code from Marco -- it
> > should allow nesting local_irq_save/restore under raw_local_irq_*().
> > 
> > I tried unconditional counting, but there's some _reallly_ wonky /
> > asymmetric code that wrecks that and I've not been able to come up with
> > anything useful.
> > 
> > This one starts counting when local_irq_save() finds it didn't disable
> > IRQs while lockdep though it did. At that point, local_irq_restore()
> > will decrement and enable things again when it reaches 0.
> > 
> > This assumes local_irq_save()/local_irq_restore() are nested sane, which
> > is mostly true.
> > 
> > This leaves #PF, which I fixed in these other patches, but I realized it
> > needs fixing for all architectures :-( No bright ideas there yet.
> > 
> > ---
> >  arch/x86/entry/thunk_32.S       |  5 ----
> >  include/linux/irqflags.h        | 45 +++++++++++++++++++-------------
> >  init/main.c                     | 16 ++++++++++++
> >  kernel/locking/lockdep.c        | 58 +++++++++++++++++++++++++++++++++++++++++
> >  kernel/trace/trace_preemptirq.c | 33 +++++++++++++++++++++++
> >  5 files changed, 134 insertions(+), 23 deletions(-)
> 
> Testing this again with syzkaller produced some new reports:
> 
> 	BUG: stack guard page was hit in error_entry
> 	BUG: stack guard page was hit in exc_int3
> 	PANIC: double fault in error_entry
> 	PANIC: double fault in exc_int3
> 
> Most of them have corrupted reports, but this one might be useful:
> 
> 	BUG: stack guard page was hit at 000000001fab0982 (stack is 00000000063f33dc..00000000bf04b0d8)
> 	BUG: stack guard page was hit at 00000000ca97ac69 (stack is 00000000af3e6c84..000000001597e1bf)
> 	kernel stack overflow (double-fault): 0000 [#1] PREEMPT SMP
> 	CPU: 1 PID: 4709 Comm: kworker/1:1H Not tainted 5.8.0+ #5
> 	Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.13.0-1 04/01/2014
> 	Workqueue: events_highpri snd_vmidi_output_work
> 	RIP: 0010:exc_int3+0x5/0xf0 arch/x86/kernel/traps.c:636
> 	Code: c9 85 4d 89 e8 31 c0 e8 a9 7d 68 fd e9 90 fe ff ff e8 0f 35 00 00 66 66 2e 0f 1f 84 00 00 00 00 00 0f 1f 40 00 55 53 48 89 fb <e8> 76 0e 00 00 85 c0 74 03 5b 5d c3 f6 83 88 00 00 00 03 74 7e 48
> 	RSP: 0018:ffffc90008114000 EFLAGS: 00010083
> 	RAX: 0000000084e00e17 RBX: ffffc90008114018 RCX: ffffffff84e00e17
> 	RDX: 0000000000000000 RSI: ffffffff84e00a39 RDI: ffffc90008114018
> 	RBP: 0000000000000000 R08: 0000000000000000 R09: 0000000000000000
> 	R10: 0000000000000000 R11: 0000000000000000 R12: 0000000000000000
> 	R13: 0000000000000000 R14: 0000000000000000 R15: 0000000000000000
> 	FS:  0000000000000000(0000) GS:ffff88807dc80000(0000) knlGS:0000000000000000
> 	CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
> 	CR2: ffffc90008113ff8 CR3: 000000002dae4006 CR4: 0000000000770ee0
> 	DR0: 0000000000000000 DR1: 0000000000000000 DR2: 0000000000000000
> 	DR3: 0000000000000000 DR6: 00000000fffe0ff0 DR7: 0000000000000400
> 	PKRU: 00000000
> 	Call Trace:
> 	 asm_exc_int3+0x31/0x40 arch/x86/include/asm/idtentry.h:537
> 	RIP: 0010:arch_static_branch include/trace/events/preemptirq.h:40 [inline]
> 	RIP: 0010:static_key_false include/linux/jump_label.h:200 [inline]
> 	RIP: 0010:trace_irq_enable_rcuidle+0xd/0x120 include/trace/events/preemptirq.h:40
> 	Code: 24 08 48 89 df e8 43 8d ef ff 48 89 df 5b e9 4a 2e 99 03 66 2e 0f 1f 84 00 00 00 00 00 55 41 56 53 48 89 fb e8 84 1a fd ff cc <1f> 44 00 00 5b 41 5e 5d c3 65 8b 05 ab 74 c3 7e 89 c0 31 f6 48 0f
> 	RSP: 0018:ffffc900081140f8 EFLAGS: 00000093
> 	RAX: ffffffff813d9e8c RBX: ffffffff81314dd3 RCX: ffff888076ce6000
> 	RDX: 0000000000000000 RSI: 0000000000000000 RDI: ffffffff81314dd3
> 	RBP: 0000000000000000 R08: ffffffff813da3d4 R09: 0000000000000001
> 	R10: 0000000000000000 R11: 0000000000000000 R12: 0000000000000000
> 	R13: 0000000000000082 R14: 0000000000000000 R15: ffff888076ce6000
> 	 trace_hardirqs_restore+0x59/0x80 kernel/trace/trace_preemptirq.c:106
> 	 rcu_irq_enter_irqson+0x43/0x70 kernel/rcu/tree.c:1074
> 	 trace_irq_enable_rcuidle+0x87/0x120 include/trace/events/preemptirq.h:40
> 	 trace_hardirqs_restore+0x59/0x80 kernel/trace/trace_preemptirq.c:106
> 	 rcu_irq_enter_irqson+0x43/0x70 kernel/rcu/tree.c:1074
> 	 trace_irq_enable_rcuidle+0x87/0x120 include/trace/events/preemptirq.h:40
> 	 trace_hardirqs_restore+0x59/0x80 kernel/trace/trace_preemptirq.c:106
> 	 rcu_irq_enter_irqson+0x43/0x70 kernel/rcu/tree.c:1074
> 	 trace_irq_enable_rcuidle+0x87/0x120 include/trace/events/preemptirq.h:40
> 	 trace_hardirqs_restore+0x59/0x80 kernel/trace/trace_preemptirq.c:106
> 	 rcu_irq_enter_irqson+0x43/0x70 kernel/rcu/tree.c:1074
> 
> 	<... repeated many many times ...>
> 
> 	 trace_irq_enable_rcuidle+0x87/0x120 include/trace/events/preemptirq.h:40
> 	 trace_hardirqs_restore+0x59/0x80 kernel/trace/trace_preemptirq.c:106
> 	 rcu_irq_enter_irqson+0x43/0x70 kernel/rcu/tree.c:1074
> 	Lost 500 message(s)!
> 	BUG: stack guard page was hit at 00000000cab483ba (stack is 00000000b1442365..00000000c26f9ad3)
> 	BUG: stack guard page was hit at 00000000318ff8d8 (stack is 00000000fd87d656..0000000058100136)
> 	---[ end trace 4157e0bb4a65941a ]---

Wheee... recursion! Let me try and see if I can make something of that.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200812081832.GK2674%40hirez.programming.kicks-ass.net.
