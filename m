Return-Path: <kasan-dev+bncBC7OBJGL2MHBBPMZ376QKGQE3Y2KVNY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43a.google.com (mail-wr1-x43a.google.com [IPv6:2a00:1450:4864:20::43a])
	by mail.lfdr.de (Postfix) with ESMTPS id 9EA932BAB9A
	for <lists+kasan-dev@lfdr.de>; Fri, 20 Nov 2020 15:03:41 +0100 (CET)
Received: by mail-wr1-x43a.google.com with SMTP id 67sf3465861wra.2
        for <lists+kasan-dev@lfdr.de>; Fri, 20 Nov 2020 06:03:41 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605881021; cv=pass;
        d=google.com; s=arc-20160816;
        b=cfUZtDbOYjEU5nAqMoN9lOGOkr2KW+HMaUkufAERGVV09zuWfNWwhNfY8qbgDZSOKj
         tmSfJ+MagWxW9AXVEESOS4i/V/QttAeoc2nvcwdElJkbrDxO1W31mGPvrxLkKP5vrTH5
         NSu5IdC1UKrjODSXXOto+GRbhCJJWizrfE1XEBt0n6oTovqFILhmCpuZL3A4iT1nJrda
         unykCAq3eGZH6/rSPgKrpehZh+mVwDBcTZRget/G7sIxdsN4Dm4wHITZLzr5mcnP+5Tg
         QBwn52TESSc85fB7+j+gnFlD6J8piYhWj/Nd0Jktf2W8IIJLufaVPdU7Qb1JQStXyHvn
         uD5Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=hEPyUxX6LJCC7lkzBtv4XLa/Q3b3DJwMsAiP6Kg+UO8=;
        b=ciW9oqnO/caeot2t1Uvo8haOTXNe5aqegefRF0OBWcFDYr9As85EqCMcuCP2QukKMc
         8RDTLArnFYRvb0ovRLC+OvemmppB9OeklGpr2zhpF14LEwOooKCbU/uBjdPOWEen0YwB
         cNCcSy4hQe0H/Nvs8YC/wutdwy99Aj7qxx12UjKYFvpwYXtdhP9RqzaEzK5c37HxutVV
         ZdjcJtk/bUJo7zmLboL3CsnkHeycDPKA/Z02j3OlJaBz88CasCOIOTW+AN24lGMwPR5M
         mb9lCUD3KVNGGPjfP3ba3SifvDMoUAVIsoJBPx8dSLjU5tF6jW0YuOjfgeUlyimvIV5n
         aIVA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=pELj+m5x;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::343 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=hEPyUxX6LJCC7lkzBtv4XLa/Q3b3DJwMsAiP6Kg+UO8=;
        b=qhIadEYe4htPIZ700ZkaxagZbDhM0LbSVybBoziz/9gQBAhgwUTw+lVmcK+TIMg6qB
         UVcCstUKbGm1bD27PomvFhHQ/+pTPGCtPBKyIkK/zj3XYGu7R+MMNoNf0x1nRcuZ+uA/
         T1Q28YxyxIUuxc0TPhHRa5+/pfG4S5X4SkqnjhXUmY+ZWegAI85iGnAf7diQH7e591xj
         +GvAOma+W2S3HrCdjKZ10niJARvz7+boh0HhqzORDEdK6vQtbkF6M8csSFfjF2Y5vEy8
         Fpu0rr89dzjbdFhKhb7+0Otf4FGCEwSxjCsiTRqDrlY8Uav0pvAT6PG3HjJY7oMalIqY
         VQ5Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=hEPyUxX6LJCC7lkzBtv4XLa/Q3b3DJwMsAiP6Kg+UO8=;
        b=nVWRGiEvIo5JDeaOtwJGFP5hb45dyeolcj0CXvDeLY431JQLdBwiBxTcFonYjqtVAd
         0wRrsKVhu82IAZOj5FAli67oXl6U5fxBbKmYZR+LPB1leIwza+/T+eI94nw4JRL8S9pg
         k0L7nckREHibGVls8xGI4Pi2DVlGax/14E9Le7h9YRwerIeYxMtPJJuoAeD2x2+t4LrQ
         y6pNfyChOGIui9rOlBOpMp3dgpfii9r9BxN+BIH/8nvvkkWDyl2PtnzeKV43EdfCPjdR
         WqLVUUZBh0fmw2OvuGhnRCkfUAKlzGHoHZxv+ocSrYauLgQo26YkRqv4d1xAGYyQslUP
         PyUw==
X-Gm-Message-State: AOAM530V2gZ+2GT815UEuBySIild43p4hkRPyD2+moifqEMSKnLqWbQr
	rzyi5+VV07B4iIGVXaOlqZY=
X-Google-Smtp-Source: ABdhPJxJnjb1ARU0TZXCZ/5b0iIaet64S3ZFVL6NlxEVpLVnRwLjR265NTItOLDtFMkR03YUNSGJNg==
X-Received: by 2002:a05:6000:182:: with SMTP id p2mr17281394wrx.116.1605881021295;
        Fri, 20 Nov 2020 06:03:41 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:2d14:: with SMTP id t20ls3433192wmt.3.canary-gmail; Fri,
 20 Nov 2020 06:03:40 -0800 (PST)
X-Received: by 2002:a05:600c:2048:: with SMTP id p8mr10400505wmg.165.1605881020115;
        Fri, 20 Nov 2020 06:03:40 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605881020; cv=none;
        d=google.com; s=arc-20160816;
        b=fcGVOB+KWwodbF8SpwUdsJBvTbiqWRytX3whR+sLBYTCo6mwXOdT5evFjkzOmRusF1
         G9OO6jXFYF59FgB3/UFksiXAk50C3UFNOFLgge1cA3jqli5+yEY0FsYOZpA5WMQeVIZ+
         2ZoiFRhJsLPMkvIYVDint84si4PZKhWCniJ/UHAeGOsUrz6LYZM1l0ns2U7uJi/L/9nk
         GPLSROGbPPIsuSEChyRhFgZ34SXsCiCVlXGP6Q/6An1wqp5bvgD9Ro+X6h33BmbXxNJg
         YJoMP7FUI5Oq2h9vWeOgMEwldVuewUkafRwgArvczHoNbFbLvGnQRBb0bD29cxImenpl
         mZJQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=JoGES5JnpzdJHEq/vqglQmICNCpPQHRF+Aicnxqj2bQ=;
        b=GxsHx7fgrj1bidnMprvciX8dZn8mh6Z+6wkns4X3OiHiMoAU8Yt6N3NOyMuPahCBmr
         nFScF4ke15frgOst6kIfN9qNNps418VI0rKUyJFdH2ydHYhwwslXDllUlwboZ/OyVnxC
         J91myntHKWsqmbZ1jiH0MQd+Zj2wWTf/B6eDhUbG2PSkzAubw942EG6GkzQraMqVPG+f
         QLCr7RES1OpdCQs/L9RodE2ViD8jMklMoWIG8BzOQRgJCCjbK4lLPEoJguVLIKOLWCua
         0tH/qEzH9hf1bi0l9np170RAxtfRP9chuPhVhTWIHsQefWqdHwqUkIgJWrezRVYhTNEQ
         Vseg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=pELj+m5x;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::343 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x343.google.com (mail-wm1-x343.google.com. [2a00:1450:4864:20::343])
        by gmr-mx.google.com with ESMTPS id i3si160857wra.1.2020.11.20.06.03.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 20 Nov 2020 06:03:40 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::343 as permitted sender) client-ip=2a00:1450:4864:20::343;
Received: by mail-wm1-x343.google.com with SMTP id 10so10456164wml.2
        for <kasan-dev@googlegroups.com>; Fri, 20 Nov 2020 06:03:40 -0800 (PST)
X-Received: by 2002:a1c:f017:: with SMTP id a23mr10277443wmb.56.1605881019458;
        Fri, 20 Nov 2020 06:03:39 -0800 (PST)
Received: from elver.google.com ([2a00:79e0:15:13:f693:9fff:fef4:2449])
        by smtp.gmail.com with ESMTPSA id x2sm4946040wru.44.2020.11.20.06.03.37
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 20 Nov 2020 06:03:37 -0800 (PST)
Date: Fri, 20 Nov 2020 15:03:32 +0100
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Mark Rutland <mark.rutland@arm.com>
Cc: Will Deacon <will@kernel.org>, "Paul E. McKenney" <paulmck@kernel.org>,
	Steven Rostedt <rostedt@goodmis.org>,
	Anders Roxell <anders.roxell@linaro.org>,
	Andrew Morton <akpm@linux-foundation.org>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>, Jann Horn <jannh@google.com>,
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>,
	Linux-MM <linux-mm@kvack.org>,
	kasan-dev <kasan-dev@googlegroups.com>, rcu@vger.kernel.org,
	Peter Zijlstra <peterz@infradead.org>, Tejun Heo <tj@kernel.org>,
	Lai Jiangshan <jiangshanlai@gmail.com>,
	linux-arm-kernel@lists.infradead.org
Subject: Re: linux-next: stall warnings and deadlock on Arm64 (was: [PATCH]
 kfence: Avoid stalling...)
Message-ID: <20201120140332.GA3120165@elver.google.com>
References: <20201118225621.GA1770130@elver.google.com>
 <20201118233841.GS1437@paulmck-ThinkPad-P72>
 <20201119125357.GA2084963@elver.google.com>
 <20201119151409.GU1437@paulmck-ThinkPad-P72>
 <20201119170259.GA2134472@elver.google.com>
 <20201119184854.GY1437@paulmck-ThinkPad-P72>
 <20201119193819.GA2601289@elver.google.com>
 <20201119213512.GB1437@paulmck-ThinkPad-P72>
 <20201119225352.GA5251@willie-the-truck>
 <20201120103031.GB2328@C02TD0UTHF1T.local>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20201120103031.GB2328@C02TD0UTHF1T.local>
User-Agent: Mutt/1.14.6 (2020-07-11)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=pELj+m5x;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::343 as
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

On Fri, Nov 20, 2020 at 10:30AM +0000, Mark Rutland wrote:
> On Thu, Nov 19, 2020 at 10:53:53PM +0000, Will Deacon wrote:
> > On Thu, Nov 19, 2020 at 01:35:12PM -0800, Paul E. McKenney wrote:
> > > On Thu, Nov 19, 2020 at 08:38:19PM +0100, Marco Elver wrote:
> > > > On Thu, Nov 19, 2020 at 10:48AM -0800, Paul E. McKenney wrote:
> > > > > On Thu, Nov 19, 2020 at 06:02:59PM +0100, Marco Elver wrote:
> > > 
> > > [ . . . ]
> > > 
> > > > > > I can try bisection again, or reverting some commits that might be
> > > > > > suspicious? But we'd need some selection of suspicious commits.
> > > > > 
> > > > > The report claims that one of the rcu_node ->lock fields is held
> > > > > with interrupts enabled, which would indeed be bad.  Except that all
> > > > > of the stack traces that it shows have these locks held within the
> > > > > scheduling-clock interrupt handler.  Now with the "rcu: Don't invoke
> > > > > try_invoke_on_locked_down_task() with irqs disabled" but without the
> > > > > "sched/core: Allow try_invoke_on_locked_down_task() with irqs disabled"
> > > > > commit, I understand why.  With both, I don't see how this happens.
> > > > 
> > > > I'm at a loss, but happy to keep bisecting and trying patches. I'm also
> > > > considering:
> > > > 
> > > > 	Is it the compiler? Probably not, I tried 2 versions of GCC.
> > > > 
> > > > 	Can we trust lockdep to precisely know IRQ state? I know there's
> > > > 	been some recent work around this, but hopefully we're not
> > > > 	affected here?
> > > > 
> > > > 	Is QEMU buggy?
> > > > 
> > > > > At this point, I am reduced to adding lockdep_assert_irqs_disabled()
> > > > > calls at various points in that code, as shown in the patch below.
> > > > > 
> > > > > At this point, I would guess that your first priority would be the
> > > > > initial bug rather than this following issue, but you never know, this
> > > > > might well help diagnose the initial bug.
> > > > 
> > > > I don't mind either way. I'm worried deadlocking the whole system might
> > > > be worse.
> > > 
> > > Here is another set of lockdep_assert_irqs_disabled() calls on the
> > > off-chance that they actually find something.
> > 
> > FWIW, arm64 is known broken wrt lockdep and irq tracing atm. Mark has been
> > looking at that and I think he is close to having something workable.
> > 
> > Mark -- is there anything Marco and Paul can try out?
> 
> I initially traced some issues back to commit:
> 
>   044d0d6de9f50192 ("lockdep: Only trace IRQ edges")
> 
> ... and that change of semantic could cause us to miss edges in some
> cases, but IIUC mostly where we haven't done the right thing in
> exception entry/return.
> 
> I don't think my patches address this case yet, but my WIP (currently
> just fixing user<->kernel transitions) is at:
> 
> https://git.kernel.org/pub/scm/linux/kernel/git/mark/linux.git/log/?h=arm64/irq-fixes
> 
> I'm looking into the kernel<->kernel transitions now, and I know that we
> mess up RCU management for a small window around arch_cpu_idle, but it's
> not immediately clear to me if either of those cases could cause this
> report.

Thank you -- I tried your irq-fixes, however that didn't seem to fix the
problem (still get warnings and then a panic). :-/

| [  118.375217] Testing all events: OK
| [  174.878839] Running tests again, along with the function tracer
| [  174.894781] Running tests on all trace events:
| [  174.906734] Testing all events: 
| [  176.204533] hrtimer: interrupt took 9035008 ns
| [  286.788330] BUG: workqueue lockup - pool cpus=0 node=0 flags=0x0 nice=0 stuck for 10s!
| [  286.883216] Showing busy workqueues and worker pools:
| [  286.899647] workqueue events: flags=0x0
| [  286.920606]   pwq 0: cpus=0 node=0 flags=0x0 nice=0 active=1/256 refcnt=2
| [  286.933010]     pending: vmstat_shepherd
| [  644.323445] INFO: task kworker/u2:1:107 blocked for more than 12 seconds.
| [  649.448126]       Not tainted 5.10.0-rc4-next-20201119-00004-g77838ee21ff6-dirty #17
| [  656.619598] "echo 0 > /proc/sys/kernel/hung_task_timeout_secs" disables this message.
| [  660.623500] task:kworker/u2:1    state:R stack:    0 pid:  107 ppid:     2 flags:0x00000428
| [  671.587980] Call trace:
| [  674.885884]  __switch_to+0x148/0x1f0
| [  675.267490]  __schedule+0x2dc/0x9a8
| [  677.748050]  schedule+0x4c/0x100
| [  679.223880]  worker_thread+0xe8/0x510
| [  680.663844]  kthread+0x13c/0x188
| [  681.663992]  ret_from_fork+0x10/0x34
| [  684.493389] 
| [  684.493389] Showing all locks held in the system:
| [  688.554449] 4 locks held by swapper/0/1:
| [  691.747079] 1 lock held by khungtaskd/23:
| [  692.525727]  #0: ffffa1ebd7ff1420 (rcu_read_lock){....}-{1:2}, at: debug_show_all_locks+0x34/0x198
| [  704.403177] 
| [  704.630928] =============================================
| [  704.630928] 
| [  706.168072] Kernel panic - not syncing: hung_task: blocked tasks
| [  706.172894] CPU: 0 PID: 23 Comm: khungtaskd Not tainted 5.10.0-rc4-next-20201119-00004-g77838ee21ff6-dirty #17
| [  706.178507] Hardware name: linux,dummy-virt (DT)
| [  706.182658] Call trace:
| [  706.186231]  dump_backtrace+0x0/0x240
| [  706.190124]  show_stack+0x34/0x88
| [  706.193917]  dump_stack+0x140/0x1bc
| [  706.197728]  panic+0x1e4/0x494
| [  706.201440]  watchdog+0x668/0xbe8
| [  706.205238]  kthread+0x13c/0x188
| [  706.208991]  ret_from_fork+0x10/0x34
| [  706.214532] Kernel Offset: 0x21ebc5a00000 from 0xffff800010000000
| [  706.219014] PHYS_OFFSET: 0xffffad8a80000000
| [  706.223148] CPU features: 0x0240022,61806082
| [  706.227149] Memory Limit: none
| [  706.233359] ---[ end Kernel panic - not syncing: hung_task: blocked tasks ]---

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201120140332.GA3120165%40elver.google.com.
