Return-Path: <kasan-dev+bncBC7OBJGL2MHBBGMX3HWAKGQEZUWLPDA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x637.google.com (mail-pl1-x637.google.com [IPv6:2607:f8b0:4864:20::637])
	by mail.lfdr.de (Postfix) with ESMTPS id 89A69CAF35
	for <lists+kasan-dev@lfdr.de>; Thu,  3 Oct 2019 21:27:23 +0200 (CEST)
Received: by mail-pl1-x637.google.com with SMTP id g20sf2352591plj.15
        for <lists+kasan-dev@lfdr.de>; Thu, 03 Oct 2019 12:27:23 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1570130842; cv=pass;
        d=google.com; s=arc-20160816;
        b=lL7V/4Bg+kY3M/TiKyIxBLYI4fEbXmUIY9NrI7zsUMgEePgOfU7dAujTvQ3eCPhEDw
         zM59ZGzhNaF8g/eoP+VTu1BusLn+/UyKTNkiOUUVM9W6QCUcIws/YSDJdr6vsz/F5gD6
         9x2MqOEzLIhrLiG6ixXAGDYTLuqAP7szkGr6vBm7vv8NvdKrMPHAdE2bOAE6tIRO6H3F
         avanDOmoGAH/OylfTtBHbh/0XHk5DtKyJ2N7oAFnA4RWEUzjbnm5p3F24LsbT9QFDhEW
         7qjPgqsEAwFlLtp1R3zN5YebsbMdIUPvGUVhRZCLERdFn/b0ZEI33yTS4L6vW0HhxfVF
         9Flg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=RSpMRdA179Y4vXh0XAk6DSYxJgbNEz32iji0v+Mx1h4=;
        b=Mdpuvc0zBCcF4RwuDepXQF0TPBOI2/oRjZRuyCCFJJwVRYXQpsM2TDOpVjRxzs3VGy
         CNpkEXmTRZu3rXfe68AMxWS45X6e7Eyjklcwfobzlgm82++CeJJUl1aNpDFabZ5Lrjnn
         vX++zCG6Lrq74rLm7NhlqPcA/SNQfakfQWBQnRCOIJIqexFg9uPDwOR/mR7BqjuI7yxt
         YNxCM9ss8Hcl+QDVY0YYD40h/yeWfpV3tVqIB8hx+hIcZ5t+OtRWyZh0OBpoHPj8SvXr
         tn6Wc2cWv/7tl0MGwcqZSBRJncobbnOHoS2vxkSp9eKhYggBd2YJ21CWUFzis6cDDUYQ
         9P8g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Rl3XhvxB;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::244 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=RSpMRdA179Y4vXh0XAk6DSYxJgbNEz32iji0v+Mx1h4=;
        b=TDuS9o9n2+riUOM7GtI6GdPCG8tRYm/4aHJL6W/2UOlZAUDuSKvvJhdMiY3RnVBl9H
         PTmp8DaJv27Z/FteTGBqH5IZ+DQiEld6B7KnC9Uom2H662chVuuRR6x5AJUN7l+XiRJa
         CvfVl+eBRJCAnqHLBub6EB240WdP89RGW9d8QksRV4+XlTNP94dQP4Vb1IpXbmbWdlkD
         HQSd5g5bvgX8D8w4mgtRXpxztRBwjT29ZZdR8P2LhPFcLnzpkrn9vkIdpeiP7LkNaCcc
         ZuTW5q4J3djl+7qj1AhR7A+vS+5TFyWxGhwERMg+X1o8Nh/ZKvau/6/EqdnidGUQ+T1D
         1img==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=RSpMRdA179Y4vXh0XAk6DSYxJgbNEz32iji0v+Mx1h4=;
        b=ZaC9qP2k0ellNrHC+xBqWHQkZ1QOoysAa/I8Rqs2WSfcdtZK7pY5ixNLFQzUAhyVoL
         qNU+gGg6CGJckPQZmLPYmQ4lYkQAOXX67tXjaZTKgfpQ5pbgWLKrFr1iR7PaDQeXqs5F
         shgRvwGFbXHluci/jhh2YLk3kvxSKHH2A7W5c93anPncNtQBs6Bl2WrKcsiYMLywyAe1
         tA1ROR3s9moajOOZatvtP3m7kN/y0Vc4Ra/AxTBo0ZX/zKIN0tgq2mQecEQt/fVPnTkg
         NxX8l+L7GbEHmVYC05537pxuJ/1S77qd2pyqMMBdE2xU47ZJcqzL4afef7uCpZEymAIj
         5vJQ==
X-Gm-Message-State: APjAAAVuXpKAcKVc1nelK2C6gUg4n90gM7ekVLiTLZLq3zq2Pn4tBdlp
	DLyH32fOsDWlfQQoc+YOrH8=
X-Google-Smtp-Source: APXvYqwJQX6gWdHe61xw5bVSGPJPQAd30BOvy0S2o+gKhK4BgIPZRpipD0BauoGWHUIw5QszwxkP4w==
X-Received: by 2002:a17:90a:b63:: with SMTP id 90mr12347827pjq.96.1570130841732;
        Thu, 03 Oct 2019 12:27:21 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:a704:: with SMTP id w4ls1767690plq.14.gmail; Thu, 03
 Oct 2019 12:27:21 -0700 (PDT)
X-Received: by 2002:a17:90a:2687:: with SMTP id m7mr12156681pje.25.1570130841157;
        Thu, 03 Oct 2019 12:27:21 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1570130841; cv=none;
        d=google.com; s=arc-20160816;
        b=WImPOVb/aHoau/1YlgNsURCEt0FqLj+srzMrlmjf3KsLcGg4IXZHY55fpgwH2ao/69
         gaT7II1POiOLT/bneUzGM8/RlBjejbbgoM6N9pkzowqt8elZh1AXCmPpWDesZTZgwzaL
         rNlv3Gg6mcTnPcgeCWaTSLDHHYySweOXZDclSPf3qCN77sPDdJ3ZpbyxnVRza7Uc7b6t
         Gx6FVFXHIaMgIeXfVZZ6qOwbfrLty4b2tanczWBVy+uq/1QrziFZL6YMI5CgPFiH+bJR
         PtZW1J+XpWLMZhV6r39PWOg3jwzxTGO0lG8hE/wY7KuU51177d3a758xuFodbHSEGxBt
         Cx7Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=52Mg07dQkN/KgqaFhPCi4LxnJtO5hzy5vEl2iOqJhXg=;
        b=MYMeXMkzskpR3nqD8uqnK03dBiYl5cxvKZ9CCy2xRJqvimz0P2AnEfjXfVGZmZyp84
         4kzdMGWpxvzAlPP86ab0kshbT0oCC8daZtVG8Wd6ssYfcTJpXN7YMeJxY81QYeR+suIa
         kfXcnLljzZ5P63rdWajl8s7xByoFphjCJBhfvJcfFfAYLu+gGv4NYxvY3wfLgQzob1A5
         2tQ8REq9Uuu5mkDIKwGXUyMfMWGotU/Msv9ReVmQWFmDMjt5laefyz8Ju6nmfyS6LrDp
         TicKBCW7Lg0KW71LQs172yZhyIYg4oOEIIkuK28Bo4Qr3CKX77i8XIbA8TlITjHqx462
         5OcQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Rl3XhvxB;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::244 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x244.google.com (mail-oi1-x244.google.com. [2607:f8b0:4864:20::244])
        by gmr-mx.google.com with ESMTPS id br8si544661pjb.3.2019.10.03.12.27.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 03 Oct 2019 12:27:21 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::244 as permitted sender) client-ip=2607:f8b0:4864:20::244;
Received: by mail-oi1-x244.google.com with SMTP id m16so3692485oic.5
        for <kasan-dev@googlegroups.com>; Thu, 03 Oct 2019 12:27:21 -0700 (PDT)
X-Received: by 2002:aca:4b85:: with SMTP id y127mr4144838oia.70.1570130839954;
 Thu, 03 Oct 2019 12:27:19 -0700 (PDT)
MIME-Version: 1.0
References: <CANpmjNPJ_bHjfLZCAPV23AXFfiPiyXXqqu72n6TgWzb2Gnu1eA@mail.gmail.com>
 <20190920163123.GC55224@lakrids.cambridge.arm.com> <CACT4Y+ZwyBhR8pB7jON8eVObCGbJ54L8Sbz6Wfmy3foHkPb_fA@mail.gmail.com>
 <CANpmjNM+aEzySwuMDkEvsVaeTooxExuTRAv-nzjhp7npT8a3ag@mail.gmail.com> <20191003161233.GB38140@lakrids.cambridge.arm.com>
In-Reply-To: <20191003161233.GB38140@lakrids.cambridge.arm.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 3 Oct 2019 21:27:08 +0200
Message-ID: <CANpmjNMBehv0UUuEko-F-ygegX+YS+Km3ggFB0tnBoCpRRXhSw@mail.gmail.com>
Subject: Re: Kernel Concurrency Sanitizer (KCSAN)
To: Mark Rutland <mark.rutland@arm.com>
Cc: Dmitry Vyukov <dvyukov@google.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	LKML <linux-kernel@vger.kernel.org>, Andrey Konovalov <andreyknvl@google.com>, 
	Alexander Potapenko <glider@google.com>, "Paul E. McKenney" <paulmck@linux.ibm.com>, Paul Turner <pjt@google.com>, 
	Daniel Axtens <dja@axtens.net>, Anatol Pomazau <anatol@google.com>, Will Deacon <willdeacon@google.com>, 
	Andrea Parri <parri.andrea@gmail.com>, Alan Stern <stern@rowland.harvard.edu>, 
	LKMM Maintainers -- Akira Yokosawa <akiyks@gmail.com>, Nicholas Piggin <npiggin@gmail.com>, Boqun Feng <boqun.feng@gmail.com>, 
	Daniel Lustig <dlustig@nvidia.com>, Jade Alglave <j.alglave@ucl.ac.uk>, 
	Luc Maranget <luc.maranget@inria.fr>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=Rl3XhvxB;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::244 as
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

On Thu, 3 Oct 2019 at 18:12, Mark Rutland <mark.rutland@arm.com> wrote:
>
> On Fri, Sep 20, 2019 at 07:51:04PM +0200, Marco Elver wrote:
> > On Fri, 20 Sep 2019 at 18:47, Dmitry Vyukov <dvyukov@google.com> wrote:
> > >
> > > On Fri, Sep 20, 2019 at 6:31 PM Mark Rutland <mark.rutland@arm.com> wrote:
> > > >
> > > > On Fri, Sep 20, 2019 at 04:18:57PM +0200, Marco Elver wrote:
> > > > > We would like to share a new data-race detector for the Linux kernel:
> > > > > Kernel Concurrency Sanitizer (KCSAN) --
> > > > > https://github.com/google/ktsan/wiki/KCSAN  (Details:
> > > > > https://github.com/google/ktsan/blob/kcsan/Documentation/dev-tools/kcsan.rst)
> > > >
> > > > Nice!
> > > >
> > > > BTW kcsan_atomic_next() is missing a stub definition in <linux/kcsan.h>
> > > > when !CONFIG_KCSAN:
> > > >
> > > > https://github.com/google/ktsan/commit/a22a093a0f0d0b582c82cdbac4f133a3f61d207c#diff-19d7c475b4b92aab8ba440415ab786ec
> > > >
> > > > ... and I think the kcsan_{begin,end}_atomic() stubs need to be static
> > > > inline too.
> >
> > Thanks for catching, fixed and pushed. Feel free to rebase your arm64 branch.
>
> Great; I've just done so!
>
> What's the plan for posting a PATCH or RFC series?

I'm planning to send some patches, but with the amount of data-races
being found I need to prioritize what we send first. Currently the
plan is to let syzbot find data-races, and we'll start by sending a
few critical reports that syzbot found. Syzbot should be set up fully
and start finding data-races within next few days.

> The rest of this email is rabbit-holing on the issue KCSAN spotted;
> sorry about that!

Thanks for looking into this! I think you're right, and please do feel
free to send a proper patch out.

Thanks,
-- Marco

> [...]
>
> > > > We have some interesting splats at boot time in stop_machine, which
> > > > don't seem to have been hit/fixed on x86 yet in the kcsan-with-fixes
> > > > branch, e.g.
> > > >
> > > > [    0.237939] ==================================================================
> > > > [    0.239431] BUG: KCSAN: data-race in multi_cpu_stop+0xa8/0x198 and set_state+0x80/0xb0
> > > > [    0.241189]
> > > > [    0.241606] write to 0xffff00001003bd00 of 4 bytes by task 24 on cpu 3:
> > > > [    0.243435]  set_state+0x80/0xb0
> > > > [    0.244328]  multi_cpu_stop+0x16c/0x198
> > > > [    0.245406]  cpu_stopper_thread+0x170/0x298
> > > > [    0.246565]  smpboot_thread_fn+0x40c/0x560
> > > > [    0.247696]  kthread+0x1a8/0x1b0
> > > > [    0.248586]  ret_from_fork+0x10/0x18
> > > > [    0.249589]
> > > > [    0.250006] read to 0xffff00001003bd00 of 4 bytes by task 14 on cpu 1:
> > > > [    0.251804]  multi_cpu_stop+0xa8/0x198
> > > > [    0.252851]  cpu_stopper_thread+0x170/0x298
> > > > [    0.254008]  smpboot_thread_fn+0x40c/0x560
> > > > [    0.255135]  kthread+0x1a8/0x1b0
> > > > [    0.256027]  ret_from_fork+0x10/0x18
> > > > [    0.257036]
> > > > [    0.257449] Reported by Kernel Concurrency Sanitizer on:
> > > > [    0.258918] CPU: 1 PID: 14 Comm: migration/1 Not tainted 5.3.0-00007-g67ab35a199f4-dirty #3
> > > > [    0.261241] Hardware name: linux,dummy-virt (DT)
> > > > [    0.262517] ==================================================================>
> >
> > Thanks, the fixes in -with-fixes were ones I only encountered with
> > Syzkaller, where I disable KCSAN during boot. I've just added a fix
> > for this race and pushed to kcsan-with-fixes.
>
> I think that's:
>
>   https://github.com/google/ktsan/commit/c1bc8ab013a66919d8347c2392f320feabb14f92
>
> ... but that doesn't look quite right to me, as it leaves us with the shape:
>
>         do {
>                 if (READ_ONCE(msdata->state) != curstate) {
>                         curstate = msdata->state;
>                         switch (curstate) {
>                                 ...
>                         }
>                         ack_state(msdata);
>                 }
>         } while (curstate != MULTI_STOP_EXIT);
>
> I don't believe that we have a guarantee of read-after-read ordering
> between the READ_ONCE(msdata->state) and the subsequent plain access of
> msdata->state, as we've been caught out on that in the past, e.g.
>
>   https://lore.kernel.org/lkml/1506527369-19535-1-git-send-email-will.deacon@arm.com/
>
> ... which I think means we could switch on a stale value of
> msdata->state. That would mean we might handle the same state twice,
> calling ack_state() more times than expected and corrupting the count.
>
> The compiler could also replace uses of curstate with a reload of
> msdata->state. If it did so for the while condition, we could skip the
> expected ack_state() for MULTI_STOP_EXIT, though it looks like that
> might not matter.
>
> I think we need to make sure that we use a consistent snapshot,
> something like the below. Assuming I'm not barking up the wrong tree, I
> can spin this as a proper patch.
>
> Thanks,
> Mark.
>
> ---->8----
> diff --git a/kernel/stop_machine.c b/kernel/stop_machine.c
> index b4f83f7bdf86..67a0b454b5b5 100644
> --- a/kernel/stop_machine.c
> +++ b/kernel/stop_machine.c
> @@ -167,7 +167,7 @@ static void set_state(struct multi_stop_data *msdata,
>         /* Reset ack counter. */
>         atomic_set(&msdata->thread_ack, msdata->num_threads);
>         smp_wmb();
> -       msdata->state = newstate;
> +       WRITE_ONCE(msdata->state, newstate);
>  }
>
>  /* Last one to ack a state moves to the next state. */
> @@ -186,7 +186,7 @@ void __weak stop_machine_yield(const struct cpumask *cpumask)
>  static int multi_cpu_stop(void *data)
>  {
>         struct multi_stop_data *msdata = data;
> -       enum multi_stop_state curstate = MULTI_STOP_NONE;
> +       enum multi_stop_state newstate, curstate = MULTI_STOP_NONE;
>         int cpu = smp_processor_id(), err = 0;
>         const struct cpumask *cpumask;
>         unsigned long flags;
> @@ -210,8 +210,9 @@ static int multi_cpu_stop(void *data)
>         do {
>                 /* Chill out and ensure we re-read multi_stop_state. */
>                 stop_machine_yield(cpumask);
> -               if (msdata->state != curstate) {
> -                       curstate = msdata->state;
> +               newstate = READ_ONCE(msdata->state);
> +               if (newstate != curstate) {
> +                       curstate = newstate;
>                         switch (curstate) {
>                         case MULTI_STOP_DISABLE_IRQ:
>                                 local_irq_disable();
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMBehv0UUuEko-F-ygegX%2BYS%2BKm3ggFB0tnBoCpRRXhSw%40mail.gmail.com.
