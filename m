Return-Path: <kasan-dev+bncBDV37XP3XYDRB6V33DWAKGQEJRIMHDY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23f.google.com (mail-lj1-x23f.google.com [IPv6:2a00:1450:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id D02E2CA2E2
	for <lists+kasan-dev@lfdr.de>; Thu,  3 Oct 2019 18:12:42 +0200 (CEST)
Received: by mail-lj1-x23f.google.com with SMTP id h19sf1024422ljc.5
        for <lists+kasan-dev@lfdr.de>; Thu, 03 Oct 2019 09:12:42 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1570119162; cv=pass;
        d=google.com; s=arc-20160816;
        b=bBufkebrv2j1jdet5FHA3wAm7ort3wHJ3H0E+QNM70+BTgDkWzXRAVSggBgfeZc71f
         znlqiwqHp9nyRh+F5l40l30WjIfdRN4F9vkfD0MjRrEVQmkNiL+It+7ur3VsNanfaV5w
         CdLcTCzkHHLy9pbi0fZsXePDBq/St1Y2qbjtFU0luImQZG+mVoLB4N1QVL3pZtSIB6ze
         Lzlep+jSMYzgW9SNQyeRreTDa1vzRd9ziQe8g79NYk4akjCeL2BDGH9t8oiZe4akyLQC
         r3HdFwEm5ARvxeWcFAyTMyWbakppAecM3Hn5PbifzSp3pBJwdInemT8MJsY7kAru3VK3
         l7YA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=Uv3lU/18374PpOu8FrAZNosF5zzBPU2j+jCQX8bwuXQ=;
        b=TZEn458xgHqyyMEa1pGedqAGG55S/7/pwpML3HD1cJXxGxc1BKwBthLVvRpnqD6BP0
         2pUITyxPWatbLr6NH3JO0fYl4SyC+RQ0wFN15BlY0Ol8DN6thSp2SLkDgXMBsBwfglVt
         pKti92Q6REHrEg4lm49Cc0zRvfeacCc5vCW4ixK703I1xBzHtPhhfu6J47eFuCuixj/7
         qK9RVyIJKRPE2aShMXX74VeIS5Xsa65ovp0PPTlwlSP/FGv15gbiRrKUwLYjZpOXZzxY
         uwtHpH6jDMG3zigVMy08WzGevCHXY2kk9TsuGr6LXcbd9sygu1ExMt3TigVhIcGVqqGy
         Lurg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: best guess record for domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Uv3lU/18374PpOu8FrAZNosF5zzBPU2j+jCQX8bwuXQ=;
        b=slkS8b1cA5CG4OhQbqpg8y8H93ZQ0i8ZlU1DfunCX6EL0uywn88VslCA5OVyNECmDa
         2Qg6CwEcbuxoNdvCMqudguc2LBwwg+kjDbPBZZvfdyLvEhg7m2QOzSFOnt178/38Pwb+
         tKzmk8l6TsGYx8E3PBOqwl4No+qVPQdKe7yYjQnXPBJcUYy1KSzIuRwPuRM8jx9lQ3vQ
         9eFPMZM/0dJCsPNIqmCuqA2LLaRJxJS49Tvz34nFaqeBjg0O5bHb4Ny82CGenUf4tke8
         pArw9MGYwXE/1gW4NrRKKPtA7OVBYHtD2rVAnhyy/ymPimF1Mnn/52x7RXJhilMDqBzZ
         /nvg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=Uv3lU/18374PpOu8FrAZNosF5zzBPU2j+jCQX8bwuXQ=;
        b=E7XFoCD9Gfv6BV6gKsBOsQbgWiK6rgq6NjyEF+BmX3gcxWDbHVPvIeuZ+iy/GWZWDE
         4kzdYhXLixOrrkbRwFUgAuSnSHqSuG0OSHxiw1iCITFYApT12WNMYHgii90wS3CdswdP
         zAwt4hA0FIM/sZPCeBYyclcpiUuIdaXg3dGDF/y+2+owSXtkorKBmOtiKnSeeFVyt70/
         4Radgkb65LMiO5uqC+l2Hq4Fa7OaJQsbZS5yPbVz+xVr31u/jJiMibl2ElQB9sQnUUh9
         8ngQXhgNCOzN1BV79pbPdyDIAUyc9aRD9xQup4O2yUK9NDjGLp7jtDwU6rwtH3M/CndY
         Rw5g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVHZgLWHHVcB6WoDKVCYr57Sl0JgazdbBC7npwR0ctSVvv9OLoz
	z12oj29pXIcJPNmUqsAvP38=
X-Google-Smtp-Source: APXvYqy0jKDN7rOk7dXXZ1jweyCKQ64yux4WchXEROcdigiTAD1Nthxe6319awBgIbxrkQbsG3yCzA==
X-Received: by 2002:a05:651c:1102:: with SMTP id d2mr6772127ljo.74.1570119162200;
        Thu, 03 Oct 2019 09:12:42 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:7d02:: with SMTP id y2ls900210ljc.8.gmail; Thu, 03 Oct
 2019 09:12:41 -0700 (PDT)
X-Received: by 2002:a2e:9b5a:: with SMTP id o26mr6685583ljj.158.1570119161461;
        Thu, 03 Oct 2019 09:12:41 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1570119161; cv=none;
        d=google.com; s=arc-20160816;
        b=k4seMhE4ivEmRcpRl5/1TUl4+mO3EuufV+TWeBC+N9xXrr+5syRuUr6jjr96QCbwqI
         iUPzRKWcjKK049GqzdOvqzV9dkqtdDHA4MpljZhjWQAv3D7aV9WKuqva2fn1r/LIxWQo
         t8KPDjv0iEpf6s6dNrN2dMUc1rIjZUU9IdWxKiNoZvAww1pzmf7F/8/Cyy/T1o3/6mp9
         msHcqc2cnaSGerjtUtwNHUEKUFGnfEiB+2NAW2dVu+izsRKGX4G8qGN2xOAMdMUqtNST
         T79Nrz+QeEApXRNMBhXFa84CRVm+8Ac8E026ao87qyGSvQKkxogZgM4+xJIgmqqZvDiX
         lbdA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=0xNfNSbNCptreVe7DnPLWvu9hM4RIr82+U+CLE0psnI=;
        b=Ea0MPzURVPGHdHybkS8DlkbWJLq7Hz38En++PqAu9NezJUaFaqukD1YzKXb93IFICA
         VfbPlwxwMpq96Rw7mNQE4RuYwAKHWIelJ7+QqhrG7CkKOTw2gXRt53tpfVuhwo51TNZx
         NbgZsbhg87JSTjMlMt8PbiyKMKB9dlfhZb7unxcwWDUcCjRAHmRiDcopLJOAtc79kDh6
         y7J5S814igoKd62GN1tIBozOM4GfNhG2cQ/v1ZdoelHF4Rvy8nZqMJ3nplljvXfK1fr6
         eutz1UkGuHsZvWw2rWaOfG98Z31anFN8PiKPA9vXg4DSUc8HBiEAhN5nb8QDY/gWQTrp
         tthQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: best guess record for domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id y6si232781lji.0.2019.10.03.09.12.40
        for <kasan-dev@googlegroups.com>;
        Thu, 03 Oct 2019 09:12:40 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 0D4C8337;
	Thu,  3 Oct 2019 09:12:39 -0700 (PDT)
Received: from lakrids.cambridge.arm.com (usa-sjc-imap-foss1.foss.arm.com [10.121.207.14])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id A91493F739;
	Thu,  3 Oct 2019 09:12:36 -0700 (PDT)
Date: Thu, 3 Oct 2019 17:12:34 +0100
From: Mark Rutland <mark.rutland@arm.com>
To: Marco Elver <elver@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	LKML <linux-kernel@vger.kernel.org>,
	Andrey Konovalov <andreyknvl@google.com>,
	Alexander Potapenko <glider@google.com>,
	"Paul E. McKenney" <paulmck@linux.ibm.com>,
	Paul Turner <pjt@google.com>, Daniel Axtens <dja@axtens.net>,
	Anatol Pomazau <anatol@google.com>,
	Will Deacon <willdeacon@google.com>,
	Andrea Parri <parri.andrea@gmail.com>,
	Alan Stern <stern@rowland.harvard.edu>,
	LKMM Maintainers -- Akira Yokosawa <akiyks@gmail.com>,
	Nicholas Piggin <npiggin@gmail.com>,
	Boqun Feng <boqun.feng@gmail.com>,
	Daniel Lustig <dlustig@nvidia.com>,
	Jade Alglave <j.alglave@ucl.ac.uk>,
	Luc Maranget <luc.maranget@inria.fr>
Subject: Re: Kernel Concurrency Sanitizer (KCSAN)
Message-ID: <20191003161233.GB38140@lakrids.cambridge.arm.com>
References: <CANpmjNPJ_bHjfLZCAPV23AXFfiPiyXXqqu72n6TgWzb2Gnu1eA@mail.gmail.com>
 <20190920163123.GC55224@lakrids.cambridge.arm.com>
 <CACT4Y+ZwyBhR8pB7jON8eVObCGbJ54L8Sbz6Wfmy3foHkPb_fA@mail.gmail.com>
 <CANpmjNM+aEzySwuMDkEvsVaeTooxExuTRAv-nzjhp7npT8a3ag@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNM+aEzySwuMDkEvsVaeTooxExuTRAv-nzjhp7npT8a3ag@mail.gmail.com>
User-Agent: Mutt/1.11.1+11 (2f07cb52) (2018-12-01)
X-Original-Sender: mark.rutland@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: best guess record for domain of mark.rutland@arm.com designates
 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com
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

On Fri, Sep 20, 2019 at 07:51:04PM +0200, Marco Elver wrote:
> On Fri, 20 Sep 2019 at 18:47, Dmitry Vyukov <dvyukov@google.com> wrote:
> >
> > On Fri, Sep 20, 2019 at 6:31 PM Mark Rutland <mark.rutland@arm.com> wrote:
> > >
> > > On Fri, Sep 20, 2019 at 04:18:57PM +0200, Marco Elver wrote:
> > > > We would like to share a new data-race detector for the Linux kernel:
> > > > Kernel Concurrency Sanitizer (KCSAN) --
> > > > https://github.com/google/ktsan/wiki/KCSAN  (Details:
> > > > https://github.com/google/ktsan/blob/kcsan/Documentation/dev-tools/kcsan.rst)
> > >
> > > Nice!
> > >
> > > BTW kcsan_atomic_next() is missing a stub definition in <linux/kcsan.h>
> > > when !CONFIG_KCSAN:
> > >
> > > https://github.com/google/ktsan/commit/a22a093a0f0d0b582c82cdbac4f133a3f61d207c#diff-19d7c475b4b92aab8ba440415ab786ec
> > >
> > > ... and I think the kcsan_{begin,end}_atomic() stubs need to be static
> > > inline too.
> 
> Thanks for catching, fixed and pushed. Feel free to rebase your arm64 branch.

Great; I've just done so!

What's the plan for posting a PATCH or RFC series?

The rest of this email is rabbit-holing on the issue KCSAN spotted;
sorry about that!

[...]

> > > We have some interesting splats at boot time in stop_machine, which
> > > don't seem to have been hit/fixed on x86 yet in the kcsan-with-fixes
> > > branch, e.g.
> > >
> > > [    0.237939] ==================================================================
> > > [    0.239431] BUG: KCSAN: data-race in multi_cpu_stop+0xa8/0x198 and set_state+0x80/0xb0
> > > [    0.241189]
> > > [    0.241606] write to 0xffff00001003bd00 of 4 bytes by task 24 on cpu 3:
> > > [    0.243435]  set_state+0x80/0xb0
> > > [    0.244328]  multi_cpu_stop+0x16c/0x198
> > > [    0.245406]  cpu_stopper_thread+0x170/0x298
> > > [    0.246565]  smpboot_thread_fn+0x40c/0x560
> > > [    0.247696]  kthread+0x1a8/0x1b0
> > > [    0.248586]  ret_from_fork+0x10/0x18
> > > [    0.249589]
> > > [    0.250006] read to 0xffff00001003bd00 of 4 bytes by task 14 on cpu 1:
> > > [    0.251804]  multi_cpu_stop+0xa8/0x198
> > > [    0.252851]  cpu_stopper_thread+0x170/0x298
> > > [    0.254008]  smpboot_thread_fn+0x40c/0x560
> > > [    0.255135]  kthread+0x1a8/0x1b0
> > > [    0.256027]  ret_from_fork+0x10/0x18
> > > [    0.257036]
> > > [    0.257449] Reported by Kernel Concurrency Sanitizer on:
> > > [    0.258918] CPU: 1 PID: 14 Comm: migration/1 Not tainted 5.3.0-00007-g67ab35a199f4-dirty #3
> > > [    0.261241] Hardware name: linux,dummy-virt (DT)
> > > [    0.262517] ==================================================================>
> 
> Thanks, the fixes in -with-fixes were ones I only encountered with
> Syzkaller, where I disable KCSAN during boot. I've just added a fix
> for this race and pushed to kcsan-with-fixes.

I think that's:

  https://github.com/google/ktsan/commit/c1bc8ab013a66919d8347c2392f320feabb14f92

... but that doesn't look quite right to me, as it leaves us with the shape:

	do {
		if (READ_ONCE(msdata->state) != curstate) {
			curstate = msdata->state;
			switch (curstate) {
				...
			}
			ack_state(msdata);
		}
	} while (curstate != MULTI_STOP_EXIT);

I don't believe that we have a guarantee of read-after-read ordering
between the READ_ONCE(msdata->state) and the subsequent plain access of
msdata->state, as we've been caught out on that in the past, e.g.

  https://lore.kernel.org/lkml/1506527369-19535-1-git-send-email-will.deacon@arm.com/

... which I think means we could switch on a stale value of
msdata->state. That would mean we might handle the same state twice,
calling ack_state() more times than expected and corrupting the count.

The compiler could also replace uses of curstate with a reload of
msdata->state. If it did so for the while condition, we could skip the
expected ack_state() for MULTI_STOP_EXIT, though it looks like that
might not matter.

I think we need to make sure that we use a consistent snapshot,
something like the below. Assuming I'm not barking up the wrong tree, I
can spin this as a proper patch.

Thanks,
Mark.

---->8----
diff --git a/kernel/stop_machine.c b/kernel/stop_machine.c
index b4f83f7bdf86..67a0b454b5b5 100644
--- a/kernel/stop_machine.c
+++ b/kernel/stop_machine.c
@@ -167,7 +167,7 @@ static void set_state(struct multi_stop_data *msdata,
        /* Reset ack counter. */
        atomic_set(&msdata->thread_ack, msdata->num_threads);
        smp_wmb();
-       msdata->state = newstate;
+       WRITE_ONCE(msdata->state, newstate);
 }
 
 /* Last one to ack a state moves to the next state. */
@@ -186,7 +186,7 @@ void __weak stop_machine_yield(const struct cpumask *cpumask)
 static int multi_cpu_stop(void *data)
 {
        struct multi_stop_data *msdata = data;
-       enum multi_stop_state curstate = MULTI_STOP_NONE;
+       enum multi_stop_state newstate, curstate = MULTI_STOP_NONE;
        int cpu = smp_processor_id(), err = 0;
        const struct cpumask *cpumask;
        unsigned long flags;
@@ -210,8 +210,9 @@ static int multi_cpu_stop(void *data)
        do {
                /* Chill out and ensure we re-read multi_stop_state. */
                stop_machine_yield(cpumask);
-               if (msdata->state != curstate) {
-                       curstate = msdata->state;
+               newstate = READ_ONCE(msdata->state);
+               if (newstate != curstate) {
+                       curstate = newstate;
                        switch (curstate) {
                        case MULTI_STOP_DISABLE_IRQ:
                                local_irq_disable();

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191003161233.GB38140%40lakrids.cambridge.arm.com.
