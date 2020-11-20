Return-Path: <kasan-dev+bncBDV37XP3XYDRBT5V336QKGQEBIFRWUA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x739.google.com (mail-qk1-x739.google.com [IPv6:2607:f8b0:4864:20::739])
	by mail.lfdr.de (Postfix) with ESMTPS id 03D022BA776
	for <lists+kasan-dev@lfdr.de>; Fri, 20 Nov 2020 11:30:41 +0100 (CET)
Received: by mail-qk1-x739.google.com with SMTP id x85sf7443283qka.14
        for <lists+kasan-dev@lfdr.de>; Fri, 20 Nov 2020 02:30:40 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605868240; cv=pass;
        d=google.com; s=arc-20160816;
        b=s+KdnznNZ158hjEpvvmyZnx9Jzfg0xIJEAhOojLzu4tsEa/PKXWdCy9aM+l8i4JYQe
         5mTjh4K9lv1j4ZKHi9uk0/8PhJy+ZYheqAwU2yXU2xwBXZJa147rIowobLaJ1ju+2UY8
         BAfAI6pPMM/2Vo1dBbRoAmbMyBuPin0ShQHinfCLREKt3XxuU9UmtOPsslks36dETiSa
         eH+w/tUn1ZJkf+8ZCDTs2N88afPKpyaiJut/mIDpWk7ExyJlq+THVDVJGFyzKCGbGnxI
         pHlkC2HtVO2F/bsbHtv1qdR3kd2tB29tQAzATor3zRp/GXG+tVQ4ve1wBGuE+zW/CnZr
         lrQg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=OePKw0vM3KuJjCaEZ04UE7jEqfUcBAXxXS1YXZwXNkg=;
        b=DAFS59aVX8VEJhZo5hr0SbMEYxbxWZTY/lWWqZqgSrrg6s1to9xic2tBZju1r9bvcm
         DDrrHjzv5T/ADQ0kiPGZaT8lLcqZJyKWsaADY/I5hL488ODwAk7FEgEnQQm8k8YYwOCi
         Ukf4T/ryORdFDQzz5eKf1ztwp/rhI/KZGlUVEsDLc7F9eidd30vMuzXpaSTGyC9V/uuH
         5tf/PtEqpvHe7Y/U1+jT+/tDGheKv23Wfo1zvAT6yI7hJ3rtcK4PauEjjIfHf2kMVi3O
         G/rE4w4lqdogK7+PK6PVF/ck1GaqaSn0cchDV6BOB+rUH/TPQ6mcCyb/3PIQUJwemOYD
         a8ug==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=OePKw0vM3KuJjCaEZ04UE7jEqfUcBAXxXS1YXZwXNkg=;
        b=JM6RqsIWPe/ngUi4dv8uwvnsPNKiJ/C7PTskileyvW4UZwQ/Jow7e3r9cW8Bt3EXYq
         IsFp2kt3wW8ArMJ65+x/0craeTHzyYY6D0S8yq0GpwJrRVWvk4SXsvggkB2nYrXl+0lH
         FsjIW6mh0SPdobyILHg9R/7003tik7ZxzqQf4C65BQ9IAQ9DAAQFrBa6eK5HKWVBKyf3
         Xx/o1tj2PubMvCYCqtU8NJ9YINGZIBR5HIOEM3ZjjX5rfKfLh/ASNy3B5ELnDxor0ewk
         rbxDDYEftmPDMN8EYp9M+W7hVqOIqhBjEElrvDf2/ELAJ6nksxsxQLkV8ITc9QWI8mL+
         +7iQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=OePKw0vM3KuJjCaEZ04UE7jEqfUcBAXxXS1YXZwXNkg=;
        b=WpKwSWm87ytgaxERv6OL54vsiR9nGptHTKMDNJCmUGg1BmozrX1fXngt6I2RYYecO/
         1nFgcrhAxpmizqM729xf3P6QQTE1A49K7RfLx5L1kP4hX7Q/nFdQPN7dQ9Ux++XxAgYZ
         hfWNY94C3OrUmKzFteUzLAv2tipEDi3zZhv6HRQGLzaKCZRdMnmNS4JHt8h9/cWhdWB/
         IoiWmHfTbUexzkz6wEvyGwa9Mxq35PvGmrAf5CuXqbue5Nfglsvf8mHsrMuc4RirUiId
         mvqD4KMOmfWmuCE7S/dxvNjR2OVaY+et9S9JmGqMVsDTIGfo9eE95WZ0I8PAeZLO45Ko
         +kEA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531exH53mc7b+//LfMOvCejDfYiVU/5dqDq8kmF/BLLnIQyFu6Uf
	6Bxa7H3PWWsat68JGvf5FFE=
X-Google-Smtp-Source: ABdhPJwMPuj4GyoyMI3DY/XOSHwLYbT6vSX33dsafnd23K1WJzQy+TTPkmVtQogU3jM1GmMWtR7jEQ==
X-Received: by 2002:a37:809:: with SMTP id 9mr15562260qki.191.1605868239689;
        Fri, 20 Nov 2020 02:30:39 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:776d:: with SMTP id h13ls2214257qtu.7.gmail; Fri, 20 Nov
 2020 02:30:39 -0800 (PST)
X-Received: by 2002:ac8:57cb:: with SMTP id w11mr15619108qta.251.1605868239212;
        Fri, 20 Nov 2020 02:30:39 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605868239; cv=none;
        d=google.com; s=arc-20160816;
        b=lQecsLJBVRWRD84SLlBIhxsKQVf30NN4hOaO5caIGxsQcXNTPzrLmJ5Tg9kOeairPI
         uAhRh6HDMGv2/CDYCa/syteNJ/ZKTF//6VFd9vA3eXIkkBbFWaUJjhRY3qdSN3fxjLOS
         X/8TaqiPXyc2NeYfkVzv5jRWI5Tfkyfh0kABy1PsE6xE0w2KqB9oQT8GSmO/aVzRVdU7
         6wp5xNjiNqwCqhLj+dT28uFtLX2vqYWU4MlprMgrFPAS4NhoWcvZ3ZiqIx2tb4Jevz9w
         3902pSoGtxEC0At37MyDNnSKBrmQbqvIF3fmGgfXgK/vBxMSq82B56UDtPaleXQ4ASEz
         CZig==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=TRDIkQtEvZkyNfCFLKGuex2IhHfSiw5WfCCpqIdIhmo=;
        b=jFMfc4m6z5Q9JBqibpsLFpJeY4LcvyW+qbGHPLnncJ/rJcejpQ1sNuA6BAJgOrCC0x
         VBvM+hhjWEeK5+GmDeBf+HOzBNKUWpGy40y5+SZ41XQB8P6WYA7zbLdczODoZxMutn0A
         rG7pLdOhiuds+7G1SJeOBhjr2hstiV53eBC7EXvbq4tqL0wlBSQj+H5bcjLSd+xK8qf7
         sKhJU/p/mq1eaElQMfRP+TgFZEdyEBW4Zf98HRVEhNC3YHaqofH5ks7SPE3lxnRR5Deb
         jgvrVCT7VZa3ap1q2S53QmucvmskB1wgQOMPrK2qTafJomFy4DmBDqY03tvj3XLrL17s
         RhSw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id a190si219039qke.6.2020.11.20.02.30.39
        for <kasan-dev@googlegroups.com>;
        Fri, 20 Nov 2020 02:30:39 -0800 (PST)
Received-SPF: pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 6C0C21042;
	Fri, 20 Nov 2020 02:30:38 -0800 (PST)
Received: from C02TD0UTHF1T.local (unknown [10.57.27.176])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id AAB813F70D;
	Fri, 20 Nov 2020 02:30:34 -0800 (PST)
Date: Fri, 20 Nov 2020 10:30:31 +0000
From: Mark Rutland <mark.rutland@arm.com>
To: Will Deacon <will@kernel.org>
Cc: "Paul E. McKenney" <paulmck@kernel.org>, Marco Elver <elver@google.com>,
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
Message-ID: <20201120103031.GB2328@C02TD0UTHF1T.local>
References: <20201117182915.GM1437@paulmck-ThinkPad-P72>
 <20201118225621.GA1770130@elver.google.com>
 <20201118233841.GS1437@paulmck-ThinkPad-P72>
 <20201119125357.GA2084963@elver.google.com>
 <20201119151409.GU1437@paulmck-ThinkPad-P72>
 <20201119170259.GA2134472@elver.google.com>
 <20201119184854.GY1437@paulmck-ThinkPad-P72>
 <20201119193819.GA2601289@elver.google.com>
 <20201119213512.GB1437@paulmck-ThinkPad-P72>
 <20201119225352.GA5251@willie-the-truck>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20201119225352.GA5251@willie-the-truck>
X-Original-Sender: mark.rutland@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as
 permitted sender) smtp.mailfrom=mark.rutland@arm.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=arm.com
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

On Thu, Nov 19, 2020 at 10:53:53PM +0000, Will Deacon wrote:
> On Thu, Nov 19, 2020 at 01:35:12PM -0800, Paul E. McKenney wrote:
> > On Thu, Nov 19, 2020 at 08:38:19PM +0100, Marco Elver wrote:
> > > On Thu, Nov 19, 2020 at 10:48AM -0800, Paul E. McKenney wrote:
> > > > On Thu, Nov 19, 2020 at 06:02:59PM +0100, Marco Elver wrote:
> > 
> > [ . . . ]
> > 
> > > > > I can try bisection again, or reverting some commits that might be
> > > > > suspicious? But we'd need some selection of suspicious commits.
> > > > 
> > > > The report claims that one of the rcu_node ->lock fields is held
> > > > with interrupts enabled, which would indeed be bad.  Except that all
> > > > of the stack traces that it shows have these locks held within the
> > > > scheduling-clock interrupt handler.  Now with the "rcu: Don't invoke
> > > > try_invoke_on_locked_down_task() with irqs disabled" but without the
> > > > "sched/core: Allow try_invoke_on_locked_down_task() with irqs disabled"
> > > > commit, I understand why.  With both, I don't see how this happens.
> > > 
> > > I'm at a loss, but happy to keep bisecting and trying patches. I'm also
> > > considering:
> > > 
> > > 	Is it the compiler? Probably not, I tried 2 versions of GCC.
> > > 
> > > 	Can we trust lockdep to precisely know IRQ state? I know there's
> > > 	been some recent work around this, but hopefully we're not
> > > 	affected here?
> > > 
> > > 	Is QEMU buggy?
> > > 
> > > > At this point, I am reduced to adding lockdep_assert_irqs_disabled()
> > > > calls at various points in that code, as shown in the patch below.
> > > > 
> > > > At this point, I would guess that your first priority would be the
> > > > initial bug rather than this following issue, but you never know, this
> > > > might well help diagnose the initial bug.
> > > 
> > > I don't mind either way. I'm worried deadlocking the whole system might
> > > be worse.
> > 
> > Here is another set of lockdep_assert_irqs_disabled() calls on the
> > off-chance that they actually find something.
> 
> FWIW, arm64 is known broken wrt lockdep and irq tracing atm. Mark has been
> looking at that and I think he is close to having something workable.
> 
> Mark -- is there anything Marco and Paul can try out?

I initially traced some issues back to commit:

  044d0d6de9f50192 ("lockdep: Only trace IRQ edges")

... and that change of semantic could cause us to miss edges in some
cases, but IIUC mostly where we haven't done the right thing in
exception entry/return.

I don't think my patches address this case yet, but my WIP (currently
just fixing user<->kernel transitions) is at:

https://git.kernel.org/pub/scm/linux/kernel/git/mark/linux.git/log/?h=arm64/irq-fixes

I'm looking into the kernel<->kernel transitions now, and I know that we
mess up RCU management for a small window around arch_cpu_idle, but it's
not immediately clear to me if either of those cases could cause this
report.

Thanks,
Mark.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201120103031.GB2328%40C02TD0UTHF1T.local.
