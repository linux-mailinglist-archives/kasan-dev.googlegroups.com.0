Return-Path: <kasan-dev+bncBC7OBJGL2MHBB2MPWH6QKGQESCYEODY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x139.google.com (mail-lf1-x139.google.com [IPv6:2a00:1450:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id 94CB52AF9A5
	for <lists+kasan-dev@lfdr.de>; Wed, 11 Nov 2020 21:22:02 +0100 (CET)
Received: by mail-lf1-x139.google.com with SMTP id z19sf885875lfg.11
        for <lists+kasan-dev@lfdr.de>; Wed, 11 Nov 2020 12:22:02 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605126122; cv=pass;
        d=google.com; s=arc-20160816;
        b=zf0UnRadCbse82wpx22bZ4vVvkwuV8GOPnw28h5Vk35Y6C6tGP+DoUF3bZKXBBDgwt
         mPYfp3VPgPLXJ3gJAktVrJNVlvqM+h34aVswD/hiSUg5x3Up2EVAGumg2GgCuTeOR/eF
         sXrinF6KACaekxq2U9P8QP0hZKCmIo2yDsKPloV5HFJDqUHts44ms/k7FIUx17OKCggh
         wJ3IteHmEXEMuELpOZkpabw1aDp3Z+3PHzQhe9N2ddtE3DmbRVChlnjInIg2S9Dgf03p
         cfuvib3c7Cn9g0ZwlJ4MT2RN3IOwkKDkLE5YvxwyMmPThfpIcu94212yjDgnV9bhR1ia
         yhYg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=9UMCtAs0XJEAsb05t32HKfeHA46Exw/Nk09VC+R3308=;
        b=J2GE1Z6dvEdKq1V6gWrupWUrt7hBrpHDHkiiS7Kj7IGdYGhYoiJWtcIKTVo+7DZjQD
         BuFsUlalFXEcs1GDy/6MlHlLx1rAGex7K1ZXe7bI53WwniDA4lt/8cqwc3iaOf08RwAG
         DkGNRVClXLMeXvT0580cJQ5xCTyBGGG7uBLRTCTJyHYa2wis9MS5iA5kfqYOsvgKcOoj
         4Pi+BZ6L/QcXivi+ImRQuahfrCwgW9NQHxOu8ohmnRDxZaAqWZEri/oCahAUKj4EeSst
         xON0z+PT7+ufYjV4cc3r7o4JqKvy2bZ83OCwvg8kt+aF3BxpwXMfLwxarDvq9YS1zJUH
         5Dgw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=PynxXI+u;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::442 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=9UMCtAs0XJEAsb05t32HKfeHA46Exw/Nk09VC+R3308=;
        b=DuAgeD1liwh1D/v0SSo0RrJ7SlB/tSWGoEaOMSYMImLWdi/g/Na2sJl7yI66Fkbu6q
         KLzYmbA51vyM+UhTSPJIc0SnwB81Agi8JHhpvYeqCDI7Tvrz3GTTa25cJoyL2MWdDpG+
         L0WhtQ+g4Hp2/McwGZRw3DWsqco0Lv3shsV8Frk39BJdRDTP7cExQ1ZHteUUbiVscww4
         0xho5nSr0DV0nbrhVWtO6S8cxQyC7STR/gtLpO44XBCildxufAJ/vQ/zHTl4e3fQTwDx
         s9dXzyPVGzfy96LkeMSOHkovfnytLl1yBIJcuuX57c676H98rKzjwK53PPWpjNz+xNPx
         KLtA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=9UMCtAs0XJEAsb05t32HKfeHA46Exw/Nk09VC+R3308=;
        b=uVtrbNDkRowjx0bfWIcNmhjxEM2hNi5WG5aJdLhVW1fuzr8DR/9qEysa6Egk2pYnzR
         c+em7bwNcSkDXTtK7IY3/ml1ntf+XBc3YQuaxwPZuvb3xHfyzqXvOfIx3WTz4iYaF9GI
         onCZN8FbNsN6JT6fCCp3aRz9wJRZIhZchqXXw9cH50pu/4w1Y1qfKK1wZkIhnnwlRfyH
         bdEdUJZVJ8ttz/P7xS+JOsds61VMfxNyYjVAgls7PlXeJJbx478eo2+zoGqgMm8Vo7jp
         iZNYcyPj/XJ4nOfKWDkwUdSc63mgSoynPos1mDgy6aIh0ik8rV2zHCmd0kR4is1SiCUs
         pjDQ==
X-Gm-Message-State: AOAM530PYl1UWtZoLhT0/HSXKZGqb+mFAx7PQQTQ2RuNcebiOX7YrUid
	3jtIR1isAgnPR181Rk5UDe4=
X-Google-Smtp-Source: ABdhPJy1fdZP8z1oTKt/8G4ZC1lQIFjjWyNLiPZLzPMmk6+QRySQEMFLC+FwIQkHIsOEoZS5A1OyDw==
X-Received: by 2002:a19:7e53:: with SMTP id z80mr8433071lfc.250.1605126122131;
        Wed, 11 Nov 2020 12:22:02 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:b5b7:: with SMTP id f23ls136422ljn.2.gmail; Wed, 11 Nov
 2020 12:22:01 -0800 (PST)
X-Received: by 2002:a05:651c:1381:: with SMTP id k1mr10550713ljb.73.1605126120870;
        Wed, 11 Nov 2020 12:22:00 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605126120; cv=none;
        d=google.com; s=arc-20160816;
        b=UvniTSdXj1ugq2WL3SuUlffuLZ7D0Mrp9ez1Cn0ji7fKF873ziRNt9S9sXC6px77/u
         l/NpUcA05eOVRFN4dhopBanxM/fRQXS2nk4TNYFa0lUpsHbiyb0w9bbTylok51P84EXJ
         MWOPEAok/GhYOsR0hlEnWtnNS10pHyuSo4AR5QBS4Xpy634XbJ6NnKY3EhQgVuw5XFDt
         GIxyhOb1vrQfOVzaTC0VuRNFR3EORWj/hxQAq3EM+2iNyAlT4DD0Qkb+NMHow1GTSHUa
         reGkUlLR0aXiEIDCTLzkrmdVPgQtQ2ZnhKz4zHikTfhdaEn6nMg8y79LfmtHVu2+Oxhw
         W0Kg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=tsp9YKJhrqfgFKDZ1DBLBnXvo2iYEAgxpR7kKkNGbK0=;
        b=f2i+MKBjkxLL1dFPh82mrylU/gU96s7TaWm5D1UUwQgM6XOdcEXk3Lgw/4m2UjKcy/
         sBZJtnWK2hSnsGV5yYFQ4YSpUK57pjE0qxi4qYj2diDOHTewvLN1gntTAw0iv/argYc2
         kzSYeFdqkIL+t0/ntrWOBxpmotWo0cDoGEopTyWUdY2ERFpPZlWVpIOQg0YaKdtY8Amw
         Y9b+y8w1OCocR3O5RjKxYJtqex+hurqW8YZ/FvDjSkouI45cZSTRn+6PZXIH5sO/cOTs
         98+/syVDUtT14pRtyFjXrnzvewbjADYxy/gXsqpNXtmDjENnwOtc3oQ9Ipv8BTqcs6FP
         873A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=PynxXI+u;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::442 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x442.google.com (mail-wr1-x442.google.com. [2a00:1450:4864:20::442])
        by gmr-mx.google.com with ESMTPS id q11si83059lfo.8.2020.11.11.12.22.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 11 Nov 2020 12:22:00 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::442 as permitted sender) client-ip=2a00:1450:4864:20::442;
Received: by mail-wr1-x442.google.com with SMTP id k2so3802869wrx.2
        for <kasan-dev@googlegroups.com>; Wed, 11 Nov 2020 12:22:00 -0800 (PST)
X-Received: by 2002:adf:906b:: with SMTP id h98mr31484154wrh.310.1605126119972;
        Wed, 11 Nov 2020 12:21:59 -0800 (PST)
Received: from elver.google.com ([2a00:79e0:15:13:f693:9fff:fef4:2449])
        by smtp.gmail.com with ESMTPSA id u5sm3547921wml.13.2020.11.11.12.21.58
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 11 Nov 2020 12:21:59 -0800 (PST)
Date: Wed, 11 Nov 2020 21:21:53 +0100
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: "Paul E. McKenney" <paulmck@kernel.org>
Cc: Steven Rostedt <rostedt@goodmis.org>,
	Anders Roxell <anders.roxell@linaro.org>,
	Andrew Morton <akpm@linux-foundation.org>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>, Jann Horn <jannh@google.com>,
	Mark Rutland <mark.rutland@arm.com>,
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>,
	Linux-MM <linux-mm@kvack.org>,
	kasan-dev <kasan-dev@googlegroups.com>, rcu@vger.kernel.org,
	peterz@infradead.org
Subject: Re: [PATCH] kfence: Avoid stalling work queue task without
 allocations
Message-ID: <20201111202153.GT517454@elver.google.com>
References: <20201110135320.3309507-1-elver@google.com>
 <CADYN=9+=-ApMi_eEdAeHU6TyuQ7ZJSTQ8F-FCSD33kZH8HR+xg@mail.gmail.com>
 <CANpmjNM8MZphvkTSo=KgCBXQ6fNY4qo6NZD5SBHjNse_L9i5FQ@mail.gmail.com>
 <20201111133813.GA81547@elver.google.com>
 <20201111130543.27d29462@gandalf.local.home>
 <20201111182333.GA3249@paulmck-ThinkPad-P72>
 <20201111183430.GN517454@elver.google.com>
 <20201111192123.GB3249@paulmck-ThinkPad-P72>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20201111192123.GB3249@paulmck-ThinkPad-P72>
User-Agent: Mutt/1.14.6 (2020-07-11)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=PynxXI+u;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::442 as
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

On Wed, Nov 11, 2020 at 11:21AM -0800, Paul E. McKenney wrote:
[...]
> > >     rcu: Don't invoke try_invoke_on_locked_down_task() with irqs disabled
> > 
> > Sadly, no, next-20201110 already included that one, and that's what I
> > tested and got me all those warnings above.
> 
> Hey, I had to ask!  The only uncertainty I seee is the acquisition of
> the lock in rcu_iw_handler(), for which I add a lockdep check in the
> (untested) patch below.  The other thing I could do is sprinkle such
> checks through the stall-warning code on the assumption that something
> RCU is calling is enabling interrupts.
> 
> Other thoughts?
> 
> 							Thanx, Paul
> 
> ------------------------------------------------------------------------
> 
> diff --git a/kernel/rcu/tree_stall.h b/kernel/rcu/tree_stall.h
> index 70d48c5..3d67650 100644
> --- a/kernel/rcu/tree_stall.h
> +++ b/kernel/rcu/tree_stall.h
> @@ -189,6 +189,7 @@ static void rcu_iw_handler(struct irq_work *iwp)
>  
>  	rdp = container_of(iwp, struct rcu_data, rcu_iw);
>  	rnp = rdp->mynode;
> +	lockdep_assert_irqs_disabled();
>  	raw_spin_lock_rcu_node(rnp);
>  	if (!WARN_ON_ONCE(!rdp->rcu_iw_pending)) {
>  		rdp->rcu_iw_gp_seq = rnp->gp_seq;

This assert didn't fire yet, I just get more of the below. I'll keep
rerunning, but am not too hopeful...

Thanks,
-- Marco

| [...]
| [  125.854798] registered taskstats version 1
| [  125.857453] Running tests on all trace events:
| [  125.857830] Testing all events: OK
| [  166.950008] hrtimer: interrupt took 16803216 ns
| [  181.867305] Running tests again, along with the function tracer
| [  181.882932] Running tests on all trace events:
| [  181.894437] Testing all events: 
| [  415.596777] BUG: workqueue lockup - pool cpus=0 node=0 flags=0x0 nice=0 stuck for 34s!
| [  415.656078] Showing busy workqueues and worker pools:
| [  415.683616] workqueue events: flags=0x0
| [  415.692860]   pwq 0: cpus=0 node=0 flags=0x0 nice=0 active=1/256 refcnt=2
| [  415.710520]     pending: vmstat_shepherd
| [  415.735770] workqueue mm_percpu_wq: flags=0x8
| [  415.744135]   pwq 0: cpus=0 node=0 flags=0x0 nice=0 active=1/256 refcnt=2
| [  415.759123]     in-flight: 15:vmstat_update
| [  415.784113] pool 0: cpus=0 node=0 flags=0x0 nice=0 hung=34s workers=2 idle: 5
| [  510.976952] BUG: workqueue lockup - pool cpus=0 node=0 flags=0x0 nice=0 stuck for 31s!
| [  511.054367] Showing busy workqueues and worker pools:
| [  511.060173] workqueue events: flags=0x0
| [  511.083325]   pwq 0: cpus=0 node=0 flags=0x0 nice=0 active=2/256 refcnt=3
| [  511.093457]     in-flight: 15:vmstat_shepherd
| [  511.100300]     pending: free_work
| [  511.111488] workqueue events_power_efficient: flags=0x82
| [  511.141245]   pwq 2: cpus=0 flags=0x5 nice=0 active=3/256 refcnt=5
| [  511.151184]     in-flight: 7:check_lifetime
| [  511.157902]     pending: neigh_periodic_work, do_cache_clean
| [  511.171073] workqueue mm_percpu_wq: flags=0x8
| [  511.198620]   pwq 0: cpus=0 node=0 flags=0x0 nice=0 active=1/256 refcnt=2
| [  511.208715]     pending: vmstat_update
| [  511.227644] pool 0: cpus=0 node=0 flags=0x0 nice=0 hung=31s workers=2 idle: 5
| [  511.255656] pool 2: cpus=0 flags=0x5 nice=0 hung=19s workers=2 manager: 61
| [  544.063224] BUG: workqueue lockup - pool cpus=0 node=0 flags=0x0 nice=0 stuck for 64s!
| [  544.174957] Showing busy workqueues and worker pools:
| [  544.223112] workqueue events: flags=0x0
| [  544.250341]   pwq 0: cpus=0 node=0 flags=0x0 nice=0 active=2/256 refcnt=3
| [  544.260574]     in-flight: 15:vmstat_shepherd
| [  544.267433]     pending: free_work
| [  544.285271] workqueue mm_percpu_wq: flags=0x8
| [  544.290950]   pwq 0: cpus=0 node=0 flags=0x0 nice=0 active=1/256 refcnt=2
| [  544.301150]     pending: vmstat_update
| [  544.315536] pool 0: cpus=0 node=0 flags=0x0 nice=0 hung=64s workers=2 idle: 5
| [  544.339558] pool 2: cpus=0 flags=0x5 nice=0 hung=5s workers=2 manager: 61 idle: 7
| [  790.375433] BUG: workqueue lockup - pool cpus=0 node=0 flags=0x0 nice=0 stuck for 32s!
| [  790.435529] Showing busy workqueues and worker pools:
| [  790.455374] workqueue events: flags=0x0
| [  790.471271]   pwq 0: cpus=0 node=0 flags=0x0 nice=0 active=1/256 refcnt=2
| [  790.481737]     in-flight: 15:vmstat_shepherd
| [  790.495314] workqueue events_power_efficient: flags=0x82
| [  790.512837]   pwq 2: cpus=0 flags=0x4 nice=0 active=1/256 refcnt=3
| [  790.521833]     in-flight: 107:neigh_periodic_work
| [  790.535532] workqueue mm_percpu_wq: flags=0x8
| [  790.555139]   pwq 0: cpus=0 node=0 flags=0x0 nice=0 active=1/256 refcnt=2
| [  790.565610]     pending: vmstat_update
| [  790.579066] pool 0: cpus=0 node=0 flags=0x0 nice=0 hung=32s workers=2 idle: 5
| [  790.603124] pool 2: cpus=0 flags=0x4 nice=0 hung=1s workers=3 idle: 7 61
| [  950.115427] BUG: workqueue lockup - pool cpus=0 node=0 flags=0x0 nice=0 stuck for 40s!
| [  950.177846] Showing busy workqueues and worker pools:
| [  950.183602] workqueue events: flags=0x0
| [  950.207180]   pwq 0: cpus=0 node=0 flags=0x0 nice=0 active=1/256 refcnt=2
| [  950.217258]     pending: vmstat_shepherd
| [  992.571446] BUG: workqueue lockup - pool cpus=0 node=0 flags=0x0 nice=0 stuck for 82s!
| [  992.662876] Showing busy workqueues and worker pools:
| [  992.668626] workqueue events: flags=0x0
| [  992.691443]   pwq 0: cpus=0 node=0 flags=0x0 nice=0 active=1/256 refcnt=2
| [  992.701473]     pending: vmstat_shepherd
| [ 1001.181519] rcu: INFO: rcu_preempt detected stalls on CPUs/tasks:
| [ 1001.186952] 	(detected by 0, t=6502 jiffies, g=3441, q=1)
| [ 1001.188828] rcu: All QSes seen, last rcu_preempt kthread activity 528 (4295139809-4295139281), jiffies_till_next_fqs=1, root ->qsmask 0x0
| [ 1001.199298] rcu: rcu_preempt kthread starved for 528 jiffies! g3441 f0x2 RCU_GP_CLEANUP(7) ->state=0x0 ->cpu=0
| [ 1001.205008] rcu: 	Unless rcu_preempt kthread gets sufficient CPU time, OOM is now expected behavior.
| [ 1001.210324] rcu: RCU grace-period kthread stack dump:
| [ 1001.214618] task:rcu_preempt     state:R  running task     stack:    0 pid:   10 ppid:     2 flags:0x00000428
| [ 1001.223303] Call trace:
| [ 1001.226919]  __switch_to+0x100/0x1e0
| [ 1001.230803]  __schedule+0x2d0/0x890
| [ 1001.234685]  preempt_schedule_common+0xd4/0x1b0
| [ 1001.238831]  preempt_schedule.part.88+0x20/0x28
| [ 1001.242963]  preempt_schedule+0x20/0x28
| [ 1001.246928]  _raw_spin_unlock_irq+0x80/0x90
| [ 1001.251011]  rcu_gp_kthread+0xe5c/0x19a8
| [ 1001.255024]  kthread+0x174/0x188
| [ 1001.258821]  ret_from_fork+0x10/0x18
| [ 1001.274658] 
| [ 1001.276945] ================================
| [ 1001.279954] WARNING: inconsistent lock state
| [ 1001.283169] 5.10.0-rc3-next-20201110-00001-gc07b306d7fa5-dirty #2 Not tainted
| [ 1001.287067] --------------------------------
| [ 1001.290073] inconsistent {IN-HARDIRQ-W} -> {HARDIRQ-ON-W} usage.
| [ 1001.293767] ksoftirqd/0/9 [HC0[0]:SC0[0]:HE0:SE1] takes:
| [ 1001.297148] ffffd53efd5d4358 (rcu_node_0){?.-.}-{2:2}, at: rcu_sched_clock_irq+0x4a0/0xd18
| [ 1001.305027] {IN-HARDIRQ-W} state was registered at:
| [ 1001.308401]   __lock_acquire+0x7bc/0x15b8
| [ 1001.311430]   lock_acquire+0x244/0x498
| [ 1001.314341]   _raw_spin_lock+0x5c/0x78
| [ 1001.317252]   rcu_preempt_deferred_qs_irqrestore+0x84/0x540
| [ 1001.320666]   rcu_preempt_deferred_qs+0x64/0x80
| [ 1001.323789]   rcu_sched_clock_irq+0x4f4/0xd18
| [ 1001.326881]   update_process_times+0x68/0x98
| [ 1001.329932]   tick_sched_handle.isra.16+0x54/0x80
| [ 1001.333110]   tick_sched_timer+0x64/0xd8
| [ 1001.336085]   __hrtimer_run_queues+0x2a4/0x750
| [ 1001.339194]   hrtimer_interrupt+0xf4/0x2a0
| [ 1001.342244]   arch_timer_handler_virt+0x44/0x70
| [ 1001.345419]   handle_percpu_devid_irq+0xfc/0x4d0
| [ 1001.348579]   generic_handle_irq+0x50/0x70
| [ 1001.351596]   __handle_domain_irq+0x9c/0x120
| [ 1001.354677]   gic_handle_irq+0xcc/0x108
| [ 1001.357651]   el1_irq+0xbc/0x180
| [ 1001.360429]   arch_local_irq_save+0x18/0x30
| [ 1001.363460]   __rcu_read_unlock+0x84/0x1d8
| [ 1001.366461]   check_lifetime+0x158/0x4e0
| [ 1001.369460]   process_one_work+0x2c4/0x828
| [ 1001.372486]   worker_thread+0x5c/0x518
| [ 1001.375432]   kthread+0x174/0x188
| [ 1001.378232]   ret_from_fork+0x10/0x18
| [ 1001.381101] irq event stamp: 68414
| [ 1001.383978] hardirqs last  enabled at (68413): [<ffffd53efb1856d0>] rcu_irq_exit_irqson+0x48/0x68
| [ 1001.388412] hardirqs last disabled at (68414): [<ffffd53efb0122bc>] el1_irq+0x7c/0x180
| [ 1001.392557] softirqs last  enabled at (68214): [<ffffd53efb010b58>] __do_softirq+0x650/0x6a4
| [ 1001.396858] softirqs last disabled at (68211): [<ffffd53efb0c0b80>] irq_exit+0x1a8/0x1b0
| [ 1001.400907] 
| [ 1001.400907] other info that might help us debug this:
| [ 1001.404542]  Possible unsafe locking scenario:
| [ 1001.404542] 
| [ 1001.407936]        CPU0
| [ 1001.410369]        ----
| [ 1001.412815]   lock(rcu_node_0);
| [ 1001.417183]   <Interrupt>
| [ 1001.419715]     lock(rcu_node_0);
| [ 1001.424132] 
| [ 1001.424132]  *** DEADLOCK ***
| [ 1001.424132] 
| [ 1001.427638] 1 lock held by ksoftirqd/0/9:
| [ 1001.430588]  #0: ffffd53efd5d4358 (rcu_node_0){?.-.}-{2:2}, at: rcu_sched_clock_irq+0x4a0/0xd18
| [ 1001.439283] 
| [ 1001.439283] stack backtrace:
| [ 1001.442601] CPU: 0 PID: 9 Comm: ksoftirqd/0 Not tainted 5.10.0-rc3-next-20201110-00001-gc07b306d7fa5-dirty #2
| [ 1001.447258] Hardware name: linux,dummy-virt (DT)
| [ 1001.450435] Call trace:
| [ 1001.452985]  dump_backtrace+0x0/0x278
| [ 1001.455904]  show_stack+0x30/0x80
| [ 1001.458690]  dump_stack+0x138/0x1b0
| [ 1001.461525]  print_usage_bug+0x2d8/0x2f8
| [ 1001.464511]  mark_lock.part.46+0x370/0x480
| [ 1001.467538]  mark_held_locks+0x58/0x90
| [ 1001.470495]  lockdep_hardirqs_on_prepare+0xdc/0x298
| [ 1001.473751]  trace_hardirqs_on+0x90/0x388
| [ 1001.476744]  el1_irq+0xd8/0x180
| [ 1001.479486]  arch_local_irq_restore+0x4/0x8
| [ 1001.482521]  trace_preempt_off+0x138/0x1e8
| [ 1001.485531]  preempt_schedule_notrace+0xec/0x1c0
| [ 1001.488707]  ftrace_ops_no_ops+0x174/0x250
| [ 1001.491730]  ftrace_graph_call+0x0/0xc
| [ 1001.494647]  preempt_count_add+0x1c/0x180
| [ 1001.497642]  schedule+0x44/0x108
| [ 1001.500440]  smpboot_thread_fn+0x160/0x298
| [ 1001.503470]  kthread+0x174/0x188
| [ 1001.506245]  ret_from_fork+0x10/0x18
| [ 1001.513585] BUG: scheduling while atomic: ksoftirqd/0/9/0x00000002
| [ 1001.522142] INFO: lockdep is turned off.
| [ 1001.530315] Modules linked in:
| [ 1001.542198] Preemption disabled at:
| [ 1001.546077] [<ffffd53efb219d74>] ftrace_ops_no_ops+0x174/0x250
| [ 1001.558740] CPU: 0 PID: 9 Comm: ksoftirqd/0 Not tainted 5.10.0-rc3-next-20201110-00001-gc07b306d7fa5-dirty #2
| [ 1001.563426] Hardware name: linux,dummy-virt (DT)
| [ 1001.566615] Call trace:
| [ 1001.569206]  dump_backtrace+0x0/0x278
| [ 1001.572108]  show_stack+0x30/0x80
| [ 1001.574947]  dump_stack+0x138/0x1b0
| [ 1001.577814]  __schedule_bug+0x8c/0xe8
| [ 1001.580769]  __schedule+0x7e8/0x890
| [ 1001.583679]  preempt_schedule_notrace+0x70/0x1c0
| [ 1001.586883]  ftrace_ops_no_ops+0x174/0x250
| [ 1001.589939]  ftrace_graph_call+0x0/0xc
| [ 1001.592891]  preempt_count_add+0x1c/0x180
| [ 1001.595925]  schedule+0x44/0x108
| [ 1001.598741]  smpboot_thread_fn+0x160/0x298
| [ 1001.601808]  kthread+0x174/0x188
| [ 1001.604629]  ret_from_fork+0x10/0x18

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201111202153.GT517454%40elver.google.com.
