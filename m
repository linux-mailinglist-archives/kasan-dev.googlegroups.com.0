Return-Path: <kasan-dev+bncBC7OBJGL2MHBB556WX6QKGQELTN4NYQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43b.google.com (mail-wr1-x43b.google.com [IPv6:2a00:1450:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id 5011F2B09AB
	for <lists+kasan-dev@lfdr.de>; Thu, 12 Nov 2020 17:14:48 +0100 (CET)
Received: by mail-wr1-x43b.google.com with SMTP id x16sf2129663wrg.7
        for <lists+kasan-dev@lfdr.de>; Thu, 12 Nov 2020 08:14:48 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605197688; cv=pass;
        d=google.com; s=arc-20160816;
        b=gWiC+7+m0HDYmJSwAE7B4jqPXFb2JFLLQu+1QspjdsdKAZ5KkM3+bCTIigrdFu6VQL
         dB3W6OdU9KhqRAD2C9kon/mAK/bSM+cbVBhf4H94sUDQ8rpyA6jTjxRLwFIcg/VIF5ls
         ncKWNy54rFPN5WpI+A9jG5EZxqjuE3fAUdG2ObwN/GPKswcLedX8Z7+09fkeuL6s5cm4
         s+zCZmDhyAgTBj8VrV9C3mFXLqtPiptvysjgwj+q1NY0jAHSd+okDUMf6kJsvb0oQ4FG
         ex6NzM0Dmx02K/m7BObu6jGpcjP33m7MK79X+m5+zc3MtaETeyJr4bDqgazoDwUxJPbD
         vWgw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=/WLCic6tOCKyliwqXJ7naED6yg5fZIibcCxoVrn6bsk=;
        b=piVEpm7vvsKxYxhnUvgDpQ5R7NzQ8VkP2u09fKkqyWnWi3ijCarWnmLWnR4Hl+MCog
         0bEwYkHXusKm1hxvBugtqc6ie4uFJP2UelUEQVg5PunPSdg8w6NsgjxAhsYIhuV2RuZf
         uxmrVw+fFrhTjoF5Tt9rQvFYCp93EC8JJnClgJKCvalZnRzyWAdY4+vBTFbMgfCVmAqD
         7T5h28tFb/CX+RX9x4m4tNOBJF9jQKVw1uzd2+VtufqekTpR6ImdssyJ5OJlvRcHnQzX
         kWWtDJ3yfUrkdoghN4+8g1PBX5ynHmD5skv7AKC4hvj+kougo2HXGkDC3NH3h2/Jfw3G
         Sltw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=WPFWGH0A;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::441 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=/WLCic6tOCKyliwqXJ7naED6yg5fZIibcCxoVrn6bsk=;
        b=KLztxQAFAbXmLKDugmsKSKsWIbSHLa6v9q4h0Js8m+4cX7P1U2bauJVzl2OzX1Bs8F
         Sz55LOZBTrCV3hSVi+hz40hEUmq6nPl6Yp1LNTSVxBzqO9ugYLqUQe9DWEzDqQs/MSif
         sBlpxHenqBiTWZ3Mp9xKo5VKAlbrfltPXfHGJO4doJ8QW1/TYeRUNoGF2sHT7TpSCDmf
         wKsumGwj5jp/T1aRZJF1kcmatE7RF77Gu/UhYfNg3pvjGWI+o/VlnWUQ6FFfIkGrQ9hW
         nDOcg9oepqn07lvZ1Zn9PSNl6tekITGlrHHkb8ydQ7RRk/7dYQPh317kTnCiD8Unyy6Z
         fAkg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=/WLCic6tOCKyliwqXJ7naED6yg5fZIibcCxoVrn6bsk=;
        b=Y5kOqlwsUFIo6rw21P7uG769AIv/+y2rQCr5FlrGHCmguIj49n40G5+CAOdbTMVt1c
         SFFGUtsU++8vgKKJ3wTco1iy5eBNYOx6pZvkipMH/IF7BJSR5EDgmuvzTGktu59757ak
         dl33nYhlD7020D51uw75lbIX/5NFUyC1G06exGn1jH0p0o99oJosie3fpUvFNmJ88V/s
         QdIjd/vDfdWrEpOV6t3iT3nRo75sHXOFWiuuIxL3WZKnAQYcZm7cKRHUuwATJp+UcCeX
         qFK6vBq6QIV4BQ3EbypBmx6SdhtIn6goW71Dmf4GyJTgXRHp44jd3mIceo73pttIl2r2
         lk/g==
X-Gm-Message-State: AOAM532i1FjdO6pCLzrxmFCZqwjqt+2FSwKdBIptesUc2BujHIVMoFhc
	Y2T73eDEPZYWMOpdtlWhV8Y=
X-Google-Smtp-Source: ABdhPJxJkDZ7OaP4UqJ8TfJvu0Cf6WebiPH+cVph8h5BURItUIUMs4CSV+Mvgl/Rt1duOI4soGCyoA==
X-Received: by 2002:a05:600c:2319:: with SMTP id 25mr435065wmo.102.1605197688024;
        Thu, 12 Nov 2020 08:14:48 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:5417:: with SMTP id i23ls1714748wmb.2.canary-gmail; Thu,
 12 Nov 2020 08:14:47 -0800 (PST)
X-Received: by 2002:a1c:9cc9:: with SMTP id f192mr364870wme.143.1605197687014;
        Thu, 12 Nov 2020 08:14:47 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605197687; cv=none;
        d=google.com; s=arc-20160816;
        b=OCL/RQXEJzmHTbiIw00cRcnQTuBimCPeL/mk+LDqQpsrqvH9kyXR5yC1oE6dQvrh1o
         h0852a5uYcdAFgsSMn7swoZ+X5xRoC13Es8mDGEJP148BqiCeXveGagaWH8J78sF328k
         O6+hepcAz0mJN+rDm7k6hR1yVrDnIl/K2SaqSmhuqiE+M7XZQktxlfZyS6UAnLgub6dI
         diJwCnh6PXKOhbIFCsuqNM//A22SZ/s/y1EFUABsVAFi5adLB0IsYCjNsPm4hyYjecJQ
         7KRFX3y2+tJpv3ThfsFZHIp3/dKqHJxbLUyqczR8W+tGZk6f5PKYQOgVr7wOxzIZ5/Xm
         NlMg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=dg9mFKp9U5H8mroGhGYMtfFfItuVk6ddUJL5dGH1N+0=;
        b=KZB7+FsUNsfSfQi/ep+5kgtKgVlYaKlm1Wu7aaitdV1rn18DLEVV3+e1488RL03k0E
         6VbxgvOIxhbUlIl+7S94b83/baJvUwW+GBIx0c88EOsbq5evGpnMBEuHBB7PbzkWJfiN
         1EJGbx9ncvivFrBa9TRNaqUNMh7cXSlqeXNrR8RFaZ22h9qpeMfiyceVeUBscVYK+Y7i
         yYhio2mF1yLXfylsgkmOwcnn39GgWuvkTZ41QcHfF6DtKYkpnCQXQ3fzDJnZ3TxHidIE
         qRHWSAxu/jyuWV+ePqM9FL2Sped1FLfJjlXO8ho+1Or4br5E7H5DwgrJ5DU40ZqqvGML
         K3ew==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=WPFWGH0A;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::441 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x441.google.com (mail-wr1-x441.google.com. [2a00:1450:4864:20::441])
        by gmr-mx.google.com with ESMTPS id z83si556443wmc.3.2020.11.12.08.14.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 12 Nov 2020 08:14:47 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::441 as permitted sender) client-ip=2a00:1450:4864:20::441;
Received: by mail-wr1-x441.google.com with SMTP id b8so6617292wrn.0
        for <kasan-dev@googlegroups.com>; Thu, 12 Nov 2020 08:14:46 -0800 (PST)
X-Received: by 2002:adf:f304:: with SMTP id i4mr325569wro.268.1605197686277;
        Thu, 12 Nov 2020 08:14:46 -0800 (PST)
Received: from elver.google.com ([2a00:79e0:15:13:f693:9fff:fef4:2449])
        by smtp.gmail.com with ESMTPSA id d63sm7038789wmd.12.2020.11.12.08.14.45
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 12 Nov 2020 08:14:45 -0800 (PST)
Date: Thu, 12 Nov 2020 17:14:39 +0100
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
	Peter Zijlstra <peterz@infradead.org>
Subject: Re: [PATCH] kfence: Avoid stalling work queue task without
 allocations
Message-ID: <20201112161439.GA2989297@elver.google.com>
References: <CADYN=9+=-ApMi_eEdAeHU6TyuQ7ZJSTQ8F-FCSD33kZH8HR+xg@mail.gmail.com>
 <CANpmjNM8MZphvkTSo=KgCBXQ6fNY4qo6NZD5SBHjNse_L9i5FQ@mail.gmail.com>
 <20201111133813.GA81547@elver.google.com>
 <20201111130543.27d29462@gandalf.local.home>
 <20201111182333.GA3249@paulmck-ThinkPad-P72>
 <20201111183430.GN517454@elver.google.com>
 <20201111192123.GB3249@paulmck-ThinkPad-P72>
 <20201111202153.GT517454@elver.google.com>
 <20201112001129.GD3249@paulmck-ThinkPad-P72>
 <CANpmjNNyZs6NrHPmomC4=9MPEvCy1bFA5R2pRsMhG7=c3LhL_Q@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNNyZs6NrHPmomC4=9MPEvCy1bFA5R2pRsMhG7=c3LhL_Q@mail.gmail.com>
User-Agent: Mutt/1.14.6 (2020-07-11)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=WPFWGH0A;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::441 as
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

On Thu, Nov 12, 2020 at 01:49PM +0100, Marco Elver wrote:
> On Thu, 12 Nov 2020 at 01:11, Paul E. McKenney <paulmck@kernel.org> wrote:
[...]
> > > This assert didn't fire yet, I just get more of the below. I'll keep
> > > rerunning, but am not too hopeful...
> >
> > Is bisection a possibility?
> 
> I've been running a bisection for past ~12h, and am making slow
> progress. It might be another 12h, but I think it'll get there.

Bisection gave me this:

| git bisect start
| # bad: [c07b306d7fa5680777e2132662d2e6c19fb53579] kfence: Avoid stalling work queue task without allocations
| git bisect bad c07b306d7fa5680777e2132662d2e6c19fb53579
| # good: [3cea11cd5e3b00d91caf0b4730194039b45c5891] Linux 5.10-rc2
| git bisect good 27598e7e73260ed0b2917eb02d4a515ebb578313
| # good: [3e5acbea719e66ef3be64fe74c99cc905ca697dc] Merge remote-tracking branch 'wireless-drivers-next/master' into master
| git bisect good 3e5acbea719e66ef3be64fe74c99cc905ca697dc
| # good: [491a5a9a2fea28353d99621b8abb83b6928b4e36] Merge remote-tracking branch 'sound-asoc/for-next' into master
| git bisect good 491a5a9a2fea28353d99621b8abb83b6928b4e36
| # bad: [502f8643d6e21c7e370a0b75131130cc51609055] Merge remote-tracking branch 'phy-next/next' into master
| git bisect bad 502f8643d6e21c7e370a0b75131130cc51609055
| # good: [6693cb1fa5ea7b91ec00f9404776a095713face5] Merge remote-tracking branch 'tip/auto-latest' into master
| git bisect good 6693cb1fa5ea7b91ec00f9404776a095713face5
| # bad: [b790e3afead9357195b6d1e1b6cd9b3521503ad2] Merge branch 'tglx-pc.2020.10.30a' into HEAD
| git bisect bad b790e3afead9357195b6d1e1b6cd9b3521503ad2
| # bad: [765b512bb3d639bfad7dd43c288ee085236c7267] Merge branches 'cpuinfo.2020.11.06a', 'doc.2020.11.06a', 'fixes.2020.11.02a', 'lockdep.2020.11.02a', 'tasks.2020.11.06a' and 'torture.2020.11.06a' into HEAD
| git bisect bad 765b512bb3d639bfad7dd43c288ee085236c7267
| # good: [01f9e708d9eae6335ae9ff25ab09893c20727a55] tools/rcutorture: Fix BUG parsing of console.log
| git bisect good 01f9e708d9eae6335ae9ff25ab09893c20727a55
| # good: [1be6ab91e2db157faedb7f16ab0636a80745a073] srcu: Take early exit on memory-allocation failure
| git bisect good 1be6ab91e2db157faedb7f16ab0636a80745a073
| # good: [65e9eb1ccfe56b41a0d8bfec651ea014968413cb] rcu: Prevent RCU_LOCKDEP_WARN() from swallowing the condition
| git bisect good 65e9eb1ccfe56b41a0d8bfec651ea014968413cb
| # good: [c386e29d43728778ddd642fa73cc582bee684171] docs/rcu: Update the call_rcu() API
| git bisect good c386e29d43728778ddd642fa73cc582bee684171
| # good: [27c0f1448389baf7f309b69e62d4b531c9395e88] rcutorture: Make grace-period kthread report match RCU flavor being tested
| git bisect good 27c0f1448389baf7f309b69e62d4b531c9395e88
| # good: [3fcd6a230fa7d03bffcb831a81b40435c146c12b] x86/cpu: Avoid cpuinfo-induced IPIing of idle CPUs
| git bisect good 3fcd6a230fa7d03bffcb831a81b40435c146c12b
| # good: [75dc2da5ecd65bdcbfc4d59b9d9b7342c61fe374] rcu-tasks: Make the units of ->init_fract be jiffies
| git bisect good 75dc2da5ecd65bdcbfc4d59b9d9b7342c61fe374
| # first bad commit: [765b512bb3d639bfad7dd43c288ee085236c7267] Merge branches 'cpuinfo.2020.11.06a', 'doc.2020.11.06a', 'fixes.2020.11.02a', 'lockdep.2020.11.02a', 'tasks.2020.11.06a' and 'torture.2020.11.06a' into HEAD

This doesn't look very satisfying, given it's the merge commit. :-/

> > Failing that, please see the updated patch below.  This adds a few more
> > calls to lockdep_assert_irqs_disabled(), but perhaps more helpfully dumps
> > the current stack of the CPU that the RCU grace-period kthread wants to
> > run on in the case where this kthread has been starved of CPU.
> 
> Thanks, I will apply that after the bisection runs.

Here's a new log with it applied:

| [  118.480959] Key type dns_resolver registered
| [  118.487752] registered taskstats version 1
| [  118.489798] Running tests on all trace events:
| [  118.490164] Testing all events: OK
| [  173.304186] Running tests again, along with the function tracer
| [  173.320155] Running tests on all trace events:
| [  173.331638] Testing all events: 
| [  173.485044] hrtimer: interrupt took 14340976 ns
| [  334.160218] BUG: workqueue lockup - pool cpus=0 node=0 flags=0x0 nice=0 stuck for 15s!
| [  334.259490] Showing busy workqueues and worker pools:
| [  334.265398] workqueue events: flags=0x0
| [  334.289070]   pwq 0: cpus=0 node=0 flags=0x0 nice=0 active=1/256 refcnt=2
| [  334.300659]     pending: vmstat_shepherd
| [  453.541827] BUG: workqueue lockup - pool cpus=0 node=0 flags=0x0 nice=0 stuck for 10s!
| [  453.655731] BUG: workqueue lockup - pool cpus=0 flags=0x4 nice=0 stuck for 10s!
| [  453.759839] Showing busy workqueues and worker pools:
| [  453.784294] workqueue events: flags=0x0
| [  453.812207]   pwq 0: cpus=0 node=0 flags=0x0 nice=0 active=1/256 refcnt=2
| [  453.822108]     pending: vmstat_shepherd
| [  453.839855] workqueue events_power_efficient: flags=0x82
| [  453.865152]   pwq 2: cpus=0 flags=0x4 nice=0 active=2/256 refcnt=4
| [  453.874553]     pending: neigh_periodic_work, do_cache_clean
| [  481.424362] BUG: workqueue lockup - pool cpus=0 flags=0x4 nice=0 stuck for 10s!
| [  481.508136] Showing busy workqueues and worker pools:
| [  481.524265] workqueue events: flags=0x0
| [  481.550480]   pwq 0: cpus=0 node=0 flags=0x0 nice=0 active=1/256 refcnt=2
| [  481.560690]     pending: vmstat_shepherd
| [  481.571255] workqueue events_power_efficient: flags=0x82
| [  481.592515]   pwq 2: cpus=0 flags=0x4 nice=0 active=1/256 refcnt=3
| [  481.601153]     pending: neigh_periodic_work
| [  532.108407] BUG: workqueue lockup - pool cpus=0 node=0 flags=0x0 nice=0 stuck for 10s!
| [  532.203476] Showing busy workqueues and worker pools:
| [  532.215930] workqueue events: flags=0x0
| [  532.244203]   pwq 0: cpus=0 node=0 flags=0x0 nice=0 active=1/256 refcnt=2
| [  532.254428]     pending: vmstat_shepherd
| [  739.567892] BUG: workqueue lockup - pool cpus=0 node=0 flags=0x0 nice=0 stuck for 19s!
| [  739.656419] Showing busy workqueues and worker pools:
| [  739.699514] workqueue events: flags=0x0
| [  739.705111]   pwq 0: cpus=0 node=0 flags=0x0 nice=0 active=1/256 refcnt=2
| [  739.715393]     pending: vmstat_shepherd
| [  739.733403] workqueue events_power_efficient: flags=0x82
| [  739.739433]   pwq 2: cpus=0 flags=0x4 nice=0 active=2/256 refcnt=4
| [  739.748156]     pending: check_lifetime, neigh_periodic_work
| [  811.578165] BUG: workqueue lockup - pool cpus=0 flags=0x5 nice=0 stuck for 14s!
| [  811.602913] Showing busy workqueues and worker pools:
| [  811.620424] workqueue events: flags=0x0
| [  811.652479]   pwq 0: cpus=0 node=0 flags=0x0 nice=0 active=1/256 refcnt=2
| [  811.662686]     pending: vmstat_shepherd
| [  811.683811] workqueue events_power_efficient: flags=0x82
| [  811.716123]   pwq 2: cpus=0 flags=0x5 nice=0 active=1/256 refcnt=3
| [  811.724857]     pending: neigh_periodic_work
| [  811.749989] pool 2: cpus=0 flags=0x5 nice=0 hung=14s workers=2 manager: 61 idle: 7
| [  822.456290] BUG: workqueue lockup - pool cpus=0 node=0 flags=0x0 nice=0 stuck for 11s!
| [  822.600359] BUG: workqueue lockup - pool cpus=0 flags=0x5 nice=0 stuck for 25s!
| [  822.675814] Showing busy workqueues and worker pools:
| [  822.720098] workqueue events: flags=0x0
| [  822.747304]   pwq 0: cpus=0 node=0 flags=0x0 nice=0 active=1/256 refcnt=2
| [  822.757174]     pending: vmstat_shepherd
| [  822.768047] workqueue events_power_efficient: flags=0x82
| [  822.799954]   pwq 2: cpus=0 flags=0x5 nice=0 active=1/256 refcnt=3
| [  822.808488]     pending: neigh_periodic_work
| [  822.831900] pool 2: cpus=0 flags=0x5 nice=0 hung=25s workers=2 manager: 61 idle: 7
| [  834.116239] BUG: workqueue lockup - pool cpus=0 node=0 flags=0x0 nice=0 stuck for 22s!
| [  834.246557] BUG: workqueue lockup - pool cpus=0 flags=0x5 nice=0 stuck for 37s!
| [  834.271069] Showing busy workqueues and worker pools:
| [  834.276687] workqueue events: flags=0x0
| [  834.296267]   pwq 0: cpus=0 node=0 flags=0x0 nice=0 active=1/256 refcnt=2
| [  834.306148]     pending: vmstat_shepherd
| [  834.324273] workqueue events_power_efficient: flags=0x82
| [  834.344433]   pwq 2: cpus=0 flags=0x5 nice=0 active=2/256 refcnt=4
| [  834.352891]     pending: neigh_periodic_work, do_cache_clean
| [  834.384530] pool 2: cpus=0 flags=0x5 nice=0 hung=37s workers=2 manager: 61 idle: 7
| [  840.906940] rcu: INFO: rcu_preempt detected stalls on CPUs/tasks:
| [  840.912685] 	(detected by 0, t=3752 jiffies, g=2709, q=1)
| [  840.914587] rcu: All QSes seen, last rcu_preempt kthread activity 620 (4295099794-4295099174), jiffies_till_next_fqs=1, root ->qsmask 0x0
| [  840.925016] rcu: rcu_preempt kthread starved for 620 jiffies! g2709 f0x2 RCU_GP_CLEANUP(7) ->state=0x0 ->cpu=0
| [  840.930687] rcu: 	Unless rcu_preempt kthread gets sufficient CPU time, OOM is now expected behavior.
| [  840.936056] rcu: RCU grace-period kthread stack dump:
| [  840.940433] task:rcu_preempt     state:R  running task     stack:    0 pid:   10 ppid:     2 flags:0x00000428
| [  840.949160] Call trace:
| [  840.952822]  dump_backtrace+0x0/0x278
| [  840.956816]  show_stack+0x30/0x80
| [  840.960643]  sched_show_task+0x1a8/0x240
| [  840.964684]  rcu_check_gp_kthread_starvation+0x170/0x358
| [  840.969113]  rcu_sched_clock_irq+0x744/0xd18
| [  840.973232]  update_process_times+0x68/0x98
| [  840.977308]  tick_sched_handle.isra.16+0x54/0x80
| [  840.981504]  tick_sched_timer+0x64/0xd8
| [  840.985500]  __hrtimer_run_queues+0x2a4/0x750
| [  840.989628]  hrtimer_interrupt+0xf4/0x2a0
| [  840.993669]  arch_timer_handler_virt+0x44/0x70
| [  840.997841]  handle_percpu_devid_irq+0xfc/0x4d0
| [  841.002043]  generic_handle_irq+0x50/0x70
| [  841.006098]  __handle_domain_irq+0x9c/0x120
| [  841.010188]  gic_handle_irq+0xcc/0x108
| [  841.014132]  el1_irq+0xbc/0x180
| [  841.017935]  arch_local_irq_restore+0x4/0x8
| [  841.021993]  trace_preempt_on+0xf4/0x190
| [  841.026016]  preempt_schedule_common+0x12c/0x1b0
| [  841.030193]  preempt_schedule.part.88+0x20/0x28
| [  841.034373]  preempt_schedule+0x20/0x28
| [  841.038369]  _raw_spin_unlock_irq+0x80/0x90
| [  841.042498]  rcu_gp_kthread+0xe5c/0x19a8
| [  841.046504]  kthread+0x174/0x188
| [  841.050320]  ret_from_fork+0x10/0x18
| [  841.054312] rcu: Stack dump where RCU grace-period kthread last ran:
| [  841.058980] Task dump for CPU 0:
| [  841.062736] task:rcu_preempt     state:R  running task     stack:    0 pid:   10 ppid:     2 flags:0x00000428
| [  841.071073] Call trace:
| [  841.074662]  dump_backtrace+0x0/0x278
| [  841.078596]  show_stack+0x30/0x80
| [  841.082386]  sched_show_task+0x1a8/0x240
| [  841.086367]  dump_cpu_task+0x48/0x58
| [  841.090311]  rcu_check_gp_kthread_starvation+0x214/0x358
| [  841.094736]  rcu_sched_clock_irq+0x744/0xd18
| [  841.098852]  update_process_times+0x68/0x98
| [  841.102949]  tick_sched_handle.isra.16+0x54/0x80
| [  841.107119]  tick_sched_timer+0x64/0xd8
| [  841.111127]  __hrtimer_run_queues+0x2a4/0x750
| [  841.115264]  hrtimer_interrupt+0xf4/0x2a0
| [  841.119319]  arch_timer_handler_virt+0x44/0x70
| [  841.123525]  handle_percpu_devid_irq+0xfc/0x4d0
| [  841.127690]  generic_handle_irq+0x50/0x70
| [  841.131702]  __handle_domain_irq+0x9c/0x120
| [  841.135779]  gic_handle_irq+0xcc/0x108
| [  841.139743]  el1_irq+0xbc/0x180
| [  841.143527]  arch_local_irq_restore+0x4/0x8
| [  841.147612]  trace_preempt_on+0xf4/0x190
| [  841.151656]  preempt_schedule_common+0x12c/0x1b0
| [  841.155869]  preempt_schedule.part.88+0x20/0x28
| [  841.160036]  preempt_schedule+0x20/0x28
| [  841.164051]  _raw_spin_unlock_irq+0x80/0x90
| [  841.168139]  rcu_gp_kthread+0xe5c/0x19a8
| [  841.172134]  kthread+0x174/0x188
| [  841.175953]  ret_from_fork+0x10/0x18
| [  841.191371] 
| [  841.193648] ================================
| [  841.196605] WARNING: inconsistent lock state
| [  841.199764] 5.10.0-rc3-next-20201110-00001-gc07b306d7fa5-dirty #23 Not tainted
| [  841.203564] --------------------------------
| [  841.206550] inconsistent {IN-HARDIRQ-W} -> {HARDIRQ-ON-W} usage.
| [  841.210074] rcu_preempt/10 [HC0[0]:SC0[0]:HE0:SE1] takes:
| [  841.213453] ffffd787e91d4358 (rcu_node_0){?.-.}-{2:2}, at: rcu_sched_clock_irq+0x4a0/0xd18
| [  841.221240] {IN-HARDIRQ-W} state was registered at:
| [  841.224538]   __lock_acquire+0x7bc/0x15b8
| [  841.227541]   lock_acquire+0x244/0x498
| [  841.230442]   _raw_spin_lock_irqsave+0x78/0x144
| [  841.233555]   rcu_sched_clock_irq+0x4a0/0xd18
| [  841.236621]   update_process_times+0x68/0x98
| [  841.239645]   tick_sched_handle.isra.16+0x54/0x80
| [  841.242801]   tick_sched_timer+0x64/0xd8
| [  841.245745]   __hrtimer_run_queues+0x2a4/0x750
| [  841.248842]   hrtimer_interrupt+0xf4/0x2a0
| [  841.251846]   arch_timer_handler_virt+0x44/0x70
| [  841.254976]   handle_percpu_devid_irq+0xfc/0x4d0
| [  841.258131]   generic_handle_irq+0x50/0x70
| [  841.261146]   __handle_domain_irq+0x9c/0x120
| [  841.264169]   gic_handle_irq+0xcc/0x108
| [  841.267096]   el1_irq+0xbc/0x180
| [  841.269844]   arch_local_irq_restore+0x4/0x8
| [  841.272881]   trace_preempt_on+0xf4/0x190
| [  841.275847]   preempt_schedule_common+0x12c/0x1b0
| [  841.279017]   preempt_schedule.part.88+0x20/0x28
| [  841.282149]   preempt_schedule+0x20/0x28
| [  841.285112]   _raw_spin_unlock_irq+0x80/0x90
| [  841.288154]   rcu_gp_kthread+0xe5c/0x19a8
| [  841.291175]   kthread+0x174/0x188
| [  841.293952]   ret_from_fork+0x10/0x18
| [  841.296780] irq event stamp: 39750
| [  841.299604] hardirqs last  enabled at (39749): [<ffffd787e6d85738>] rcu_irq_enter_irqson+0x48/0x68
| [  841.303961] hardirqs last disabled at (39750): [<ffffd787e6c122bc>] el1_irq+0x7c/0x180
| [  841.308042] softirqs last  enabled at (36704): [<ffffd787e6c10b58>] __do_softirq+0x650/0x6a4
| [  841.312250] softirqs last disabled at (36683): [<ffffd787e6cc0b80>] irq_exit+0x1a8/0x1b0
| [  841.316257] 
| [  841.316257] other info that might help us debug this:
| [  841.319834]  Possible unsafe locking scenario:
| [  841.319834] 
| [  841.323217]        CPU0
| [  841.325656]        ----
| [  841.328097]   lock(rcu_node_0);
| [  841.332433]   <Interrupt>
| [  841.334966]     lock(rcu_node_0);
| [  841.339379] 
| [  841.339379]  *** DEADLOCK ***
| [  841.339379] 
| [  841.342829] 1 lock held by rcu_preempt/10:
| [  841.345794]  #0: ffffd787e91d4358 (rcu_node_0){?.-.}-{2:2}, at: rcu_sched_clock_irq+0x4a0/0xd18
| [  841.354415] 
| [  841.354415] stack backtrace:
| [  841.357664] CPU: 0 PID: 10 Comm: rcu_preempt Not tainted 5.10.0-rc3-next-20201110-00001-gc07b306d7fa5-dirty #23
| [  841.362249] Hardware name: linux,dummy-virt (DT)
| [  841.365352] Call trace:
| [  841.367862]  dump_backtrace+0x0/0x278
| [  841.370745]  show_stack+0x30/0x80
| [  841.373517]  dump_stack+0x138/0x1b0
| [  841.376339]  print_usage_bug+0x2d8/0x2f8
| [  841.379288]  mark_lock.part.46+0x370/0x480
| [  841.382304]  mark_held_locks+0x58/0x90
| [  841.385228]  lockdep_hardirqs_on_prepare+0xdc/0x298
| [  841.388452]  trace_hardirqs_on+0x90/0x388
| [  841.391434]  el1_irq+0xd8/0x180
| [  841.394178]  arch_local_irq_restore+0x4/0x8
| [  841.397186]  trace_preempt_on+0xf4/0x190
| [  841.400127]  preempt_schedule_common+0x12c/0x1b0
| [  841.403246]  preempt_schedule.part.88+0x20/0x28
| [  841.406347]  preempt_schedule+0x20/0x28
| [  841.409278]  _raw_spin_unlock_irq+0x80/0x90
| [  841.412290]  rcu_gp_kthread+0xe5c/0x19a8
| [  841.415237]  kthread+0x174/0x188
| [  841.418011]  ret_from_fork+0x10/0x18
| [  841.423450] BUG: scheduling while atomic: rcu_preempt/10/0x00000002
| [  841.431367] INFO: lockdep is turned off.
| [  841.439132] Modules linked in:
| [  841.450608] Preemption disabled at:
| [  841.452261] [<ffffd787e7fffec0>] preempt_schedule.part.88+0x20/0x28
| [  841.467324] CPU: 0 PID: 10 Comm: rcu_preempt Not tainted 5.10.0-rc3-next-20201110-00001-gc07b306d7fa5-dirty #23
| [  841.471926] Hardware name: linux,dummy-virt (DT)
| [  841.475030] Call trace:
| [  841.477581]  dump_backtrace+0x0/0x278
| [  841.480451]  show_stack+0x30/0x80
| [  841.483220]  dump_stack+0x138/0x1b0
| [  841.486057]  __schedule_bug+0x8c/0xe8
| [  841.488949]  __schedule+0x7e8/0x890
| [  841.491801]  preempt_schedule_common+0x44/0x1b0
| [  841.494927]  preempt_schedule.part.88+0x20/0x28
| [  841.498048]  preempt_schedule+0x20/0x28
| [  841.500963]  _raw_spin_unlock_irq+0x80/0x90
| [  841.503988]  rcu_gp_kthread+0xe5c/0x19a8
| [  841.506965]  kthread+0x174/0x188
| [  841.509732]  ret_from_fork+0x10/0x18

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201112161439.GA2989297%40elver.google.com.
