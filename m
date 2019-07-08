Return-Path: <kasan-dev+bncBCV5TUXXRUIBBZUNRXUQKGQEEKIO73A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3f.google.com (mail-yb1-xb3f.google.com [IPv6:2607:f8b0:4864:20::b3f])
	by mail.lfdr.de (Postfix) with ESMTPS id DC63B61FA0
	for <lists+kasan-dev@lfdr.de>; Mon,  8 Jul 2019 15:36:39 +0200 (CEST)
Received: by mail-yb1-xb3f.google.com with SMTP id u14sf9710198ybu.19
        for <lists+kasan-dev@lfdr.de>; Mon, 08 Jul 2019 06:36:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1562592998; cv=pass;
        d=google.com; s=arc-20160816;
        b=tVPykQXlbKzlscxXf/prnXCKnxN0QpIXNmyBqC3Y1oX7hQdSAJjOVPmjPDFw963K6A
         iFpKMVgqEzDi3AXrziyjnBg31QvZ6btw6NAZ8Ckeu8O8BnIod8bTiVMMLm38CdgMTwZq
         sKbsF+8GdkZJyimuCSWqd76pAeQ8DAUEr7IMg4RNt9Tj7o+RJbs/ulFFynIvNuHF/tSz
         MEls8X+2TXUipkSnK+vD4YZxk4voAB7a444advS0JI5c/4BFufc+N4l4Lcg0JDvyNh+x
         TuxoLqbAkKqtk/lZMO/vXNZpdHcdk/TklW5zgV+XIN8NL6QnMo/64I83zJzOO7Y+0xM/
         mLyw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=AZSJjfXjPv7lQeRruYK73MqsIc0A4qHPf8ITMs32yD8=;
        b=OnirRgjlwbs0oy7MDflaIna9RLEhYUdYFUBsRKN0+s/WVHyn1e50my6N6lZl2n/Wdq
         9si1gpHgLK6tJr21gXVnYU5NFuzaKpZPdAhMXQcCkTDQFYF4fi4AZSMlHcQ68DD6jtw1
         ThwKkHAQn2uUEKCsCHC+pnSzCqK7j0c6w/YP0pkbSCYU5kDhGD9bj0JPmo5lpzXP5qaR
         ZSYc+ArBL6/67SdzTex0S8YbPekMUZHQ057x1EVe3Ek1d5gBoWGGUU64zH6Eenm22wR9
         lpGHNqGkrnAeHiWzYmqdjFG6u68QHnIpKyaQ541T77bYUlQ2rq7e2cMKNKNcHIbyfXJz
         Ck7w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=merlin.20170209 header.b=tCo6CNCg;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=AZSJjfXjPv7lQeRruYK73MqsIc0A4qHPf8ITMs32yD8=;
        b=PnYES5Sm0A6SsITXtIBubBXIlb8yc+RJM3/9X5uB95cjQGkAe/mPjNhn0u3qcZojKU
         B5t9OyEycP+55gGfU7mExizELuuEZ/DPgS6dkSboopn8uq9iA/8ku73gu+5sJSb01s7M
         n57eOaPC9Ness3T5SwfdSZhp0UuFDGqoOqx6JeNi6RrCTPLMUWsV2KV/0mNDBihHPmQa
         x7nNrHbvV5Gaqz6Fi+1Ubl27HaT3xqpRY/iIxb3BQ2Q1SMNPZinzOhNHrd2SI4w8nfao
         O20kUp58+iFN5ct7qnlkWVTvV1Hb4rCyeooVJg0mvh90EwNsH9/S6jnnhD3p74vcSVN4
         SusQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=AZSJjfXjPv7lQeRruYK73MqsIc0A4qHPf8ITMs32yD8=;
        b=FBUImjwo5/rLJYG/eN4lORT6+3AE1g7hyL6NsBH0WNYtZy36+q+lvuptXwsGwOGMQi
         oa+ZLVTwpLyOu0Z56t/olIczaYobjFEXQsZeEE1EZx355ycVovBxIv0Fb+wLWTosa68T
         WsfctwcEXu0caGqvqHhosytsxEj3vBgH+uDveGkv+HwnCl5aq4w3Bs/0Cwm2mdXZumt2
         xN/f099W5gkSnh8TohTkhxNvhh8byIxj60FuR6ixIHNffzo/DyGj+v3pxVWCjMwo0tTa
         yzCZbMklGkgs8W93gU4Pm9WT04YGvhc7Q4g/WOy4mUQDr4eSfdeo54NjZamEgTOkKjnW
         n/5Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAXqIBtnGfQ3nFAweVf0LQs08Y8HPhyUCkkBFduz+XpcB8ruy8bQ
	8N257PKz4y8LWnaBOvUedc0=
X-Google-Smtp-Source: APXvYqxG5fBeOHfW3eKUJLISoGYux8bvhWldl4Besxqy/RagEoDeuNZ/I1FRy+vVLJEtAFORhOZgSQ==
X-Received: by 2002:a25:804d:: with SMTP id a13mr10786712ybn.55.1562592998645;
        Mon, 08 Jul 2019 06:36:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:8405:: with SMTP id u5ls1488864ybk.6.gmail; Mon, 08 Jul
 2019 06:36:38 -0700 (PDT)
X-Received: by 2002:a25:9d82:: with SMTP id v2mr10322527ybp.226.1562592998304;
        Mon, 08 Jul 2019 06:36:38 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1562592998; cv=none;
        d=google.com; s=arc-20160816;
        b=cDmpCKER8GeQBKvMW7a/Y1k6vCAUcDqQEnSD4ngp2PCeC6jR1YUas0mz/WPEM/XwuF
         rYz80tdz8rFq6uut9A1+0Yp9dMwi/IT20O39u+xP4nEhb6k0mcm8BqtK/Zjsmrpy41z+
         zOztLYLPdps9hdBjOK89VP0PuBSWOgIViY//7q9b1T8tlK261anhExk/8cnjf8woVaaS
         tBVzvZTNaA7FoL03TOqk7ZDnGFitbHA/j7ZWrsKsSdj5G8OqLBLCagR/xky5udVBTQdx
         /s5xvcsba7ZdLmwor6Zf5QfKyqQix42ueAeJt47gtlgtKXla4nDSu9oDFmWy5EuAZdGh
         EHTw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=05F80iXfXNpAi1oVvhB3ub6LRHCm34VoFGBmreAiqfU=;
        b=HJvlquh9A3uGJDvA8ROjL/sU3lw/tD0V3I31nyxc1UNceS3U4UeJPw6cxSPsQE+IL9
         2AtzWqfJ9faLjsRu8GLapnGSOwTBYttdslTTt545Nrtd54pHizKzGnKi5FW+1QYzuGPd
         D6NZWQn53TDbx8pUWJQGGaSfR2fZNaD/CPjw1rPmeqFZKNlIT6pZR47SsOqY2rfcpJ68
         BcDO5DLVf/L22dcs4MsXaCb7m/PmcRYdvPd4R11LrH4jXe8YFV9nDSquv1C6RDmNw2rN
         mLlWYHuDL2k1XiWi8CtCYiP4Bl+jIxB4w1JffcP9Mq29FejUCa9nX7IIUKtZ7X5Au+3V
         YeWg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=merlin.20170209 header.b=tCo6CNCg;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from merlin.infradead.org (merlin.infradead.org. [2001:8b0:10b:1231::1])
        by gmr-mx.google.com with ESMTPS id z14si799009ybj.3.2019.07.08.06.36.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=AEAD-AES256-GCM-SHA384 bits=256/256);
        Mon, 08 Jul 2019 06:36:34 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) client-ip=2001:8b0:10b:1231::1;
Received: from j217100.upc-j.chello.nl ([24.132.217.100] helo=hirez.programming.kicks-ass.net)
	by merlin.infradead.org with esmtpsa (Exim 4.92 #3 (Red Hat Linux))
	id 1hkToe-0007TQ-52; Mon, 08 Jul 2019 13:36:24 +0000
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 1000)
	id 3534A20B28AD7; Mon,  8 Jul 2019 15:36:21 +0200 (CEST)
Date: Mon, 8 Jul 2019 15:36:21 +0200
From: Peter Zijlstra <peterz@infradead.org>
To: Dmitry Vyukov <dvyukov@google.com>
Cc: kernel test robot <rong.a.chen@intel.com>,
	Ingo Molnar <mingo@kernel.org>,
	Josh Poimboeuf <jpoimboe@redhat.com>, LKP <lkp@01.org>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	kasan-dev <kasan-dev@googlegroups.com>
Subject: Re: 7457c0da02 [ 0.733186] BUG: KASAN: unknown-crash in
 unwind_next_frame
Message-ID: <20190708133621.GJ3402@hirez.programming.kicks-ass.net>
References: <20190708004729.GL17490@shao2-debian>
 <20190708105533.GH3402@hirez.programming.kicks-ass.net>
 <CACT4Y+aJYy-aRCAArTEsTKSz1NPE2JONk68P67qPb=7iun3uwQ@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CACT4Y+aJYy-aRCAArTEsTKSz1NPE2JONk68P67qPb=7iun3uwQ@mail.gmail.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=merlin.20170209 header.b=tCo6CNCg;
       spf=pass (google.com: best guess record for domain of
 peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
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

On Mon, Jul 08, 2019 at 01:04:18PM +0200, Dmitry Vyukov wrote:
> On Mon, Jul 8, 2019 at 12:55 PM Peter Zijlstra <peterz@infradead.org> wrote:
> > On Mon, Jul 08, 2019 at 08:47:29AM +0800, kernel test robot wrote:

> > >     x86/alternatives: Add int3_emulate_call() selftest

> > > [    0.726834] CPU: GenuineIntel Intel Core Processor (Haswell) (family: 0x6, model: 0x3c, stepping: 0x1)
> > > [    0.728007] Spectre V2 : Spectre mitigation: kernel not compiled with retpoline; no mitigation available!
> > > [    0.728009] Speculative Store Bypass: Vulnerable
> > > [    0.729969] MDS: Vulnerable: Clear CPU buffers attempted, no microcode
> > > [    0.732269] ==================================================================
> > > [    0.733186] BUG: KASAN: unknown-crash in unwind_next_frame+0x3f6/0x490
> >
> > This is a bit of a puzzle; I'm not sure what KASAN is trying to tell us
> > here, also isn't the unwinder expected to go off into the weeds at times
> > and 'expected' to cope with that? I'm also very much unsure how the
> > fingered commit would lead to this, the below splat is in a lockdep
> > unwind from completely unrealted code (pageattr).
> >
> > Josh, Andrey, any clues?
> 
> +kasan-dev@googlegroups.com
> 
> Frame pointer unwinder is supposed to be precise for the current task,
> it should not touch random memory. This is thoroughly tested. If we
> start giving up on this property, we will open door for lots of bugs.
> Don't know about ORC, I guess it also meant to be precise, but we just
> never stressed it.
> I don't see what unwinder is involved here.

The config that came with had:

  CONFIG_UNWINDER_FRAME_POINTER=y

So that should, according to what you say, be solid.

Now, the fingered commit will unconditionally trigger the idtentry
create_gap logic; and since this splat is *right* after
alternative_instructions(), which does the int3_selftest(), this could
maybe indicate some stack corruption.

	check_bugs()
	  alternative_instructions()
	    int3_selftest();
	    stop_nmi()
	    apply_aternatives()
	    ...
	    restart_nmi()
	  set_memory_4k()
	    ...
	      *SPLAT*

Still, what does KASAN want to tell us here? AFAICT there's 2 separate
conditions under which it states "unknown-crash", and I'm not sure I
understand either one of them. In one case the memory has shadow memory,
the other not.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190708133621.GJ3402%40hirez.programming.kicks-ass.net.
For more options, visit https://groups.google.com/d/optout.
