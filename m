Return-Path: <kasan-dev+bncBDAZZCVNSYPBB44H5KLAMGQEHGKVN7I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x938.google.com (mail-ua1-x938.google.com [IPv6:2607:f8b0:4864:20::938])
	by mail.lfdr.de (Postfix) with ESMTPS id BB2AB57E063
	for <lists+kasan-dev@lfdr.de>; Fri, 22 Jul 2022 13:03:16 +0200 (CEST)
Received: by mail-ua1-x938.google.com with SMTP id k36-20020ab04327000000b00382d2589eb2sf1962489uak.8
        for <lists+kasan-dev@lfdr.de>; Fri, 22 Jul 2022 04:03:16 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1658487795; cv=pass;
        d=google.com; s=arc-20160816;
        b=cKqRo0Gjhmjc216Cz/kjXEt+TlmU5h11cdD0gdRkB/yW5mD+8v2ky6J4uGKFF1h6SH
         HpFIsgPl3K4OGIcZ4rVI5CBJn3WziRwYTkfw9C/ViTp4q22ykmag9tlTfx6XL+3pvYyV
         vthlbcFE7ma1kN5CGIJmhYrPFF/NHEqqUnJuroP/VYcZGJwmJk0TzYP7/huANRhPwRUA
         vgWak8CbApZwmhwn2g+F8d/4ZG+S7c9g0ZSdQM80IqlULR3vsDH5aUH/OSLoJFT6HhQj
         EKyc2paIfXgWXkspX6l/qH7HJWWmnM7vrrSH0Qj5Odzr1FGN0x+USoOtKuKLLS8j0NfM
         a+ZQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=lUGhrn9sprwwyRMpe04qwjG67jrSrcc3Mm6m10UBKqw=;
        b=PtAgky2/1LtoIyhc/zgAChnGIOvqmigajd3Z78xrRnOiFn1djRWvZYYOhrSQ+zHLO2
         dkO6w+mE2avHz+B3FlTWSYbIgYY2sYE3ECpsl5gmvTwQX1Eol7/o0N6KpLogvamdeHbW
         xdqLdmu6WhonjrQgBD2AcnrM8ZHYHru0w8jdBl5GeXKgtDaB3M960hEIP8CXBW3Ueh6A
         jw6vfl/1EnDWMl8TjJbSmnQu8FWrdWfN8RKHTRAlRX+GYqn0bz2Xwy/ny3H9urNYvEvw
         VV6pZly2tJIrMywaM1IN72xTD7CVhXEn7JLHdZhI5hjST+CpfMGl3ZBTJIKkciiiYYta
         /+3A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=FLZZhI4A;
       spf=pass (google.com: domain of will@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=will@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=lUGhrn9sprwwyRMpe04qwjG67jrSrcc3Mm6m10UBKqw=;
        b=GbGmvkrr5zNk9KbmR+N7reUfyS0WPoIdyrbp4z7UpcEP6fzOi51KFLZjSKD1P4r6zY
         jFH6HtphuJ3ZUGlygJjF0WLy5mF10ZBWoK2EzNF8llO4buH3WHQ9x4xI2z/4+WnoXDxN
         TJCBM5lkshVPgAINhzG8a0dbGjTQCC771sHOPHrOEbsWS9p1Kl0KeniZz71GLZtUBesr
         mL7pUO/IlX4WPNJmZJRqvnnBKRNmgzBaUl6WAWLcHfQRREXwwokA4z41q6lZwji6jlz6
         8DVuCXrKdH3B1WGZmUnZ4sCuXaeWpT/i1aI1aEyQqnr5TEXf/RuTB58KbZVirJHm0WMb
         Oc2A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=lUGhrn9sprwwyRMpe04qwjG67jrSrcc3Mm6m10UBKqw=;
        b=v35ttXrlAJZGeRrD9LCB7d8OBS7rPv562sCnoU9aGk95KPdNPooR6Ye+AG+Vc3LSWc
         dLP/Pdf8CXpQlp/qbAQEPp64mjuwlE7nzy++ojaG+gG+cC4Y/lSJJd5sokrMC0hzVowY
         HRFuCnP49v/e5vJ1aNaww7ANiJzp3VFLf3DbzFoqTXil4DcabJ0i4YCB7BhGTJqvAJ4w
         aoQSjcwIibsOSt5CH7hijm4o1sftReOmUFxG5vnSqrJhYzOWl7ses0pxqd3b4JF2GTap
         j31BP7nvOU24a+8OIkASkiil1sMb9WqeNgOV4FUy3YY03mmaH7h0qIMrJfV0OPOTg4/g
         9mBw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AJIora+OTpr4Pf4a0FH2+l5G9nKk1VS06QwGPjWfP//a/IgwhlJplqyz
	Q4YB+OPWMBSXnWCnA/R1NoY=
X-Google-Smtp-Source: AGRyM1unvQXW7yN2P+vJT9Gl0u5s+fZs9dIMNE8PeyAVllkL7hB/kmfH3y7JnYQdp2Qe4XcPH7tgig==
X-Received: by 2002:a05:6130:10b:b0:37f:a52:99fd with SMTP id h11-20020a056130010b00b0037f0a5299fdmr875339uag.96.1658487795438;
        Fri, 22 Jul 2022 04:03:15 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ab0:308e:0:b0:384:421b:56b8 with SMTP id h14-20020ab0308e000000b00384421b56b8ls316557ual.9.-pod-prod-gmail;
 Fri, 22 Jul 2022 04:03:14 -0700 (PDT)
X-Received: by 2002:ab0:4973:0:b0:37f:27c2:59fb with SMTP id a48-20020ab04973000000b0037f27c259fbmr879185uad.80.1658487794825;
        Fri, 22 Jul 2022 04:03:14 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1658487794; cv=none;
        d=google.com; s=arc-20160816;
        b=uN8CNaTYFYenNDEL7XCZ8Ko24eGhf2p+t/qQQ43vCF7VeYjGIJvs5FWCw/HQwDHlEU
         DsUKZLp8ZQ3LGjJBEyi1bnx36gXeyY8jegoFQANcMSKFyTq/q/QlMaDvvT8u6bhcZPKP
         l7VIj/BAR52PWpfgYaEUhq2pH7d4V6VAJAU1eWUemZj8W3KVgBK2H8dfbDO7A/IgBbae
         Mi9b8bFyfAoCum7TcDsgryW+rGTSpMaH27QH+l9LTwCjJkK0aUDY69Nz9p9xSLu+AK+m
         TCgxtanNP0CF18asxRnFVu1ZDx4ylrnd38C0dHiI715DERsDvL0Nirmr8a7KSLYQTwXo
         84Ew==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=osVvsZ7wSzKK1NdKqI7D8rpMNqgA8kgi1cP/l+IILXg=;
        b=LnJVyyWbLP0ZWrzU72HqelZpSUvlLNP1JSRDm1UrBshEtlY2/HhbK5KuKLzzaRHdrU
         d/clNHIdtKhhb5r5vZ+LEJD3/R4RbPHKDYjPQm6ca0tnRQMpbKCedMDRscJTIk1Eip8r
         58HU6XXIXgJpEnDBFTe5nS54/2kWxY6gf2RdKM2HcaLBQj0HjYTNJTttbyMsWbgoa5n3
         0eUbz9P1fap8O8WxknsduEWDnnkEcvQV9R110j7zVPS1wkiUkDGFOIRNz3oj59ZNjIK8
         sRAovy1BlHpheqiE+j/RsqqHystMmj/Pr8vTWG13b6YEagZtVWxErxOSGjRLvWl152Or
         ElcA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=FLZZhI4A;
       spf=pass (google.com: domain of will@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=will@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id c7-20020ab06ec7000000b00383f50be320si500293uav.1.2022.07.22.04.03.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 22 Jul 2022 04:03:14 -0700 (PDT)
Received-SPF: pass (google.com: domain of will@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 660556137B;
	Fri, 22 Jul 2022 11:03:14 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 583BEC341C6;
	Fri, 22 Jul 2022 11:03:10 +0000 (UTC)
Date: Fri, 22 Jul 2022 12:03:06 +0100
From: Will Deacon <will@kernel.org>
To: Dmitry Vyukov <dvyukov@google.com>
Cc: Mark Rutland <mark.rutland@arm.com>, Marco Elver <elver@google.com>,
	Peter Zijlstra <peterz@infradead.org>,
	Frederic Weisbecker <frederic@kernel.org>,
	Ingo Molnar <mingo@kernel.org>,
	Thomas Gleixner <tglx@linutronix.de>,
	Arnaldo Carvalho de Melo <acme@kernel.org>,
	Alexander Shishkin <alexander.shishkin@linux.intel.com>,
	Jiri Olsa <jolsa@redhat.com>, Namhyung Kim <namhyung@kernel.org>,
	Michael Ellerman <mpe@ellerman.id.au>,
	linuxppc-dev@lists.ozlabs.org, linux-perf-users@vger.kernel.org,
	x86@kernel.org, linux-sh@vger.kernel.org,
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org
Subject: Re: [PATCH v3 01/14] perf/hw_breakpoint: Add KUnit test for
 constraints accounting
Message-ID: <20220722110305.GA18336@willie-the-truck>
References: <20220704150514.48816-1-elver@google.com>
 <20220704150514.48816-2-elver@google.com>
 <Ytl9L0Zn1PVuL1cB@FVFF77S0Q05N.cambridge.arm.com>
 <20220722091044.GC18125@willie-the-truck>
 <CACT4Y+ZOXXqxhe4U3ZtQPCj2yrf6Qtjg1q0Kfq8+poAOxGgUew@mail.gmail.com>
 <20220722101053.GA18284@willie-the-truck>
 <CACT4Y+Z0imEHF0jM-f-uYdpfSpfzMpa+bFZfPeQW1ECBDjD9fA@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CACT4Y+Z0imEHF0jM-f-uYdpfSpfzMpa+bFZfPeQW1ECBDjD9fA@mail.gmail.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: will@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=FLZZhI4A;       spf=pass
 (google.com: domain of will@kernel.org designates 2604:1380:4641:c500::1 as
 permitted sender) smtp.mailfrom=will@kernel.org;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=kernel.org
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

On Fri, Jul 22, 2022 at 12:31:45PM +0200, Dmitry Vyukov wrote:
> On Fri, 22 Jul 2022 at 12:11, Will Deacon <will@kernel.org> wrote:
> > > > > On Mon, Jul 04, 2022 at 05:05:01PM +0200, Marco Elver wrote:
> > > > > I'm not immediately sure what would be necessary to support per-task kernel
> > > > > breakpoints, but given a lot of that state is currently per-cpu, I imagine it's
> > > > > invasive.
> > > >
> > > > I would actually like to remove HW_BREAKPOINT completely for arm64 as it
> > > > doesn't really work and causes problems for other interfaces such as ptrace
> > > > and kgdb.
> > >
> > > Will it be a localized removal of code that will be easy to revert in
> > > future? Or will it touch lots of code here and there?
> > > Let's say we come up with a very important use case for HW_BREAKPOINT
> > > and will need to make it work on arm64 as well in future.
> >
> > My (rough) plan is to implement a lower-level abstraction for handling the
> > underlying hardware resources, so we can layer consumers on top of that
> > instead of funneling through hw_breakpoint. So if we figure out how to make
> > bits of hw_breakpoint work on arm64, then it should just go on top.
> >
> > The main pain point for hw_breakpoint is kernel-side {break,watch}points
> > and I think there are open design questions about how they should work
> > on arm64, particularly when considering the interaction with user
> > watchpoints triggering on uaccess routines and the possibility of hitting
> > a kernel watchpoint in irq context.
> 
> I see. Our main interest would be break/watchpoints on user addresses
> firing from both user-space and kernel (uaccess), so at least on irqs.

Interesting. Do other architectures report watchpoint hits on user
addresses from kernel uaccess? It feels like this might be surprising to
some users, and it opens up questions about accesses using different virtual
aliases (e.g. via GUP) or from other entities as well (e.g. firmware,
KVM guests, DMA).

Will

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220722110305.GA18336%40willie-the-truck.
