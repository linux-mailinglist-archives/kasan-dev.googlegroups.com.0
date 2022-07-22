Return-Path: <kasan-dev+bncBCMIZB7QWENRBH6S5KLAMGQEJ2OYDXI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x140.google.com (mail-lf1-x140.google.com [IPv6:2a00:1450:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id D6A1957E270
	for <lists+kasan-dev@lfdr.de>; Fri, 22 Jul 2022 15:41:52 +0200 (CEST)
Received: by mail-lf1-x140.google.com with SMTP id u19-20020a05651206d300b0048a335d5cb1sf1836844lff.21
        for <lists+kasan-dev@lfdr.de>; Fri, 22 Jul 2022 06:41:52 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1658497312; cv=pass;
        d=google.com; s=arc-20160816;
        b=QFdZIMT/OnbMqpFKYhDl+SZOnTFnv36DvEb9jcXwyeSnSW4727PYbgbMybExKVHBgT
         hZci3JGvkVbf7DzWk3P1j8RiipRDoPUetiNsECWIRCga0y/6nT3UCUPv4Mk7A6JRz9Y3
         vkM9PuiJm/Wlbl+HBHLkigJ82JqnBS3jOaMt3ZdYTkZxG3j6yZW/ePGOd8miQtT6xglt
         UWLqN0InV2jivPPVBxhitaC+iXK43SlrBBglCV0tAAqLSSWspHza4N/vGqcNRkN978lR
         jAUGkJ2xM6ahdmCmz1lJXhEBVYkhLw6Zan6wC0SzeezhZHzqnzZGYv1YOBxW9C4vuU/D
         jnxQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=dFPsMXPBSBPoFpQ9zsiuVpvWkpNzt+yNPODiK++Vr7g=;
        b=PjpXE8dxPA/BuXHUKAlF0NSEvsVlIpYbKutwjoSuUvYyBSLzejgrUaGWoCuAiRy8ku
         m/GPB39ncFhZitdONrZyDv7k2N9nTHs8L8SISDJpTi5mPXebXDsYtk9z5B+2DN+JH59C
         oItUVDkIiAmnR1xYZAmkN5mlFnGWah5Q7EJKVW2K2ksVQtYTzPXtQ/hRTRt8K9q+bSc4
         lEfP+Qhz44FTqDRNTaVR2iHTeonrJQtea70V+bbzVCmRMQwtlKC7hf258HrK87Q1Agyl
         zSTKpVjxQ8DDiyY/iN/5h0jGU8nbfIboW9d780PVtc8GHrA0w78e6eEV4uUxl4M2Ssy5
         vkfQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Mav9qQe7;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::230 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=dFPsMXPBSBPoFpQ9zsiuVpvWkpNzt+yNPODiK++Vr7g=;
        b=KlI0aHfgdA31xZZel8hxumV/R5G4ZNyp3XD/qMc4uuwq6pzRO9a37HKLw3uEYm9IeR
         vYS6SYKa+O/aXh8tWKp2X+pbW4uJY9OVUGN6bTin11dUXoj7VL/hhURMQlDwQpGiMo+9
         oxUEjh0cS8KUGeR0RN0bKFCUrhgZhodpHGpXdF/p92GATeaWqXyQp7fdjFpGnETNU45U
         idPvDNoR3G8ucisAfhlTfXfkiUAbM/RpchDJcSP5KVSTsGuhFyDFGIXCdt0gfbTJpvXE
         GN24tyOnpGY/YreT8vESvlRVaHe67s6oRtjhH6VjygUvG8ZbMUJVXrtPvcS8k9bfgJNC
         BEHA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=dFPsMXPBSBPoFpQ9zsiuVpvWkpNzt+yNPODiK++Vr7g=;
        b=cDgUMdriARsWJudyn4tWA3NA0DsGt9vkzmnUAa34dsMFdfH98GzsVFg7W5NSWL1r7J
         a2+s11QswBGqVVlmSzbOsAED9UriSwFcoRLdsIHge+3P0USdTljYnIDe21KqPhZ68r9Y
         h9mVOVdLDFpJqTsW3Ym7qSqXdffFZOiUZbSZytnJ4pc0+edOn6OIB/IY0WTeXtt/jbE8
         PXau9rqQ3H2iwUOIRLxLtTQE342JxI+l5Pmuag7Zk6ZZuESBFsyNzqY1UFjjDT40Pmjn
         azDIbnuZOQEhcafkbPw1vFjCDxl+HV5ALSpe2KJHjaz83UsrG5GOtoaceelOQwsrC7DL
         TJZQ==
X-Gm-Message-State: AJIora+tFYeft0YXFODPKC5KXjEa04p6r2N0fR7w6vDQGAXGI6t3dDD0
	PGeeKCrxSRG5cZhUnNLcycY=
X-Google-Smtp-Source: AGRyM1uoLDcQxtKf+fAZgpNYT2QAMxwiD9xer9eHABb1npadAnSJniBsdv4Bp3Duds/PJtjJUSgPnA==
X-Received: by 2002:a05:6512:3b9c:b0:489:fdbf:7cfe with SMTP id g28-20020a0565123b9c00b00489fdbf7cfemr29251lfv.241.1658497312184;
        Fri, 22 Jul 2022 06:41:52 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:8655:0:b0:25d:b5b1:9d35 with SMTP id i21-20020a2e8655000000b0025db5b19d35ls1114817ljj.6.-pod-prod-gmail;
 Fri, 22 Jul 2022 06:41:51 -0700 (PDT)
X-Received: by 2002:a2e:a54e:0:b0:25d:a9a4:f324 with SMTP id e14-20020a2ea54e000000b0025da9a4f324mr35851ljn.408.1658497310996;
        Fri, 22 Jul 2022 06:41:50 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1658497310; cv=none;
        d=google.com; s=arc-20160816;
        b=JLwqJPJT/CXmCMGOwlkCxyCLWjwemhwdqMQnB4NabaYIOWnBeZVWFq4HxdPHbxDZKB
         g2YXQCkQo7zYMjLeGOXZMVg+CwouTGZlwjLk/FxwYyVNepfHyA/5keG2EpbhtIIiDAVq
         RuozPJAcuTak3ywUxfe6nuuqaGi7eB2Al4Hc/4w96BJLqQlHXOs52QuSvl6StOmE6T43
         wMnuLB/XiFw8VujVq6f1OodaZP5m+aEfqu/sWuNKN4b/aCTe8UFN0qiivcR06JQcrU+S
         zrsqXVs0u6252zF3jt2Qdsb66cmpuc9JJ+Em/CiVIdYBr/tMO+tzIRw7qAboO48qfX6e
         XHpA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Dx7D0BqkkDvjmBT9gC4DV9N7HZuC2AWyX/zQVsh2Lhg=;
        b=jis+FV4SDk3SR/hFA3jFzxYnkAdcLN4vawhU02SrYYvuFRu0ckydlD0UzcQ/6Nklal
         /D2spPiuxgIes6MUq4Uzfi2GAcLcNg8hn6So+kMcIlRBjJonQhHbyvoxoN5/fW9n+o70
         Qaqhfa1Y73FbcfvsfPs4KCEXD8UrQAYbqlRaWDr3PuCYlXAEfgWbVOqJhxxExXdSHsva
         +IuwClFLemnRB70HQoY34w7s5aWxIJMDlEUGwaljNpSXuTj5yIVgkfgi7oXGgb/VXG8t
         h9pl8x+F1mThLY+yVAJk4e5jFmh7JvtQX9o6BkXg2xEI+AmBXm+q2BGrUs6VKGnUTx6j
         /faQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Mav9qQe7;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::230 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-lj1-x230.google.com (mail-lj1-x230.google.com. [2a00:1450:4864:20::230])
        by gmr-mx.google.com with ESMTPS id v18-20020a05651203b200b0048a29c923e9si196525lfp.5.2022.07.22.06.41.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 22 Jul 2022 06:41:50 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::230 as permitted sender) client-ip=2a00:1450:4864:20::230;
Received: by mail-lj1-x230.google.com with SMTP id k19so5477521lji.10
        for <kasan-dev@googlegroups.com>; Fri, 22 Jul 2022 06:41:50 -0700 (PDT)
X-Received: by 2002:a2e:bd0e:0:b0:25a:88b3:9af6 with SMTP id
 n14-20020a2ebd0e000000b0025a88b39af6mr24943ljq.363.1658497309800; Fri, 22 Jul
 2022 06:41:49 -0700 (PDT)
MIME-Version: 1.0
References: <20220704150514.48816-1-elver@google.com> <20220704150514.48816-2-elver@google.com>
 <Ytl9L0Zn1PVuL1cB@FVFF77S0Q05N.cambridge.arm.com> <20220722091044.GC18125@willie-the-truck>
 <CACT4Y+ZOXXqxhe4U3ZtQPCj2yrf6Qtjg1q0Kfq8+poAOxGgUew@mail.gmail.com>
 <20220722101053.GA18284@willie-the-truck> <CACT4Y+Z0imEHF0jM-f-uYdpfSpfzMpa+bFZfPeQW1ECBDjD9fA@mail.gmail.com>
 <20220722110305.GA18336@willie-the-truck>
In-Reply-To: <20220722110305.GA18336@willie-the-truck>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 22 Jul 2022 15:41:38 +0200
Message-ID: <CACT4Y+aLiNNt3ESZUKHT9U8duN-TMK561nC7Htx9y3R7afCV4g@mail.gmail.com>
Subject: Re: [PATCH v3 01/14] perf/hw_breakpoint: Add KUnit test for
 constraints accounting
To: Will Deacon <will@kernel.org>
Cc: Mark Rutland <mark.rutland@arm.com>, Marco Elver <elver@google.com>, 
	Peter Zijlstra <peterz@infradead.org>, Frederic Weisbecker <frederic@kernel.org>, 
	Ingo Molnar <mingo@kernel.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Arnaldo Carvalho de Melo <acme@kernel.org>, Alexander Shishkin <alexander.shishkin@linux.intel.com>, 
	Jiri Olsa <jolsa@redhat.com>, Namhyung Kim <namhyung@kernel.org>, 
	Michael Ellerman <mpe@ellerman.id.au>, linuxppc-dev@lists.ozlabs.org, 
	linux-perf-users@vger.kernel.org, x86@kernel.org, linux-sh@vger.kernel.org, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=Mav9qQe7;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::230
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Dmitry Vyukov <dvyukov@google.com>
Reply-To: Dmitry Vyukov <dvyukov@google.com>
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

On Fri, 22 Jul 2022 at 13:03, Will Deacon <will@kernel.org> wrote:
> > > > > > On Mon, Jul 04, 2022 at 05:05:01PM +0200, Marco Elver wrote:
> > > > > > I'm not immediately sure what would be necessary to support per-task kernel
> > > > > > breakpoints, but given a lot of that state is currently per-cpu, I imagine it's
> > > > > > invasive.
> > > > >
> > > > > I would actually like to remove HW_BREAKPOINT completely for arm64 as it
> > > > > doesn't really work and causes problems for other interfaces such as ptrace
> > > > > and kgdb.
> > > >
> > > > Will it be a localized removal of code that will be easy to revert in
> > > > future? Or will it touch lots of code here and there?
> > > > Let's say we come up with a very important use case for HW_BREAKPOINT
> > > > and will need to make it work on arm64 as well in future.
> > >
> > > My (rough) plan is to implement a lower-level abstraction for handling the
> > > underlying hardware resources, so we can layer consumers on top of that
> > > instead of funneling through hw_breakpoint. So if we figure out how to make
> > > bits of hw_breakpoint work on arm64, then it should just go on top.
> > >
> > > The main pain point for hw_breakpoint is kernel-side {break,watch}points
> > > and I think there are open design questions about how they should work
> > > on arm64, particularly when considering the interaction with user
> > > watchpoints triggering on uaccess routines and the possibility of hitting
> > > a kernel watchpoint in irq context.
> >
> > I see. Our main interest would be break/watchpoints on user addresses
> > firing from both user-space and kernel (uaccess), so at least on irqs.
>
> Interesting. Do other architectures report watchpoint hits on user
> addresses from kernel uaccess? It feels like this might be surprising to
> some users, and it opens up questions about accesses using different virtual
> aliases (e.g. via GUP) or from other entities as well (e.g. firmware,
> KVM guests, DMA).

x86 supports this.
There is that attr.exclude_kernel flag that requires special permissions:
https://elixir.bootlin.com/linux/v5.19-rc7/source/kernel/events/core.c#L12061
https://elixir.bootlin.com/linux/v5.19-rc7/source/kernel/events/core.c#L9323
But if I understand correctly, it only filters out delivery, the HW
breakpoint fires even if attr.exclude_kernel is set.

We also wanted to relax this permission check somewhat:
https://lore.kernel.org/all/20220601093502.364142-1-elver@google.com/

Yes, if the kernel maps the page at a different virtual address, then
the breakpoint won't fire I think.
Don't know what are the issues with firmware/KVM.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BaLiNNt3ESZUKHT9U8duN-TMK561nC7Htx9y3R7afCV4g%40mail.gmail.com.
