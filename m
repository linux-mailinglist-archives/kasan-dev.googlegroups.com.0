Return-Path: <kasan-dev+bncBDV37XP3XYDRBSWYQSBAMGQEW6ZMGLQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x437.google.com (mail-pf1-x437.google.com [IPv6:2607:f8b0:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id 2F0FE32D9A7
	for <lists+kasan-dev@lfdr.de>; Thu,  4 Mar 2021 19:51:56 +0100 (CET)
Received: by mail-pf1-x437.google.com with SMTP id s18sf18830641pfe.10
        for <lists+kasan-dev@lfdr.de>; Thu, 04 Mar 2021 10:51:56 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1614883915; cv=pass;
        d=google.com; s=arc-20160816;
        b=N7PnRN8isdMdELh+ng0L3+tN6Ld9TnLCYTp7oEwXLJ4GK10hyn++cRw36EFveMUYmh
         2AmSfQSKPPq8wcMQ07GKzrixAyR0rHueiQEcebrxKd7tTWkPdaE/LB+lhgNXQoLc6VJ1
         B7wvLLdX0AY7JdJOmdE/qwc+BMb893YEqm10Z5upF1g2hiRM90Vi5MIZlRBYLAe5hQWp
         3ML2Hjd/UAIBf6eVX0I4V1lC7B50oQR7WSrmdVraIxHebWChwL1ARiv5P01O4RHXYDKR
         QsXCkTq8VdBWXsFKNfokU51JUwgoKY/mYbGMIsxs7QhNssz9lKRaLNrdtXXQ115H8aUq
         kBaA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=z5bPUZ900CusTsl/U+hal4FERsbq6L6p5rdpTE6SmKc=;
        b=UqArX4UgoD05ugoMVW62Q0r5/DHVmXuV3VXxeFztehY/pJ9hzUL/GBmGq0I1w3Lfac
         XTF1OdiifM5aofiDvkHBhT3XhJ/3u3b75sJdA2o6foHTh9Y78UPjmkEaBTw9esPWOldy
         ZrdP+Il0EZ6n0W37JT3E+7Y5N4SyUGoKVaN/qDidPc0sd9x7i0oT/zmGkl+ILWVhkc+1
         fkQJR+aByAavq6GbdLX3BC+8O54lyMKC+MqeoLocXedwichJgUA916CVNYT3HWKwWMFQ
         rjKMBywLWuoHj78aaG1UV3agQnVKlYSBJlJhHMvEdgap613ZCEvwb12ekPgqDzPq5QZC
         N7HQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=z5bPUZ900CusTsl/U+hal4FERsbq6L6p5rdpTE6SmKc=;
        b=b97bzEO6wVLywTG5Hjw+l9b9FhqZRzhLMHX08aaUvYTR4xqTjiQsXcOogBb2Id2/dh
         L2qhlpkoCtyHQbkIk5bWsahtCMpcp4D1diBY01RwS7I42mybzbAYLdk9q4anL4Nuhub6
         tCQZloh0dSKHSeXjMzaIbh6c2jBYB1tHxMXelaju7NnAySzsi1cz6IcLnZZ1/YohhyG5
         VHTe3Yti1ZGoDTJbMYUuLeNU6+Jwwp1fzM/5RWMZwWKDforaHQQD2ZkDwBbo4abZQMk9
         ed57tVNB232S7AzOHR13O4hiJJMWrbQwzFdyEfGYbD4zS6JyIhR+RQOu3UqnxNBUkQ5j
         3mjw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=z5bPUZ900CusTsl/U+hal4FERsbq6L6p5rdpTE6SmKc=;
        b=KeVJGqY/5XlVC9LsOavuggre1CoVQN2IvfecRnKTkhjqK3PbMX00epqXXuT0vx6kNV
         vnOOGS2TiBazWqnZ1sQzAg4R2qeJ5zdR9Qu9NiEb6ihUvz3kNixbeNTTcWFa4ddwuHBa
         rAzRz2FDGNHpTaw8D9L68dH7PQzJNxU2WCT5UGffPIBZpOAu6hnqd+qIM3bKeTHQz2rm
         cPXi2JMxM2gtmRGwiUpAWm8NNpbHwbODr29573flegJtghBZ5G2mZHZGNTxsA+P9jmEx
         e6E2cC+y9usLByicQrD+oTzc3Nc4XN1kSojYroWrpF70KyVRBuXuXrI3msL8PRa2887Q
         GcFQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530qbNf3O6akvffGEsJ8g2+m+gSXNENnpFJ55CMYTvcPxllVqP/C
	insPo7sjK1oC1Cfck3wyD9E=
X-Google-Smtp-Source: ABdhPJzlD+ddbmMDW8ybz1qE877AimmL18JnnBoXPWzDZe9LQM/2goMEUU06QBFyhN1Ve+qqYVsizQ==
X-Received: by 2002:a63:f209:: with SMTP id v9mr4711327pgh.97.1614883914904;
        Thu, 04 Mar 2021 10:51:54 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:cb0b:: with SMTP id z11ls702737pjt.2.canary-gmail;
 Thu, 04 Mar 2021 10:51:54 -0800 (PST)
X-Received: by 2002:a17:902:e886:b029:de:57b2:da69 with SMTP id w6-20020a170902e886b02900de57b2da69mr5167842plg.65.1614883914065;
        Thu, 04 Mar 2021 10:51:54 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1614883914; cv=none;
        d=google.com; s=arc-20160816;
        b=UI02vdxt9TWH6DugOvAFQ6jt/ve7rX0i7MntPXF8ObfWUpxMmlif2yOAnBoPjYPdab
         RaMe1oLsyDHBBO512Qu218s2C90JuqMx9DV3oV8p6cSmCwemsOSeYqwtg3fsKuOE5iCG
         sUUtzy4JzTkArAXx3ScEYqO+QHj2E4dixDfADwHg4Npmta4Zp0ErUZpDzTLbK0YUakZz
         c6ku/ziCHJb8/rLs6oTqgTGemo2HEY7FZxslkxqcbWhSvnEPckay03dKzpCUtUE8aSya
         TK7iqVTa/YzDyVOIJr5CAusirOPhys12g9Ctgj7sdiMIBLGjwyAxO5ni6ELGZ/tyhBIe
         PAVA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=cUmkhQt/y6pC826CUsKJjFSqa8Jc4NK0rFmfgLN77/M=;
        b=VeF4ILK6F9rH7jLGXqFuWdavCfAZPqbuhQzBaGp+00JB1hmmlgB5HHw4A2tsB7MfJL
         dxpcpyQDS/EQPysAEtw7OCK47e283U5Y1P0oJA4yZZJsFkO2MC7PZMLoyPWSIYfW06bi
         vdrlhIyyiR/He4vdjgaIGtDNAlKmQYIPXBnouwEcMI/xfmKdD94FT5E04FLVcCVODO1I
         AYlszHj8qCjH6Wnj2hfaeZCDww4ezoyGyQ6/1gwRquV0nguu0pOwTJcmj48gx2eNPpCT
         namGsobfmnPXAOALs7/5sA41scPuXpwnvsb024+il9b5MxOi25d0nvSvV9vvuyUxuvJt
         7mDQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id b3si34128plz.4.2021.03.04.10.51.53
        for <kasan-dev@googlegroups.com>;
        Thu, 04 Mar 2021 10:51:53 -0800 (PST)
Received-SPF: pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id EEE5331B;
	Thu,  4 Mar 2021 10:51:52 -0800 (PST)
Received: from C02TD0UTHF1T.local (unknown [10.57.53.210])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id D5FF23F7D7;
	Thu,  4 Mar 2021 10:51:50 -0800 (PST)
Date: Thu, 4 Mar 2021 18:51:48 +0000
From: Mark Rutland <mark.rutland@arm.com>
To: Marco Elver <elver@google.com>
Cc: Christophe Leroy <christophe.leroy@csgroup.eu>,
	Benjamin Herrenschmidt <benh@kernel.crashing.org>,
	Paul Mackerras <paulus@samba.org>,
	Michael Ellerman <mpe@ellerman.id.au>,
	LKML <linux-kernel@vger.kernel.org>, linuxppc-dev@lists.ozlabs.org,
	kasan-dev <kasan-dev@googlegroups.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>,
	Linux ARM <linux-arm-kernel@lists.infradead.org>,
	broonie@kernel.org, linux-toolchains@vger.kernel.org
Subject: Re: [PATCH v1] powerpc: Include running function as first entry in
 save_stack_trace() and friends
Message-ID: <20210304185148.GE60457@C02TD0UTHF1T.local>
References: <e2e8728c4c4553bbac75a64b148e402183699c0c.1614780567.git.christophe.leroy@csgroup.eu>
 <CANpmjNOvgbUCf0QBs1J-mO0yEPuzcTMm7aS1JpPB-17_LabNHw@mail.gmail.com>
 <1802be3e-dc1a-52e0-1754-a40f0ea39658@csgroup.eu>
 <YD+o5QkCZN97mH8/@elver.google.com>
 <20210304145730.GC54534@C02TD0UTHF1T.local>
 <CANpmjNOSpFbbDaH9hNucXrpzG=HpsoQpk5w-24x8sU_G-6cz0Q@mail.gmail.com>
 <20210304165923.GA60457@C02TD0UTHF1T.local>
 <YEEYDSJeLPvqRAHZ@elver.google.com>
 <20210304180154.GD60457@C02TD0UTHF1T.local>
 <CANpmjNOZWuhqXATDjH3F=DMbpg2xOy0XppVJ+Wv2XjFh_crJJg@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNOZWuhqXATDjH3F=DMbpg2xOy0XppVJ+Wv2XjFh_crJJg@mail.gmail.com>
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

On Thu, Mar 04, 2021 at 07:22:53PM +0100, Marco Elver wrote:
> On Thu, 4 Mar 2021 at 19:02, Mark Rutland <mark.rutland@arm.com> wrote:
> > On Thu, Mar 04, 2021 at 06:25:33PM +0100, Marco Elver wrote:
> > > On Thu, Mar 04, 2021 at 04:59PM +0000, Mark Rutland wrote:
> > > > On Thu, Mar 04, 2021 at 04:30:34PM +0100, Marco Elver wrote:
> > > > > On Thu, 4 Mar 2021 at 15:57, Mark Rutland <mark.rutland@arm.com> wrote:
> > > > > > [adding Mark Brown]
> > > > > >
> > > > > > The bigger problem here is that skipping is dodgy to begin with, and
> > > > > > this is still liable to break in some cases. One big concern is that
> > > > > > (especially with LTO) we cannot guarantee the compiler will not inline
> > > > > > or outline functions, causing the skipp value to be too large or too
> > > > > > small. That's liable to happen to callers, and in theory (though
> > > > > > unlikely in practice), portions of arch_stack_walk() or
> > > > > > stack_trace_save() could get outlined too.
> > > > > >
> > > > > > Unless we can get some strong guarantees from compiler folk such that we
> > > > > > can guarantee a specific function acts boundary for unwinding (and
> > > > > > doesn't itself get split, etc), the only reliable way I can think to
> > > > > > solve this requires an assembly trampoline. Whatever we do is liable to
> > > > > > need some invasive rework.
> > > > >
> > > > > Will LTO and friends respect 'noinline'?
> > > >
> > > > I hope so (and suspect we'd have more problems otherwise), but I don't
> > > > know whether they actually so.
> > > >
> > > > I suspect even with 'noinline' the compiler is permitted to outline
> > > > portions of a function if it wanted to (and IIUC it could still make
> > > > specialized copies in the absence of 'noclone').
> > > >
> > > > > One thing I also noticed is that tail calls would also cause the stack
> > > > > trace to appear somewhat incomplete (for some of my tests I've
> > > > > disabled tail call optimizations).
> > > >
> > > > I assume you mean for a chain A->B->C where B tail-calls C, you get a
> > > > trace A->C? ... or is A going missing too?
> > >
> > > Correct, it's just the A->C outcome.
> >
> > I'd assumed that those cases were benign, e.g. for livepatching what
> > matters is what can be returned to, so B disappearing from the trace
> > isn't a problem there.
> >
> > Is the concern debugability, or is there a functional issue you have in
> > mind?
> 
> For me, it's just been debuggability, and reliable test cases.
> 
> > > > > Is there a way to also mark a function non-tail-callable?
> > > >
> > > > I think this can be bodged using __attribute__((optimize("$OPTIONS")))
> > > > on a caller to inhibit TCO (though IIRC GCC doesn't reliably support
> > > > function-local optimization options), but I don't expect there's any way
> > > > to mark a callee as not being tail-callable.
> > >
> > > I don't think this is reliable. It'd be
> > > __attribute__((optimize("-fno-optimize-sibling-calls"))), but doesn't
> > > work if applied to the function we do not want to tail-call-optimize,
> > > but would have to be applied to the function that does the tail-calling.
> >
> > Yup; that's what I meant then I said you could do that on the caller but
> > not the callee.
> >
> > I don't follow why you'd want to put this on the callee, though, so I
> > think I'm missing something. Considering a set of functions in different
> > compilation units:
> >
> >   A->B->C->D->E->F->G->H->I->J->K
> 
> I was having this problem with KCSAN, where the compiler would
> tail-call-optimize __tsan_X instrumentation.

Those are compiler-generated calls, right? When those are generated the
compilation unit (and whatever it has included) might not have provided
a prototype anyway, and the compiler has special knowledge of the
functions, so it feels like the compiler would need to inhibit TCO here
for this to be robust. For their intended usage subjecting them to TCO
doesn't seem to make sense AFAICT.

I suspect that compilers have some way of handling that; otherwise I'd
expect to have heard stories of mcount/fentry calls getting TCO'd and
causing problems. So maybe there's an easy fix there?

> This would mean that KCSAN runtime functions ended up in the trace,
> but the function where the access happened would not. However, I don't
> care about the runtime functions, and instead want to see the function
> where the access happened. In that case, I'd like to just mark
> __tsan_X and any other kcsan instrumentation functions as
> do-not-tail-call-optimize, which would solve the problem.

I understand why we don't want to TCO these calls, but given the calls
are implicitly generated, I strongly suspect it's better to fix the
implicit call generation to not be TCO'd to begin with.

> The solution today is that when you compile a kernel with KCSAN, every
> instrumented TU is compiled with -fno-optimize-sibling-calls. The
> better solution would be to just mark KCSAN runtime functions somehow,
> but permit tail calling other things. Although, I probably still want
> to see the full trace, and would decide that having
> -fno-optimize-sibling-calls is a small price to pay in a
> debug-only-kernel to get complete traces.
> 
> > ... if K were marked in this way, and J was compiled with visibility of
> > this, J would stick around, but J's callers might not, and so the a
> > trace might see:
> >
> >   A->J->K
> >
> > ... do you just care about the final caller, i.e. you just need
> > certainty that J will be in the trace?
> 
> Yes. But maybe it's a special problem that only sanitizers have.

I reckon for basically any instrumentation we don't want calls to be
TCO'd, though I'm not immediately sure of cases beyond sanitizers and
mcount/fentry.

Thanks,
Mark.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210304185148.GE60457%40C02TD0UTHF1T.local.
