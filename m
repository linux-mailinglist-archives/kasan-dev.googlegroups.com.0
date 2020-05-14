Return-Path: <kasan-dev+bncBC7OBJGL2MHBBTES6X2QKGQE33VTBMA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1037.google.com (mail-pj1-x1037.google.com [IPv6:2607:f8b0:4864:20::1037])
	by mail.lfdr.de (Postfix) with ESMTPS id C7B961D3168
	for <lists+kasan-dev@lfdr.de>; Thu, 14 May 2020 15:36:14 +0200 (CEST)
Received: by mail-pj1-x1037.google.com with SMTP id mt16sf4959756pjb.5
        for <lists+kasan-dev@lfdr.de>; Thu, 14 May 2020 06:36:14 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1589463373; cv=pass;
        d=google.com; s=arc-20160816;
        b=XUq/6grEL3GwD2ZRPTqTmj6XsWty0G1h/RM02M5TYvQ3neDPwqWEiSsKbF4ocvmpEB
         COGNKWWbwVNzdr1Gm1P1MUCzW8naPynmF5BKppouDOD45v2J0od0t2LrcUvtAmhzEKKA
         0foaj0wSwO8NX7umqXvidEf6uD5ZXisN2ECi4MbVLPlNfdBVGMwI2UQLLKDyL8XkScf9
         6mpFijTihzThTUNvlj74c2xhlo1zVDerPpy7BLs1hGGSyTrYuumqJYJGXb1Q+o14XNov
         P3HG8eL59uK1rxsKrISKpo4atEkWOT8SSadHZODXOAKXyVm75kFLDGk79qOHXv8/dFRF
         Nn3g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=IsE8TBvqkBVJoS54mN8fGRjwk7daRU//MpHQFmTTBMU=;
        b=wNhSePmd8UXJ8gJtyuN5DVFWASTfhGdXxKf+17aIPq7GzzLf3ZZkFCXGNpilJuZdSz
         eLEbWrGLtNTf/iJO1ACt/E1UJyO6aBhkwZiEoe2pvxSOlyJtgmRBim1QIeAw5WzNCh7y
         iCbVKL3Tie2L25e3ry8+RlGvX93aa1Pz3B8Bn8opIetGRqpN9j6GQSEYo9ZIH5bTL0mE
         Tpw4s03Bsro9RR8Aupl5NBAwxyr9WKGTQ/HLATbdVcahoPcYX1vF1e/ewGVzRXt+CSBX
         FP7t0hk0wqPHrhepam+G2SLy8GaXIfyLbbEoSM54oGnjJp0l+1i9H8e76MbFlOiGg4q6
         Q7kA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=TzIq+IWZ;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::244 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=IsE8TBvqkBVJoS54mN8fGRjwk7daRU//MpHQFmTTBMU=;
        b=oChnGQ9bayISsnVBbGwc2dt2/3fLYq2O72xOaSYsgX0icJx+Wc6DyhgRvQ1osO0CfB
         ItpCxQEEom9f0idSIfzwu22Jf1RaxJhl+6S3lxDdnVAQCIuoyKuxPNtmBGwMVEUYBv9Z
         0+wlBjDvRE1SqMVps2aj49wFxLKUq2phFQJrKLTmqZQi1CK5T+Jvx+L8avQGmiat1CN6
         j90lYe5jDSPZJS4CdleMiKIQdcoGYvVlnr3ZBF6Lmk9bn9CVaUefeFKS563eZ7tgS3yB
         N1IJiE5nVTxW7t3jRLaxNnxaFP5qwWiHHGSvE3Em+xvfyeqoitf7/9E1aTVl3vsYp9W+
         dXrA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=IsE8TBvqkBVJoS54mN8fGRjwk7daRU//MpHQFmTTBMU=;
        b=G0SQ7wlTVezfFMbJtFRGAbWGK1zXo1uzNA6eSAQ+5IxUbIPhqhhIE+SbmLZC73RRGm
         COL3KWRETg/yfqojqM9/BHhZniVUWHVo0eMIPIFbxcdtQLHPr5K/MCNge0a9wNHnrlsM
         Wk/fLCHD96VfuH/wsEKtb7cEDbhxbHJSfEmVE4++D+RVyT8tbz6tslSAFPD3G+qxzFm8
         NPWfB3zPqX9qxfCFNjnvFjzTvlSZh81YuLvUp+dOJ7OYxYdHylKPbcW6JRUjtzMRVWCc
         b2xo5cPaXWqXyWMjut+BfzNPtMBqpyHJmux84Adh7Om0kAqca05HUtq8KMhw0xgz3grx
         jofA==
X-Gm-Message-State: AOAM533KwLGgHYJLyn9Y/IhlohHFznE54fD1Ph+Ee71flSbOdUJ9ZySZ
	UPZfHyWN/b1S6jdi+mpbNH4=
X-Google-Smtp-Source: ABdhPJz7fnAfBSzryCR7k6Wa7ORRZ2wfVTsp3PfWmci/ZFReiMPeiF/1im7VPKE9wDXsSmReAHTNBg==
X-Received: by 2002:a63:1054:: with SMTP id 20mr4101021pgq.79.1589463372437;
        Thu, 14 May 2020 06:36:12 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:fe52:: with SMTP id x18ls830260pgj.6.gmail; Thu, 14 May
 2020 06:36:12 -0700 (PDT)
X-Received: by 2002:aa7:9429:: with SMTP id y9mr4641277pfo.8.1589463371963;
        Thu, 14 May 2020 06:36:11 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1589463371; cv=none;
        d=google.com; s=arc-20160816;
        b=McCwHSnqUYr52GWwW8AMAp/tIPGAvCJAbWulbIMoz2swsTiviObNZmVeDDG6c6sVTN
         PUiiKMCpyok2Xb9ERmZKGTiBO91UrTPWAXnIkA9guZzb+a2uZnLLR7ziELy6GOYqpsbC
         myv4HfLw2T7oqoJpJP/mgNYja9Be9SVW+60AmNpm6+wGAoFG0wDQ0eZVd8diAgCro40N
         uQW35fkddMiNyf8egr/gZOSy29JWBr+jp2Y3s3wW1I15pNFdp4n5ucGObMnrVea2lTug
         hCghUwCbt2fWJP01nAbMfowWIk2Si41XALEWy5u9KoMyVzws0+jQh0kw5FqBSViPwzvP
         pYQQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=6PHyeCO76tbGZ0mePRVZUvflJ0rFtTxZbMOic/9HXzM=;
        b=tELd4vry3Tz1pOF3fWsmI9a+nRcp+WSz0tmqwCIH2BNMOaZuY/N4vxNi5pjZaa1PSd
         v5ic4ZUsNW530z7IqOD3JEVQNsrE+HPmH0vds0KI8yyt9uX9zQVtQAO4CnFescjhTcbc
         4l/k8YjCwz2YuLvCj6kABBQEq7apSdB6XIy34ccr4W9JYUE2vBJHCsKV2Yxk98ZRxViI
         JBBajHG01iXsb7ebM1oBnASxgGPKkpYOeigTMz4nEnVSvJ1L8dHdp8l7ixyxG0sBdYZh
         axSstTM0nLbtS630yHSKYpx5ofWhfTa07M9BNNS3FrpdaqV29nUCE76mrQov9fdvhAnu
         Ie4A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=TzIq+IWZ;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::244 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x244.google.com (mail-oi1-x244.google.com. [2607:f8b0:4864:20::244])
        by gmr-mx.google.com with ESMTPS id b8si727069pjk.2.2020.05.14.06.36.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 14 May 2020 06:36:11 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::244 as permitted sender) client-ip=2607:f8b0:4864:20::244;
Received: by mail-oi1-x244.google.com with SMTP id a2so24337789oia.11
        for <kasan-dev@googlegroups.com>; Thu, 14 May 2020 06:36:11 -0700 (PDT)
X-Received: by 2002:aca:ebc5:: with SMTP id j188mr1520452oih.70.1589463370303;
 Thu, 14 May 2020 06:36:10 -0700 (PDT)
MIME-Version: 1.0
References: <CANpmjNMariz3-keqwUsLHVrpk2r7ThLSKtkhHxTDa3SEGeznhA@mail.gmail.com>
 <20200513123243.GO2957@hirez.programming.kicks-ass.net> <20200513124021.GB20278@willie-the-truck>
 <CANpmjNM5XW+ufJ6Mw2Tn7aShRCZaUPGcH=u=4Sk5kqLKyf3v5A@mail.gmail.com>
 <20200513165008.GA24836@willie-the-truck> <CANpmjNN=n59ue06s0MfmRFvKX=WB2NgLgbP6kG_MYCGy2R6PHg@mail.gmail.com>
 <20200513174747.GB24836@willie-the-truck> <CANpmjNNOpJk0tprXKB_deiNAv_UmmORf1-2uajLhnLWQQ1hvoA@mail.gmail.com>
 <20200513212520.GC28594@willie-the-truck> <CANpmjNOAi2K6knC9OFUGjpMo-rvtLDzKMb==J=vTRkmaWctFaQ@mail.gmail.com>
 <20200514110537.GC4280@willie-the-truck>
In-Reply-To: <20200514110537.GC4280@willie-the-truck>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 14 May 2020 15:35:58 +0200
Message-ID: <CANpmjNMTsY_8241bS7=XAfqvZHFLrVEkv_uM4aDUWE_kh3Rvbw@mail.gmail.com>
Subject: Re: [PATCH v5 00/18] Rework READ_ONCE() to improve codegen
To: Will Deacon <will@kernel.org>, kasan-dev <kasan-dev@googlegroups.com>
Cc: Peter Zijlstra <peterz@infradead.org>, LKML <linux-kernel@vger.kernel.org>, 
	Thomas Gleixner <tglx@linutronix.de>, "Paul E. McKenney" <paulmck@kernel.org>, Ingo Molnar <mingo@kernel.org>, 
	Dmitry Vyukov <dvyukov@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=TzIq+IWZ;       spf=pass
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

On Thu, 14 May 2020 at 13:05, Will Deacon <will@kernel.org> wrote:
>
> Hi Marco,
>
> On Thu, May 14, 2020 at 09:31:49AM +0200, Marco Elver wrote:
> > Ouch. With the __{READ,WRITE}_ONCE requirement, we're going to need
> > Clang 11 though.
> >
> > Because without the data_race() around __*_ONCE,
> > arch_atomic_{read,set} will be broken for KCSAN, but we can't have
> > data_race() because it would still add
> > kcsan_{enable,disable}_current() calls to __no_sanitize functions (if
> > compilation unit is instrumented). We can't make arch_atomic functions
> > __no_sanitize_or_inline, because even in code that we want to
> > sanitize, they should remain __always_inline (so they work properly in
> > __no_sanitize functions). Therefore, Clang 11 with support for
> > distinguishing volatiles will be the compiler that will satisfy all
> > the constraints.
> >
> > If this is what we want, let me prepare a series on top of
> > -tip/locking/kcsan with all the things I think we need.
>
> Stepping back a second, the locking/kcsan branch is at least functional at
> the moment by virtue of KCSAN_SANITIZE := n being used liberally in
> arch/x86/. However, I still think we want to do better than that because (a)
> it would be good to get more x86 coverage and (b) enabling this for arm64,
> where objtool is not yet available, will be fragile if we have to whitelist
> object files. There's also a fair bit of arm64 low-level code spread around
> drivers/, so it feels like we'd end up with a really bad case of whack-a-mole.
>
> Talking off-list, Clang >= 7 is pretty reasonable wrt inlining decisions
> and the behaviour for __always_inline is:
>
>   * An __always_inline function inlined into a __no_sanitize function is
>     not instrumented
>   * An __always_inline function inlined into an instrumented function is
>     instrumented
>   * You can't mark a function as both __always_inline __no_sanitize, because
>     __no_sanitize functions are never inlined
>
> GCC, on the other hand, may still inline __no_sanitize functions and then
> subsequently instrument them.
>
> So if were willing to make KCSAN depend on Clang >= 7, then we could:
>
>   - Remove the data_race() from __{READ,WRITE}_ONCE()
>   - Wrap arch_atomic*() in data_race() when called from the instrumented
>     atomic wrappers
>
> At which point, I *think* everything works as expected. READ_ONCE_NOCHECK()
> won't generate any surprises, and Peter can happily use arch_atomic()
> from non-instrumented code.
>
> Thoughts? I don't see the need to support buggy compilers when enabling
> a new debug feature.

This is also a reply to
https://lkml.kernel.org/r/20200514122038.GH3001@hirez.programming.kicks-ass.net
-- the problem with __READ_ONCE would be solved with what Will
proposed above.

Let me try to spell out the requirements I see so far (this is for
KCSAN only though -- other sanitizers might be similar):

  1. __no_kcsan functions should not call anything, not even
kcsan_{enable,disable}_current(), when using __{READ,WRITE}_ONCE.
[Requires leaving data_race() off of these.]

  2. __always_inline functions inlined into __no_sanitize function is
not instrumented. [Has always been satisfied by GCC and Clang.]

  3. __always_inline functions inlined into instrumented function is
instrumented. [Has always been satisfied by GCC and Clang.]

  4. __no_kcsan functions should never be spuriously inlined into
instrumented functions, causing the accesses of the __no_kcsan
function to be instrumented. [Satisfied by Clang >= 7. All GCC
versions are broken.]

  5. we should not break atomic_{read,set} for KCSAN. [Because of #1,
we'd need to add data_race() around the arch-calls in
atomic_{read,set}; or rely on Clang 11's -tsan-distinguish-volatile
support (GCC 11 might get this as well).]

  6. never emit __tsan_func_{entry,exit}. [Clang supports disabling
this, GCC doesn't.]

  7. kernel is supported by compiler. [Clang >= 9 seems to build -tip
for me, anything below complains about lack of asm goto. GCC trivial.]

So, because of #4 & #6 & #7 we're down to Clang >= 9. Because of #5
we'll have to make a choice between Clang >= 9 or Clang >= 11
(released in ~June). In an ideal world we might even fix GCC in
future.

That's not even considering the problems around UBSan and KASAN. But
maybe one step at a time?

Any preferences?

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMTsY_8241bS7%3DXAfqvZHFLrVEkv_uM4aDUWE_kh3Rvbw%40mail.gmail.com.
