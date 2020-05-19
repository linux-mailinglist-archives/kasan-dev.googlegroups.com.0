Return-Path: <kasan-dev+bncBCD3NZ4T2IKRBA5HSH3AKGQEXZWMHLI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x338.google.com (mail-wm1-x338.google.com [IPv6:2a00:1450:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id 9D20E1DA3CD
	for <lists+kasan-dev@lfdr.de>; Tue, 19 May 2020 23:45:39 +0200 (CEST)
Received: by mail-wm1-x338.google.com with SMTP id w189sf290712wmg.1
        for <lists+kasan-dev@lfdr.de>; Tue, 19 May 2020 14:45:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1589924739; cv=pass;
        d=google.com; s=arc-20160816;
        b=o8i9pqtqbmZ5xeZxAyAdC2S9CgOCH7uTTtfgLLVGKafnTXOOvUewXsl2uQG8qeLTzY
         O9guny9MEyA/Y9HdxaER3FvNIGOf6MPrdhcSCfTzxfaPLkVGKVulctJOE2cvODm+jVmC
         BrTketjnhk8UTWzTV4psAFt8baVCZ/jS7H+9rZAMMYS9D4Hj2NMQRdcpegpWx5/Cy9V6
         yGbFZfimK78TzFJZe4Pu02lZl7zteb7XI1aZQwXJE4pTISRtJSpTsKGvMA78S4jgZBN+
         6+PuYNqUREIUDlZ7/47+/kvPLoooF1YoMMWJvMKsBZawiFFd5mqiYWxi4Pgex9yV/7KS
         SNKg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=0hvuW8ArvmpgGkgS2f/V2xm2vXJMjpAhWjrkmER0fJU=;
        b=qvq/pFz6i7P0S0WRKwHZq1LRuWqi6L9a3enNWj4O0CJQZJG6MTx6+ii9b/eE35Xos3
         0oXr9KizbxTzDtEa3KI7RgbZ8QPaPXWHoeuRA3fGFUeVoEXZJStwq+HVo6XnENYq3xbE
         YcwTlxeuGBHJB6A5+b5n049lqmbQLS/JJRsR/3PTQhRUQ9T7SxIXoYaOwM7Q7dOQRUAk
         G6PJvCd24X5vCsxl0tZ90G5yfhes7XcJ3zITiEfihdx7ZeqSLkq7TD1xb7vTpSjTFaNZ
         7IBBLOC10zgmfPi7OUPpy/S/xZnRHBaSlVF7PPiG6K7DZrmkMfgCxfdRWxcsu9xMinUk
         7XDw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@lca.pw header.s=google header.b=kooqm401;
       spf=pass (google.com: domain of cai@lca.pw designates 2a00:1450:4864:20::643 as permitted sender) smtp.mailfrom=cai@lca.pw
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=0hvuW8ArvmpgGkgS2f/V2xm2vXJMjpAhWjrkmER0fJU=;
        b=DDGrGNLOKI0LAdVynyOZcZdrzyoL7RonSPFKBmx1I3N3efm7quYh9sjsNGMnerQ3P4
         Mb3IPpqfgx47kCcYek4YLgxO/NE93xRrZNn4yugFnvldSF7aFy2x5MPIQzgqGE0XHjWM
         OVTRg5U7yF7yVluFmS/e7kWaC32MyS9T1VhKnYFGN0ls9gg6EGQW89aTXLB91CnhPGmE
         tscUvb66WZbku/mMl7N2Pcj9mS65hym6Flc+JTvihtcueckoYd+yXFK0+uqv83dkCosy
         lnaIRotPzhn6KlRQ/UCMmLnCOFyHFTPih1X/yDwng0wpsCbnx5h6pF8QzNLzvu3iPy8x
         qAEg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=0hvuW8ArvmpgGkgS2f/V2xm2vXJMjpAhWjrkmER0fJU=;
        b=h3GTHiJIcDUcLL6sdZgBrkR9/kvUyx2cNtKa68rTdx+d9TEaHKr0ORwlgE6a7ncsla
         UJ7X16dJTefMMt7FCK5JDZ9EoPgvOIJ1q3xUMj2Z1TtjbJ/rt6aV8bVcXsBN8i1JU4lW
         /bOXthDSgduhOw4EdqItkD+r2JNuhoIeBWMdrkjnKBMvO/hQcsj6d+pYxYI88bpp46L5
         PR5ubZCfiGnNPNYrm7d/Mm4XqYMH+1hjUyd3JipyT0OH5QiYiTJ7Ype32Kkaw9gZnO7U
         aTcoeJXgPwQE1252u/T3D38gDJ78di2aLhVkyV+/YQ6NkpQek64DqKshLkXW1vclHqRu
         s/1g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533/FCMbF1cgWXDfSSMEkXSWR5eCOwg4lucqhnzamqQTPQW/s3D3
	4YswcAKAghSKLJpAYYSucTk=
X-Google-Smtp-Source: ABdhPJxbrfckwlmrP8IWeaoXot39+0UgClXUm3qTCSY5mVmcyaTTFF3i0psg1j3KRqTYiXR7Ji3w5A==
X-Received: by 2002:adf:f08a:: with SMTP id n10mr958031wro.217.1589924739363;
        Tue, 19 May 2020 14:45:39 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:fac9:: with SMTP id a9ls1036786wrs.2.gmail; Tue, 19 May
 2020 14:45:38 -0700 (PDT)
X-Received: by 2002:adf:bc41:: with SMTP id a1mr997142wrh.302.1589924738911;
        Tue, 19 May 2020 14:45:38 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1589924738; cv=none;
        d=google.com; s=arc-20160816;
        b=VfRFiGj95KwtY3kghpj2NgYMH9fqArqeKUiV9ijsIolwABFOAhGICikQM7AsUI0ESU
         Tpli29KEDSSv1CgKeD6je+GXXkhWAxbzunYb2y6UaXomGbgCb3cjeWseElwoT8IF9jZI
         yjnwOKfC+KmIG6XeUPVgrHAU3uJ4Al2OmIB8gr0cyXkt6LVXV1GHvY11XKKLQ6b23SRt
         tWUCadCi8MloUSoc/SYxYWPu1FmShu+MX8XCCAdVrGmoPgDaLapu+uJM9Yql75RBGpsR
         guZ3GxC26IJKRJL6ETmZBwLz8hQ1R2yLpzxv1r7RE+BKIG5knoZS7QnoYTeRX7VQVCII
         LsIQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=cSRyYwL1zh4grnM+TNINN+oD+vS6Z1eKKyNnOMI4spM=;
        b=Onma2Wz9vmuwZ8qeH3gQ/rMs07Lo+kBxukjnoWpWav7ISRjREoDZ0k/bPkIRULKyn5
         zYliRic7nWw//0t1TseEZ4+pX0W97BuWXhIbATuLybc8nJlwmRBr+2+sXyD3KaHaZwLE
         3Of8ykfuW7L2csubWhOETHChoYJ6zaLcrkkvflcLsTa6cyUNTldHS0lNYvlnZX8DKKSj
         /qaFAHz/C84WB+mR3LGSxNjgk6EWOBfaxP0Zk1wmumCULbgqgx/k54Ujae9IhrZ/efMI
         LuJwwLvhrAn4ruPxhGWUWEBqStYyOWsDVmvznOVC4hhAO/5BGOWf1s30FLeZ+tHcfTHQ
         Ju1Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@lca.pw header.s=google header.b=kooqm401;
       spf=pass (google.com: domain of cai@lca.pw designates 2a00:1450:4864:20::643 as permitted sender) smtp.mailfrom=cai@lca.pw
Received: from mail-ej1-x643.google.com (mail-ej1-x643.google.com. [2a00:1450:4864:20::643])
        by gmr-mx.google.com with ESMTPS id r3si292140wmg.1.2020.05.19.14.45.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 19 May 2020 14:45:38 -0700 (PDT)
Received-SPF: pass (google.com: domain of cai@lca.pw designates 2a00:1450:4864:20::643 as permitted sender) client-ip=2a00:1450:4864:20::643;
Received: by mail-ej1-x643.google.com with SMTP id yc10so708339ejb.12
        for <kasan-dev@googlegroups.com>; Tue, 19 May 2020 14:45:38 -0700 (PDT)
X-Received: by 2002:a17:907:2711:: with SMTP id w17mr1256244ejk.8.1589924738593;
 Tue, 19 May 2020 14:45:38 -0700 (PDT)
MIME-Version: 1.0
References: <20200512183839.2373-1-elver@google.com> <20200512190910.GM2957@hirez.programming.kicks-ass.net>
 <CAG=TAF5S+n_W4KM9F8QuCisyV+s6_QA_gO70y6ckt=V7SS2BXw@mail.gmail.com> <CANpmjNMxvMpr=KaJEoEeRMuS3PGZEyi-VkeSmNywpQTAzFMSVA@mail.gmail.com>
In-Reply-To: <CANpmjNMxvMpr=KaJEoEeRMuS3PGZEyi-VkeSmNywpQTAzFMSVA@mail.gmail.com>
From: Qian Cai <cai@lca.pw>
Date: Tue, 19 May 2020 17:45:27 -0400
Message-ID: <CAG=TAF7zVCMLj5US0uw-piwBUSmWpmPSPV3Thjbh7_kGsO88hQ@mail.gmail.com>
Subject: Re: [PATCH] READ_ONCE, WRITE_ONCE, kcsan: Perform checks in __*_ONCE variants
To: Marco Elver <elver@google.com>
Cc: Peter Zijlstra <peterz@infradead.org>, 
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Will Deacon <will@kernel.org>, Thomas Gleixner <tglx@linutronix.de>, 
	"Paul E . McKenney" <paulmck@kernel.org>, Ingo Molnar <mingo@kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: cai@lca.pw
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@lca.pw header.s=google header.b=kooqm401;       spf=pass
 (google.com: domain of cai@lca.pw designates 2a00:1450:4864:20::643 as
 permitted sender) smtp.mailfrom=cai@lca.pw
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

On Tue, May 19, 2020 at 5:26 PM Marco Elver <elver@google.com> wrote:
>
> On Tue, 19 May 2020 at 23:10, Qian Cai <cai@lca.pw> wrote:
> >
> > On Tue, May 12, 2020 at 3:09 PM Peter Zijlstra <peterz@infradead.org> wrote:
> > >
> > > On Tue, May 12, 2020 at 08:38:39PM +0200, Marco Elver wrote:
> > > > diff --git a/include/linux/compiler.h b/include/linux/compiler.h
> > > > index 741c93c62ecf..e902ca5de811 100644
> > > > --- a/include/linux/compiler.h
> > > > +++ b/include/linux/compiler.h
> > > > @@ -224,13 +224,16 @@ void ftrace_likely_update(struct ftrace_likely_data *f, int val,
> > > >   * atomicity or dependency ordering guarantees. Note that this may result
> > > >   * in tears!
> > > >   */
> > > > -#define __READ_ONCE(x)       (*(const volatile __unqual_scalar_typeof(x) *)&(x))
> > > > +#define __READ_ONCE(x)                                                       \
> > > > +({                                                                   \
> > > > +     kcsan_check_atomic_read(&(x), sizeof(x));                       \
> > > > +     data_race((*(const volatile __unqual_scalar_typeof(x) *)&(x))); \
> > > > +})
> > >
> > > NAK
> > >
> > > This will actively insert instrumentation into __READ_ONCE() and I need
> > > it to not have any.
> >
> > Any way to move this forward? Due to linux-next commit 6bcc8f459fe7
> > (locking/atomics: Flip fallbacks and instrumentation), it triggers a
> > lots of KCSAN warnings due to atomic ops are no longer marked.
>
> This is no longer the right solution we believe due to the various
> requirements that Peter also mentioned. See the discussion here:
>     https://lkml.kernel.org/r/CANpmjNOGFqhtDa9wWpXs2kztQsSozbwsuMO5BqqW0c0g0zGfSA@mail.gmail.com
>
> The new solution is here:
>     https://lkml.kernel.org/r/20200515150338.190344-1-elver@google.com
> While it's a little inconvenient that we'll require Clang 11
> (currently available by building yourself from LLVM repo), but until
> we get GCC fixed (my patch there still pending :-/), this is probably
> the right solution going forward.   If possible, please do test!

That would be quite unfortunate. The version here is still gcc-8.3.1
and clang-9.0.1 on RHEL 8.2 here. It will probably need many years to
be able to get the fixed compilers having versions that high. Sigh...
Also, I want to avoid compiling compilers on my own.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAG%3DTAF7zVCMLj5US0uw-piwBUSmWpmPSPV3Thjbh7_kGsO88hQ%40mail.gmail.com.
