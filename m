Return-Path: <kasan-dev+bncBC7OBJGL2MHBBLGE3L3AKGQERGDQ3BY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43d.google.com (mail-pf1-x43d.google.com [IPv6:2607:f8b0:4864:20::43d])
	by mail.lfdr.de (Postfix) with ESMTPS id 136891EC24B
	for <lists+kasan-dev@lfdr.de>; Tue,  2 Jun 2020 21:02:06 +0200 (CEST)
Received: by mail-pf1-x43d.google.com with SMTP id y11sf9075416pfn.3
        for <lists+kasan-dev@lfdr.de>; Tue, 02 Jun 2020 12:02:06 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1591124524; cv=pass;
        d=google.com; s=arc-20160816;
        b=w4NMIgBVabRvlAaZgn7K0H/0whZb/9zNcrmR37nCKykemSNWusygIeBMvIIspqpYAg
         e692h69SZNW/30cCLUeJDiGkhfxubQMKEeNDe/iWG7S1s+oow30Ogfj5Qy2gqQ+f14cM
         6tOk6ezFO5gn3WCEP/ypUg+Rds/FIXhznOSz2UnktgbX+9p7oOLQiJ6hkUAFEsVbxASR
         A3cCMrop122BmXUisx7sfbehVQO7UJ+kgXTzuuek2d48Z7IeTSuiSOLu52JdkCNxmdeD
         PSTtntkOa8vhxPIVCAGIE5DS+iatHcTEMDAxFX94vyr2yPfgNNwi4LWcPzLs2oYEuEDP
         M6VA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=/amo/Za9X3OtZMp/y7X4cNarGwgXP9ne+obQ78X0M1c=;
        b=GS+eceMbkg6aHq1LwZUHS5wy4JPyaVV778yVJnP4yFZaAL9O0SPAL43dRHOiajgsPd
         Hte9RtK3Fc8w/QlY1cjUBJzYrUaCDIYULiHXxQP5VVTjqGS3r+hOKEpwQ8IPS6o9x8+a
         Q9ILjwT7QHjmhwEwO4NZQhBgYBcX2OaUZTmCVWHoMckhdPRjVErbLo8nDUXJ/T2AaUpi
         cjoAuXA98OaxMOtYISEGzzWNOvGmVvzWJD34uaIy8uNtSOR/T7d2CUWVulGMvPWqREef
         egEDYx2FLniQBdsOECxPiKKcsQx0YRD0lNV3VoQCV7kEctBTF8ElY2WmxlsPXkt1K2u1
         kcHg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=vrumBDaB;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::241 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=/amo/Za9X3OtZMp/y7X4cNarGwgXP9ne+obQ78X0M1c=;
        b=JDqKz/Z8HnP2I2k9hfcLbACO0LPsEPFg810Jknyuh8b6ATls/LWNKuR7DCZOHHCUhH
         OGUHy8kdP50TR1OvsYJPjj3RsTEcnirb8U8cCwuEcsNgIp0N+tZKi1b4mK7A1Q2nJpNo
         UPqNeFavwSzUAPVGwae2hPDS5ZRjSm0F9PizmSCAGQknYz8ZFqGp/5XebFIcZWC5uXxw
         tFSDhbsz3tT8jnVT/EbYazp6OjPNJc/yjzUCu+XjmmK/nkXzKmH/23bRyXtoL/pZDglL
         CnmamBBZzPSztCeV+3XELCp7XTFuqsIIJ2GRvPlhlnCeZ3v140mzHMJ7alhy/ZiDOrQ2
         JwjA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=/amo/Za9X3OtZMp/y7X4cNarGwgXP9ne+obQ78X0M1c=;
        b=GeY9KcNtdWYOniYKIMVvrlq+2iGsTzlwD01diW0YG+mm4taRUZSQUg/N/Orc4Lu8EY
         1nqSYeUMdBGERWtfpziZ+J0c2nwGiHoB3j4jvsG5bPXgYWIHvMT9b818t+rnEshCid8X
         bCQ6X1Ai1RbtotMprc9O7iDpSTc2BuGdyD/5t5QHoLh3h9pkxz4hXfOeGPDwfHVWuAoe
         qdwyxvFaH3f3l36gTB5Q8blqTAi+/iKGkko9l57vwVBddVmxMlLCBBoQqMqk5CksLcyE
         bibxgeJUD9V0TxWhfl2tFYBUPDtRgoHTSoFZWodCcYwNTPToLpfkwq/4g8GojTtFHEGI
         8FQw==
X-Gm-Message-State: AOAM533Fayr4DQ3MaMj9Uiir9YJN2Rzquz0UfTdPR2sKdE42iXBZ66EB
	9Jsc3Tm0KxSHdgqbShLLf+4=
X-Google-Smtp-Source: ABdhPJwg2APOOp76bFKvY4+oVreMZbgA8zBlxCkxnJwj50ZA1UFmuQ+C7yxTVk9P5gA0eLwWQu1h5g==
X-Received: by 2002:a17:90a:cf17:: with SMTP id h23mr629988pju.139.1591124524667;
        Tue, 02 Jun 2020 12:02:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a65:63d0:: with SMTP id n16ls5450362pgv.6.gmail; Tue, 02 Jun
 2020 12:02:04 -0700 (PDT)
X-Received: by 2002:a63:f143:: with SMTP id o3mr26686709pgk.453.1591124524108;
        Tue, 02 Jun 2020 12:02:04 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1591124524; cv=none;
        d=google.com; s=arc-20160816;
        b=FCIKkWpIrJ5Vv+WlyB4S8tMFBK8cT8Hge8IEeT520GBWynr5WmTywGwsyK92dXU1nd
         O5Thlb5fK83uaxByLYE2quqCnAMZ5Jhh0gBY6DO3+L3YSoVO3aLHNdQ1RZSn1T8znG9H
         Fhdp4ytv3ynx1YA8Jp666vfqIa+xjdLRCSJ0FfnsrwGEUlfkFam+bWZCoVLBJL42GQKn
         bO56VHT9ppDw48CVJRc6rK7qpOqu309qjrMHCH6CkdfVXh6KZ3CHf3huCXw1OU4y+7Be
         GPK5mq8uX7TrtaAukueMv8hSDI3beDyFQVnOKmYi6tUcohHzMm/tnVfyoZh21C0y/qjy
         IdCQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=fQp0wr55zKHTmcfSyP/aceC1T2FCV6dcgdAfq1cn0oY=;
        b=dxwIAcMylzECsdqXgxSP5cGQHB07OvgvgdSCeHsJNxoTQZ6x/WnkhJcIT0GUZYm1gD
         RYPahiFQRB9ZnV3Gpo2O4lBkkmKopTcjlR9arsN/FIZSpByRbxjCjUR7YQLemUUxxki2
         XgsVMxqRK5ExZKVNJ1EWqpDaEF7+43CoETKT0a97khzgVEB4tK8gY7fI2lytGwUSAKk3
         JL7DGzM7waQu3k1JjE16Omq47/P8li0NMoitIz+eWhwulZaj7eYf0NnK/EZuPfLTfN11
         Szr0OXFMN4W8iV/h6LG9tPra4VWwi5UZgN5xJCbvvom81o0TPtClyrFxQwZ4URAv+4KI
         tGXA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=vrumBDaB;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::241 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x241.google.com (mail-oi1-x241.google.com. [2607:f8b0:4864:20::241])
        by gmr-mx.google.com with ESMTPS id b5si353297pjn.0.2020.06.02.12.02.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 02 Jun 2020 12:02:04 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::241 as permitted sender) client-ip=2607:f8b0:4864:20::241;
Received: by mail-oi1-x241.google.com with SMTP id c194so8205121oig.5
        for <kasan-dev@googlegroups.com>; Tue, 02 Jun 2020 12:02:04 -0700 (PDT)
X-Received: by 2002:aca:ebc5:: with SMTP id j188mr4030323oih.70.1591124523224;
 Tue, 02 Jun 2020 12:02:03 -0700 (PDT)
MIME-Version: 1.0
References: <20200602184409.22142-1-elver@google.com> <CAKwvOd=5_pgx2+yQt=V_6h7YKiCnVp_L4nsRhz=EzawU1Kf1zg@mail.gmail.com>
In-Reply-To: <CAKwvOd=5_pgx2+yQt=V_6h7YKiCnVp_L4nsRhz=EzawU1Kf1zg@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 2 Jun 2020 21:01:51 +0200
Message-ID: <CANpmjNP0jh=pwm5quCsXo75cfemyyJ=32vCUpEE5UygJ9g7R9A@mail.gmail.com>
Subject: Re: [PATCH -tip 1/2] Kconfig: Bump required compiler version of KASAN
 and UBSAN
To: Nick Desaulniers <ndesaulniers@google.com>
Cc: Will Deacon <will@kernel.org>, Peter Zijlstra <peterz@infradead.org>, 
	Borislav Petkov <bp@alien8.de>, Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@kernel.org>, 
	clang-built-linux <clang-built-linux@googlegroups.com>, 
	"Paul E. McKenney" <paulmck@kernel.org>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=vrumBDaB;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::241 as
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

On Tue, 2 Jun 2020 at 20:57, Nick Desaulniers <ndesaulniers@google.com> wrote:
>
> On Tue, Jun 2, 2020 at 11:44 AM 'Marco Elver' via Clang Built Linux
> <clang-built-linux@googlegroups.com> wrote:
> >
> > Adds config variable CC_HAS_WORKING_NOSANITIZE, which will be true if we
> > have a compiler that does not fail builds due to no_sanitize functions.
> > This does not yet mean they work as intended, but for automated
> > build-tests, this is the minimum requirement.
> >
> > For example, we require that __always_inline functions used from
> > no_sanitize functions do not generate instrumentation. On GCC <= 7 this
> > fails to build entirely, therefore we make the minimum version GCC 8.
> >
> > For KCSAN this is a non-functional change, however, we should add it in
> > case this variable changes in future.
> >
> > Link: https://lkml.kernel.org/r/20200602175859.GC2604@hirez.programming.kicks-ass.net
> > Suggested-by: Peter Zijlstra <peterz@infradead.org>
> > Signed-off-by: Marco Elver <elver@google.com>
>
> Is this a problem only for x86?  If so, that's quite a jump in minimal
> compiler versions for a feature that I don't think is currently
> problematic for other architectures?  (Based on
> https://lore.kernel.org/lkml/20200529171104.GD706518@hirez.programming.kicks-ass.net/
> )

__always_inline void foo(void) {}
__no_sanitize_address void bar(void) { foo(); }

where __no_sanitize_address is implied by 'noinstr' now, and 'noinstr'
is no longer just x86.

Therefore, it's broken on *all* architectures. The compiler will just
break the build with an error. I don't think we can fix that.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNP0jh%3Dpwm5quCsXo75cfemyyJ%3D32vCUpEE5UygJ9g7R9A%40mail.gmail.com.
