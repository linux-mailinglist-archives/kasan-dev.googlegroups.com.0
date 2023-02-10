Return-Path: <kasan-dev+bncBDW2JDUY5AORBOO2TGPQMGQEKIT3TVA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x537.google.com (mail-pg1-x537.google.com [IPv6:2607:f8b0:4864:20::537])
	by mail.lfdr.de (Postfix) with ESMTPS id 04920692306
	for <lists+kasan-dev@lfdr.de>; Fri, 10 Feb 2023 17:13:47 +0100 (CET)
Received: by mail-pg1-x537.google.com with SMTP id n33-20020a635c61000000b004fb4f0424f3sf2220501pgm.14
        for <lists+kasan-dev@lfdr.de>; Fri, 10 Feb 2023 08:13:46 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1676045625; cv=pass;
        d=google.com; s=arc-20160816;
        b=ROW9XNS1FcA+ERGWfyJyvjbRXeJ3Vr6S9Z2kMhkYJX1LGt2u9mzKD5a4mhIfEmI8Bw
         KYRS8GZouCT2rNt4ODV7VJFOgXnUZY4Z9KC6HXJNNZ3afdVIH5mVhZMRjzS5n9yZG2Ex
         GeuZJG7403Ha+/uOAyE+WUNQidiFm2KD5vM5f6B2XyHi0CJx/o9LPYBLg+XQDZvdwRPs
         e5dTBvPagGKLJuu4AtqTj47Q8ALhOzxuUPY2acQSPHdeIeciKVsllM+80Gc7qsf6lZve
         F6guV8l2XeHKNBfITuxeAEPAsXWISa01WwmwfJW/sl/83Fd2K4QKRZjHNGosLAzQOVmb
         m9tQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=p0JKgGC4YqgpMj842sypqvde6pvxLIblpdpL/KLsEDY=;
        b=lAhRaTX66saKrUD4rV2Vyg4pTMwdbl4CSL4PXQfJbZzqKVKsa5ghGOFF757nMTCuvO
         rw7aXB65F1xEHM0o385sPT53teOJsAqRjmIRjdG3DBqq7BbXrQVuhW/Zvhsqoc335PIq
         jW7Kvdb4PrIYZbdoE0Mn1phf4MK7V8Jc2Qn4lTL5WasmNeKBij+jTIgqABi3yy+l0Z5p
         Bh3mYu9K6fLuoeX56pBw8fzBSSxcmTHpu3m6hR3DCh4PL9oshsE0KOucKBRtm6jhJeVi
         amL4FCecTCrgj/ZvTE0gr2zTZrGnMs9j8Vd21Nmq/SRDfD4ukaXx/c9WBZt/gZkjZbEw
         jLHQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=ViHsFMln;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::633 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=p0JKgGC4YqgpMj842sypqvde6pvxLIblpdpL/KLsEDY=;
        b=DI+xFLN00JlrXeY1z0cXqriM8/1pDIZRl0kxdnUW34bORuLwXmteD8k+NJI1HaSpZM
         VT0rwl4UXrIxA9+2O4tTHOvIQXD8oIwu+LG9PCiqWH9wjQkU/WKhRPS9we/DzYx+AD7T
         Y6ruCFA7PLMixwmA0KEtfNqU4xLDefizHfoemir+wrSMPr4dRuSt3RhC9Y0vDGntYcMT
         A8mLkJ9ZisYFy/2C0D460N3GvNpEE1efhZHpLRSE1RQBHzkz5YnDshdGg/zwlgO0hnJH
         kpvmn4mg5A7QD8QdaVoYIdKZVldvI7Nbwu0SlDYiO3qHW9TXL2IVi++h4tQNyDkHAyw0
         n37w==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:from:to:cc:subject:date:message-id:reply-to;
        bh=p0JKgGC4YqgpMj842sypqvde6pvxLIblpdpL/KLsEDY=;
        b=oXKUbvXROVxyXLsdUglJFq0IsDdSQxOA3XsvBipACSmSSLvUHIIf31hklx8Qf9FoKK
         AVyPBztHKRjYjiicKvVQ8W52tpeRYw8OEXcduDUpD5Z9xLVPRk6CB4CLDaP5hjguxBOz
         6fDCX3cUgyRSNoDGs+fQP5NxrL6EXBGP0DZNzwaqEl1AzPh41/9vsPW801VJVV/Kaw/Z
         7qyZ8LEONPQZLlS67XvA2xb4nTtyPnjtiaq8iZXrD/NzHp3IszTZQGEek6dbQf1libEm
         +BIuIkuHrAjhTXOWqMsr4hVJuKLDaMrwbv8foUArJfwW9/PNmlqFvm4XmJE0Gg1Qpw+7
         4LhQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=p0JKgGC4YqgpMj842sypqvde6pvxLIblpdpL/KLsEDY=;
        b=pCSLLFn/uRZ8oKJm0FtNOmBrdyeMT6DyU+2QKU81MQd5ZF1vqi6Pjk9Vo+VLFwEc7l
         pQEEEe2oWMYmRIsPk/saUFjbr6MsIMOYVI4stHkxLWO8bOFLIkbeUz4G61MDneRdKnxI
         HzxcJfq+BxjRyN+QHX6AqgF5g8OyuAwz8WkWzpOXovPljDJFL0hmnDW/OFe9C12uINas
         +s1zMbYn+DIcv9HlC2lmlXRVWaWqgEBd62ankWNMrMdLWWp4iPABx5TU+L+V2MDpxfB7
         KIQosVi1np0ZZ120qCNn+aHgazd5xFO2Ir8SGC+SHby0PVY/TFcgLghHSIaUlVNeHIWX
         SZ2g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKWxg35K+o9c4UtR/w3+Q1llgQ/D891F7YMG6RHKQWlh+Xt6g2+3
	h+EtxYNfX3PROIdXTpQOxvQ=
X-Google-Smtp-Source: AK7set+hvzgKfpdwR0Y84D2olUkV/8TyTqiW92KDo9PEoPGkt/OvlAlnvDGcJwbLLn8Jpz30s4Ym5Q==
X-Received: by 2002:a17:903:258e:b0:192:63c3:7b5f with SMTP id jb14-20020a170903258e00b0019263c37b5fmr3868297plb.28.1676045625347;
        Fri, 10 Feb 2023 08:13:45 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:11c6:b0:219:84d6:9802 with SMTP id
 gv6-20020a17090b11c600b0021984d69802ls9534697pjb.3.-pod-canary-gmail; Fri, 10
 Feb 2023 08:13:44 -0800 (PST)
X-Received: by 2002:a17:902:f142:b0:19a:7b73:8da9 with SMTP id d2-20020a170902f14200b0019a7b738da9mr904991plb.32.1676045624623;
        Fri, 10 Feb 2023 08:13:44 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1676045624; cv=none;
        d=google.com; s=arc-20160816;
        b=nV0SVbdPDWDZBHR98Je9CFVWqDmE6nDUfVRrNwt63ryWnVnkgeseDoXoGfZ8+4DCXH
         PSYW+Mu0MoAJkqT/r+AvWDwVwO5xBsa+R7rNDwJc8RxMJ+PhexF7yh1/gn+EfDt+8wG2
         neJgDZlunSqXZ10RaJSd8M8SAm+U75ejELM8BjayqD2ZWbpkTSJpMP3690vM3gsORlMx
         DdWMrWEFxtOEhMgJiD4MvxLT1XhtNpq+slIm3QwlIdbbWH2yFpo7XYWZQ/PcNU/fivW7
         Ykw/xA4qXgFuHCviGha8ggzkKfOyYw7fP6DaKEmKaZAcF1D2ThFSieutJ9gnF4BknB0i
         Bs+g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Z0CshUXcCs6affI6qquSsVCmroKwyEhvHhVKSrEyVPg=;
        b=uJBUrecH0C8i2Fx2naocI3W+skQyUFp6NEDIhM31VqMnuNhi8GDtzHKasHEGEz7bbD
         cKbAeUl/MRcdRT21q0jXvEE/DNw/JuDd5onXIF6gC9NROjNv9zlahnwqbCwucWJ0Y69I
         gtzYa7CE0wAGqDWolivZ7z0vJNd0apYuR48BU15vkAWM2HaGFyjskjCP3wH8/gct9KjP
         PZFYGYtBf4ja1bgHNuJGOaqihsBVSg3dubcksTHZND5kW5sUFy9EBv0uhj+6df6EqwV7
         F/KD87MTwv0m3g6ObiRfFlBGv+OAm7VtpT4Ndg57C3gQ/tl0sNGt8Dg8AKD15iEqN3F6
         xUwg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=ViHsFMln;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::633 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pl1-x633.google.com (mail-pl1-x633.google.com. [2607:f8b0:4864:20::633])
        by gmr-mx.google.com with ESMTPS id t2-20020a17090340c200b0019a6ca00d0esi202523pld.5.2023.02.10.08.13.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 10 Feb 2023 08:13:44 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::633 as permitted sender) client-ip=2607:f8b0:4864:20::633;
Received: by mail-pl1-x633.google.com with SMTP id w5so6935157plg.8
        for <kasan-dev@googlegroups.com>; Fri, 10 Feb 2023 08:13:44 -0800 (PST)
X-Received: by 2002:a17:903:555:b0:196:14ea:d3c6 with SMTP id
 jo21-20020a170903055500b0019614ead3c6mr3612078plb.20.1676045624224; Fri, 10
 Feb 2023 08:13:44 -0800 (PST)
MIME-Version: 1.0
References: <20230208184203.2260394-1-elver@google.com> <CA+fCnZeU=pRcyiBpj3nyri0ow+ZYp=ewU3dtSVm_6mh73y1NTA@mail.gmail.com>
 <CANpmjNP_Ka6RTqHNRD7xx93ebZhY+iz69GHBusT=A8X1KvViVA@mail.gmail.com>
In-Reply-To: <CANpmjNP_Ka6RTqHNRD7xx93ebZhY+iz69GHBusT=A8X1KvViVA@mail.gmail.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Fri, 10 Feb 2023 17:13:33 +0100
Message-ID: <CA+fCnZcNF5kNxNuphwj41P45tQEhQ9wX00ZA4g=KTX4sbUirQg@mail.gmail.com>
Subject: Re: [PATCH -tip] kasan: Emit different calls for instrumentable memintrinsics
To: Marco Elver <elver@google.com>
Cc: Peter Zijlstra <peterz@infradead.org>, Masahiro Yamada <masahiroy@kernel.org>, 
	Nathan Chancellor <nathan@kernel.org>, Nick Desaulniers <ndesaulniers@google.com>, 
	Nicolas Schier <nicolas@fjasle.eu>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, linux-kbuild@vger.kernel.org, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	Ingo Molnar <mingo@kernel.org>, Tony Lindgren <tony@atomide.com>, 
	Ulf Hansson <ulf.hansson@linaro.org>, linux-toolchains@vger.kernel.org, 
	Mark Rutland <mark.rutland@arm.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=ViHsFMln;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::633
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Fri, Feb 10, 2023 at 12:35 AM Marco Elver <elver@google.com> wrote:
>
> On Thu, 9 Feb 2023 at 23:43, Andrey Konovalov <andreyknvl@gmail.com> wrote:
> >
> > On Wed, Feb 8, 2023 at 7:42 PM Marco Elver <elver@google.com> wrote:
> > >
> > > Clang 15 will provide an option to prefix calls to memcpy/memset/memmove
> > > with __asan_ in instrumented functions: https://reviews.llvm.org/D122724
> >
> > Hi Marco,
> >
> > Does this option affect all functions or only the ones that are marked
> > with no_sanitize?
>
> Only functions that are instrumented, i.e. wherever
> fsanitize=kernel-address inserts instrumentation.

Ack.

> > Based on the LLVM patch description, should we also change the normal
> > memcpy/memset/memmove to be noninstrumented?
>
> They are no longer instrumented as of 69d4c0d32186 (for
> CONFIG_GENERIC_ENTRY arches).

Ah, sorry, overlooked that.

> > These __asan_mem* functions are not defined in the kernel AFAICS.
> > Should we add them?
>
> Peter introduced them in 69d4c0d32186, and we effectively have no
> mem*() instrumentation on x86 w/o the compiler-enablement patch here.
>
> > Or maybe we should just use "__" as the prefix, as right now __mem*
> > functions are the ones that are not instrumented?
>
> __asan_mem* is for instrumented code, just like ASan userspace does
> (actually ASan userspace has been doing it like this forever, just the
> kernel was somehow special).
>
> [...]
> > > Fixes: 69d4c0d32186 ("entry, kasan, x86: Disallow overriding mem*() functions")
> > > Signed-off-by: Marco Elver <elver@google.com>
> > > ---
> > >
> > > The Fixes tag is just there to show the dependency, and that people
> > > shouldn't apply this patch without 69d4c0d32186.
>
> ^^^ Depends on this commit, which is only in -tip.

Got it. Missed that patch.

> > > +ifdef CONFIG_GENERIC_ENTRY
>
> It also only affects GENERIC_ENTRY arches.
>
> > > +# Instrument memcpy/memset/memmove calls by using instrumented __asan_mem*()
> > > +# instead. With compilers that don't support this option, compiler-inserted
> > > +# memintrinsics won't be checked by KASAN.
> > > +CFLAGS_KASAN += $(call cc-param,asan-kernel-mem-intrinsic-prefix)
> > > +endif
>
> Probably the same should be done for SW_TAGS, because arm64 will be
> GENERIC_ENTRY at one point or another as well.

Yes, makes sense. I'll file a bug for this once I fully understand the
consequences of these changes.

> KASAN + GCC on x86 will have no mem*() instrumentation after
> 69d4c0d32186, which is sad, so somebody ought to teach it the same
> param as above.

Hm, with that patch we would have no KASAN checking within normal mem*
functions (not the ones embedded by the compiler) on GENERIC_ENTRY
arches even with Clang, right?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZcNF5kNxNuphwj41P45tQEhQ9wX00ZA4g%3DKTX4sbUirQg%40mail.gmail.com.
